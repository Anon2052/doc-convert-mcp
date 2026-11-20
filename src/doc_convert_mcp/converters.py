"""Pure document-conversion functions.

No web-framework dependencies here so the logic is testable in isolation and
reusable from both the MCP tools and the REST endpoints.
"""

from __future__ import annotations

import csv
import html.parser
import io
import ipaddress
import socket
import time
import urllib.parse
import zipfile
from typing import NamedTuple

import httpcore
import httpx
from openpyxl import load_workbook
from PIL import Image, UnidentifiedImageError
from pypdf import PdfReader
from pypdf.errors import PdfReadError
from pytesseract import TesseractNotFoundError, image_to_string

MAX_FILE_BYTES = 25 * 1024 * 1024  # 25 MB per input file
MAX_PDF_PAGES = 100
MAX_PDF_TEXT_CHARS = 10 * 1024 * 1024  # 10M chars extracted-text cap (H-6)
MAX_TABLE_ROWS = 5000
MAX_TABLE_COLS = 50
MAX_URL_BYTES = 5 * 1024 * 1024  # 5 MB cap on fetched pages
MAX_REDIRECT_HOPS = 5  # H-1: manual redirect walk, validated per hop
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# H-6: zip-bomb guardrails for xlsx/xlsm (openpyxl inflates with no limit)
MAX_ZIP_UNCOMPRESSED_BYTES = 200 * 1024 * 1024  # 200 MB aggregate uncompressed
MAX_ZIP_COMPRESSION_RATIO = 100  # per-entry uncompressed:compressed
MAX_ZIP_ENTRIES = 10_000
URL_USER_AGENT = "doc-convert-mcp/0.1.0 (+https://github.com/Anon2052/doc-convert-mcp)"


class ConversionError(Exception):
    """Raised when input cannot be converted (corrupt, unsupported, oversized)."""


def _check_size(data: bytes, label: str) -> None:
    if not data:
        raise ConversionError(f"{label}: empty input")
    if len(data) > MAX_FILE_BYTES:
        raise ConversionError(f"{label}: {len(data)} bytes exceeds {MAX_FILE_BYTES} byte limit")


# ---------------------------------------------------------------- PDF -> Markdown


def pdf_to_markdown(data: bytes, max_pages: int = MAX_PDF_PAGES) -> str:
    """Extract text from a PDF and render it as Markdown, one section per page."""
    _check_size(data, "PDF")
    try:
        reader = PdfReader(io.BytesIO(data))
    except (PdfReadError, ValueError) as exc:
        raise ConversionError(f"PDF: unreadable or corrupt ({exc})") from exc
    if reader.is_encrypted:
        raise ConversionError("PDF: encrypted PDFs are not supported")
    pages = reader.pages[: max_pages if max_pages > 0 else MAX_PDF_PAGES]
    sections: list[str] = []
    total_text = 0
    for i, page in enumerate(pages, start=1):
        try:
            text = page.extract_text() or ""
        except Exception as exc:  # a single bad page must not kill the document
            text = f"[page {i} could not be extracted: {exc}]"
        text = text.strip()
        # H-6: a crafted PDF can repeat a giant text stream on every page
        # (pypdf's cap is per-page-count, not per-text-volume).
        total_text += len(text)
        if total_text > MAX_PDF_TEXT_CHARS:
            sections.append(
                f"_[truncated: extracted text exceeded the {MAX_PDF_TEXT_CHARS} char limit]_"
            )
            break
        sections.append(f"## Page {i}\n\n{text if text else '_[no extractable text]_'}")
    if len(reader.pages) > len(pages):
        sections.append(f"_[truncated: showing first {len(pages)} of {len(reader.pages)} pages]_")
    return "\n\n".join(sections)


# ---------------------------------------------------------------- OCR


def ocr_image(data: bytes, lang: str = "eng") -> str:
    """Run OCR on an image and return the recognized text."""
    _check_size(data, "image")
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except (UnidentifiedImageError, OSError) as exc:
        raise ConversionError(f"image: unrecognized image data ({exc})") from exc
    if img.mode not in ("L", "RGB"):
        img = img.convert("RGB")
    try:
        text = image_to_string(img, lang=lang)
    except TesseractNotFoundError as exc:
        raise ConversionError(
            "OCR: tesseract binary not found. Install tesseract-ocr "
            "(e.g. `apt install tesseract-ocr`) to enable OCR."
        ) from exc
    except Exception as exc:
        raise ConversionError(f"OCR failed: {exc}") from exc
    return text.strip()


# ---------------------------------------------------------------- Spreadsheets


def _rows_to_markdown(rows: list[list[str]]) -> str:
    rows = [r[:MAX_TABLE_COLS] for r in rows[:MAX_TABLE_ROWS]]
    if not rows:
        return "_[empty sheet]_"
    width = max(len(r) for r in rows)
    norm = [r + [""] * (width - len(r)) for r in rows]

    def esc(cell: str) -> str:
        return cell.replace("|", "\\|").replace("\n", " ").strip()

    header, *body = norm
    lines = [
        "| " + " | ".join(esc(c) for c in header) + " |",
        "| " + " | ".join("---" for _ in header) + " |",
    ]
    lines.extend("| " + " | ".join(esc(c) for c in r) + " |" for r in body)
    if len(rows) >= MAX_TABLE_ROWS:
        lines.append(f"\n_[truncated at {MAX_TABLE_ROWS} rows]_")
    return "\n".join(lines)


def _guard_zip(data: bytes, label: str) -> None:
    """Pre-scan a zip container (xlsx/xlsm) for decompression bombs (H-6).

    openpyxl inflates zip entries into memory with no limit — a ~42KB file
    of highly-compressible zeros can hold gigabytes. The pre-scan reads only
    the zip central directory (headers, no entry data), so it is cheap.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ConversionError(f"{label}: unreadable workbook ({exc})") from exc
    entries = zf.infolist()
    if len(entries) > MAX_ZIP_ENTRIES:
        raise ConversionError(
            f"{label}: zip has {len(entries)} entries (max {MAX_ZIP_ENTRIES})"
        )
    total_uncompressed = 0
    for info in entries:
        size = info.file_size
        total_uncompressed += size
        if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
            raise ConversionError(
                f"{label}: uncompressed zip contents exceed "
                f"{MAX_ZIP_UNCOMPRESSED_BYTES} byte limit"
            )
        # Per-entry compression ratio catches a single giant entry hiding
        # inside an otherwise-small archive. Skip tiny/directory entries.
        if info.compress_size >= 512 and size > info.compress_size * MAX_ZIP_COMPRESSION_RATIO:
            raise ConversionError(
                f"{label}: zip entry {info.filename!r} has suspicious "
                f"compression ratio ({size}/{info.compress_size})"
            )
    zf.close()


def parse_spreadsheet(data: bytes, filename: str) -> str:
    """Parse a CSV or XLSX file into Markdown tables (one section per sheet)."""
    _check_size(data, "spreadsheet")
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext == "csv":
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = data.decode("latin-1")
        rows = [row for row in csv.reader(io.StringIO(text)) if any(c.strip() for c in row)]
        return f"## {filename}\n\n{_rows_to_markdown(rows)}"
    if ext in ("xlsx", "xlsm"):
        _guard_zip(data, "spreadsheet")  # H-6: zip-bomb pre-scan
        try:
            wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        except Exception as exc:
            raise ConversionError(f"spreadsheet: unreadable workbook ({exc})") from exc
        sections = []
        for ws in wb.worksheets:
            rows = [
                ["" if v is None else str(v) for v in row] for row in ws.iter_rows(values_only=True)
            ]
            rows = [r for r in rows if any(c.strip() for c in r)]
            sections.append(f"## Sheet: {ws.title}\n\n{_rows_to_markdown(rows)}")
        wb.close()
        return "\n\n".join(sections) if sections else "_[workbook has no sheets]_"
    raise ConversionError(
        f"spreadsheet: unsupported extension '.{ext}' (supported: .csv, .xlsx, .xlsm)"
    )


# ---------------------------------------------------------------- URL -> clean text


class _TextExtractor(html.parser.HTMLParser):
    """Minimal HTML -> text: drops script/style, keeps block structure."""

    BLOCK_TAGS = {
        "p",
        "div",
        "br",
        "li",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "tr",
        "section",
        "article",
        "header",
        "footer",
    }

    def __init__(self) -> None:
        super().__init__()
        self._parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style", "noscript"):
            self._skip += 1
        elif tag in self.BLOCK_TAGS and not self._skip:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "noscript"):
            self._skip = max(0, self._skip - 1)
        elif tag in self.BLOCK_TAGS and not self._skip:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self._parts.append(data)

    def text(self) -> str:
        lines = (line.strip() for line in "".join(self._parts).splitlines())
        return "\n".join(line for line in lines if line)


class _FetchResult(NamedTuple):
    final_url: str
    headers: dict
    status_code: int
    body: bytes
    encoding: str | None


def _validate_url(url: str) -> tuple[urllib.parse.ParseResult, str]:
    """Parse a URL, resolve its host ONCE, and reject anything non-public.

    Returns ``(parsed_parts, pinned_ip)``: the single validated IP literal
    the TCP connection must dial. Every resolved A/AAAA record must be a
    public unicast address.

    Hardening (pre-launch security audit, 2026-10-01):
    - H-1: redirects are walked MANUALLY (follow_redirects=False, max 5
      hops). Every hop's Location is validated BEFORE it is followed.
    - H-2: DNS is resolved exactly ONCE per hop, here. The TCP connection
      dials that validated IP literal via a pinned httpcore network backend
      instead of letting httpcore re-resolve the hostname at connect time
      (the DNS-rebinding TOCTOU). The request URL keeps the original
      hostname, so the Host header and TLS SNI are unchanged. trust_env=False
      on the fetch client: an ambient HTTP(S)_PROXY would do its own DNS and
      silently bypass the pin.
    - H-3: bodies stream (httpx.stream + iter_bytes) with a running byte
      cap on the DECODED body (catches gzip bombs), a Content-Length
      pre-check, and a shared per-fetch deadline against slow-drip.
    """
    try:
        parts = urllib.parse.urlparse(url)
    except ValueError as exc:
        raise ConversionError(f"URL: malformed ({exc})") from exc
    if parts.scheme not in ("http", "https"):
        raise ConversionError("URL: only http(s) URLs are allowed")
    host = parts.hostname or ""
    if not host:
        raise ConversionError("URL: missing hostname")
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ConversionError(f"URL: cannot resolve host '{host}' ({exc})") from exc
    pinned: str | None = None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        # `not is_global` covers private, loopback, link-local, multicast,
        # reserved, unspecified — AND carrier-grade NAT (100.64.0.0/10),
        # which the individual is_* flags miss on some Python builds.
        if not ip.is_global:
            raise ConversionError(f"URL: host '{host}' resolves to a non-public IP ({ip})")
        if pinned is None:
            pinned = info[4][0]
    if pinned is None:
        raise ConversionError(f"URL: host '{host}' did not resolve to any address")
    return parts, pinned


class _PinnedIPBackend(httpcore.NetworkBackend):
    """httpcore network backend that dials a pre-validated IP literal (H-2)."""

    def __init__(self, pinned_ip: str) -> None:
        self._pinned_ip = pinned_ip
        self._inner = httpcore.SyncBackend()

    def connect_tcp(  # noqa: ANN001, ANN202
        self, host, port, timeout=None, local_address=None, socket_options=None
    ):
        # `host` is intentionally ignored: the socket must dial the vetted IP.
        return self._inner.connect_tcp(
            self._pinned_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    def connect_unix_socket(self, path, timeout=None, socket_options=None):  # noqa: ANN001, ANN202
        raise httpcore.ConnectError("unix sockets are not supported by the fetch guard")

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


class _PinnedIPTransport(httpx.HTTPTransport):
    """httpx transport pinning every TCP dial to one validated IP (H-2)."""

    def __init__(self, pinned_ip: str) -> None:
        # Build the pool directly (mirroring httpx.HTTPTransport defaults)
        # with the pinned backend. super().__init__() is deliberately NOT
        # called: it would build an unpinned pool we immediately discard.
        # Coupled to pinned httpx==0.28.1 / httpcore==1.0.9 (see
        # requirements.txt); handle_request/close only touch self._pool.
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(verify=True, cert=None, trust_env=False),
            network_backend=_PinnedIPBackend(pinned_ip),
        )


def _read_capped(resp: httpx.Response, max_bytes: int, deadline: float) -> bytes:
    """Stream the (decoded) response body with a running byte cap (H-3)."""
    declared = resp.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > max_bytes:
                raise ConversionError(
                    f"URL: content-length {declared} exceeds {max_bytes} byte limit"
                )
        except ValueError:
            pass  # malformed header; the streaming cap below still applies
    chunks: list[bytes] = []
    total = 0
    # iter_bytes() yields DECODED bytes (gzip/deflate already inflated), so
    # the running total caps decompression bombs, not just wire bytes.
    for chunk in resp.iter_bytes(chunk_size=65536):
        total += len(chunk)
        if total > max_bytes:
            raise ConversionError(f"URL: response body exceeds {max_bytes} byte limit")
        if time.monotonic() > deadline:
            raise ConversionError("URL: fetch timed out")
        chunks.append(chunk)
    return b"".join(chunks)


def _fetch_guarded(url: str, timeout: int = 20) -> _FetchResult:
    """Fetch with per-hop redirect validation (H-1), DNS pinning (H-2),
    and a streaming body cap (H-3).
    """
    deadline = time.monotonic() + timeout
    current = url
    for _hop in range(MAX_REDIRECT_HOPS + 1):
        # Resolve + validate THIS hop before any socket is opened for it.
        _parts, pinned_ip = _validate_url(current)
        hop_timeout = max(1.0, deadline - time.monotonic())
        transport = _PinnedIPTransport(pinned_ip)
        try:
            with httpx.Client(
                transport=transport,
                timeout=hop_timeout,
                headers={"User-Agent": URL_USER_AGENT},
            ) as client:
                with client.stream("GET", current, follow_redirects=False) as resp:
                    if resp.status_code in _REDIRECT_STATUSES:
                        location = resp.headers.get("location")
                        if not location:
                            raise ConversionError("URL: redirect without Location header")
                        # Next hop is validated at the top of the loop.
                        current = urllib.parse.urljoin(current, location)
                        continue
                    if resp.status_code >= 400:
                        return _FetchResult(
                            str(resp.url), dict(resp.headers), resp.status_code, b"", None
                        )
                    body = _read_capped(resp, MAX_URL_BYTES, deadline)
                    return _FetchResult(
                        str(resp.url),
                        dict(resp.headers),
                        resp.status_code,
                        body,
                        resp.encoding,
                    )
        except httpx.HTTPError as exc:
            raise ConversionError(f"URL: fetch failed ({exc})") from exc
    raise ConversionError(f"URL: too many redirects (>{MAX_REDIRECT_HOPS} hops)")


def url_to_clean_text(url: str, timeout: int = 20) -> str:
    """Fetch a web page and return its main text content, stripped of markup."""
    result = _fetch_guarded(url, timeout)
    content_type = result.headers.get("content-type", "")
    if "html" not in content_type and "text" not in content_type:
        raise ConversionError(f"URL: unsupported content type '{content_type}'")
    if result.status_code >= 400:
        raise ConversionError(f"URL: HTTP {result.status_code} for {url}")
    try:
        html_text = result.body.decode(result.encoding or "utf-8", errors="replace")
    except (LookupError, UnicodeDecodeError) as exc:
        raise ConversionError(f"URL: undecodable response ({exc})") from exc
    extractor = _TextExtractor()
    extractor.feed(html_text)
    text = extractor.text()
    if not text:
        raise ConversionError("URL: no extractable text found")
    return text
