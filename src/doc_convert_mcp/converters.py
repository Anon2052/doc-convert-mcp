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
import urllib.parse

import httpx
from openpyxl import load_workbook
from PIL import Image, UnidentifiedImageError
from pypdf import PdfReader
from pypdf.errors import PdfReadError
from pytesseract import TesseractNotFoundError, image_to_string

MAX_FILE_BYTES = 25 * 1024 * 1024  # 25 MB per input file
MAX_PDF_PAGES = 100
MAX_TABLE_ROWS = 5000
MAX_TABLE_COLS = 50
MAX_URL_BYTES = 5 * 1024 * 1024  # 5 MB cap on fetched pages


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
    for i, page in enumerate(pages, start=1):
        try:
            text = page.extract_text() or ""
        except Exception as exc:  # a single bad page must not kill the document
            text = f"[page {i} could not be extracted: {exc}]"
        text = text.strip()
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


def _validate_url(url: str) -> urllib.parse.ParseResult:
    """Parse a URL and reject anything that smells like SSRF."""
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
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ConversionError(f"URL: host '{host}' resolves to a non-public IP ({ip})")
    return parts


def url_to_clean_text(url: str, timeout: int = 20) -> str:
    """Fetch a web page and return its main text content, stripped of markup."""
    _validate_url(url)
    try:
        resp = httpx.get(
            url,
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": "doc-convert-mcp/0.1.0 (+https://github.com/Anon2052/doc-convert-mcp)"
            },
        )
    except httpx.HTTPError as exc:
        raise ConversionError(f"URL: fetch failed ({exc})") from exc
    # Re-validate after redirects (httpx followed them already; check final host).
    _validate_url(str(resp.url))
    content_type = resp.headers.get("content-type", "")
    if "html" not in content_type and "text" not in content_type:
        raise ConversionError(f"URL: unsupported content type '{content_type}'")
    if resp.status_code >= 400:
        raise ConversionError(f"URL: HTTP {resp.status_code} for {url}")
    body = resp.content[:MAX_URL_BYTES]
    try:
        html_text = body.decode(resp.encoding or "utf-8", errors="replace")
    except (LookupError, UnicodeDecodeError) as exc:
        raise ConversionError(f"URL: undecodable response ({exc})") from exc
    extractor = _TextExtractor()
    extractor.feed(html_text)
    text = extractor.text()
    if not text:
        raise ConversionError("URL: no extractable text found")
    return text
