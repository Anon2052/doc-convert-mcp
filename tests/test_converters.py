"""Unit tests for the pure conversion functions."""

from __future__ import annotations

import io
import shutil
import urllib.parse

import pytest
from openpyxl import Workbook
from PIL import Image, ImageDraw

from doc_convert_mcp import converters
from doc_convert_mcp.converters import (
    MAX_FILE_BYTES,
    ConversionError,
    ocr_image,
    parse_spreadsheet,
    pdf_to_markdown,
    url_to_clean_text,
)


def make_pdf_bytes(text: str) -> bytes:
    """Build a minimal valid single-page PDF containing `text` (computes xref)."""
    content = f"BT /F1 24 Tf 100 700 Td ({text}) Tj ET".encode("latin-1")
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(out.tell())
        out.write(f"{i} 0 obj\n".encode() + body + b"\nendobj\n")
    xref_pos = out.tell()
    out.write(f"xref\n0 {len(objs) + 1}\n".encode())
    out.write(b"0000000000 65535 f \n")
    for off in offsets:
        out.write(f"{off:010d} 00000 n \n".encode())
    out.write(
        f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode()
    )
    return out.getvalue()


def make_encrypted_pdf_bytes() -> bytes:
    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(612, 792)
    writer.encrypt("secret")
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def make_text_png(text: str = "Hello OCR 123") -> bytes:
    img = Image.new("RGB", (400, 100), "white")
    ImageDraw.Draw(img).text((10, 30), text, fill="black")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


TESSERACT = shutil.which("tesseract")
needs_tesseract = pytest.mark.skipif(not TESSERACT, reason="tesseract binary not installed")


# ------------------------------------------------------------- pdf_to_markdown


def test_pdf_to_markdown_basic():
    md = pdf_to_markdown(make_pdf_bytes("Hello PDF World"))
    assert "## Page 1" in md
    assert "Hello PDF World" in md


def test_pdf_to_markdown_corrupt():
    with pytest.raises(ConversionError):
        pdf_to_markdown(b"this is not a pdf at all")


def test_pdf_to_markdown_empty():
    with pytest.raises(ConversionError):
        pdf_to_markdown(b"")


def test_pdf_to_markdown_encrypted():
    with pytest.raises(ConversionError, match="encrypted"):
        pdf_to_markdown(make_encrypted_pdf_bytes())


def test_pdf_to_markdown_oversize():
    with pytest.raises(ConversionError, match="exceeds"):
        pdf_to_markdown(b"%PDF" + b"x" * MAX_FILE_BYTES)


def test_pdf_to_markdown_max_pages():
    md = pdf_to_markdown(make_pdf_bytes("hi"), max_pages=0)
    assert "## Page 1" in md  # max_pages<=0 falls back to default, still works


# ------------------------------------------------------------- ocr_image


@needs_tesseract
def test_ocr_image_basic():
    text = ocr_image(make_text_png("Hello OCR 123"))
    assert "Hello" in text and "123" in text


def test_ocr_image_invalid_bytes():
    with pytest.raises(ConversionError):
        ocr_image(b"definitely not an image")


def test_ocr_image_empty():
    with pytest.raises(ConversionError):
        ocr_image(b"")


def test_ocr_image_oversize():
    with pytest.raises(ConversionError, match="exceeds"):
        ocr_image(b"\x89PNG" + b"x" * MAX_FILE_BYTES)


# ------------------------------------------------------------- parse_spreadsheet


def test_parse_csv():
    md = parse_spreadsheet(b"name,age\nAlice,30\nBob,25\n", "people.csv")
    assert "| name | age |" in md
    assert "| Alice | 30 |" in md
    assert "| Bob | 25 |" in md


def test_parse_xlsx():
    wb = Workbook()
    ws = wb.active
    ws.title = "Sales"
    ws.append(["item", "qty"])
    ws.append(["apples", 10])
    buf = io.BytesIO()
    wb.save(buf)
    md = parse_spreadsheet(buf.getvalue(), "sales.xlsx")
    assert "## Sheet: Sales" in md
    assert "| apples | 10 |" in md


def test_parse_spreadsheet_unsupported_extension():
    with pytest.raises(ConversionError, match="unsupported"):
        parse_spreadsheet(b"data", "file.xls")


def test_parse_spreadsheet_empty():
    with pytest.raises(ConversionError):
        parse_spreadsheet(b"", "empty.csv")


def test_parse_spreadsheet_escapes_pipes():
    md = parse_spreadsheet(b"a,b\nx|y,z\n", "t.csv")
    assert "x\\|y" in md


# ------------------------------------------------------------- url_to_clean_text


class _FakeResp:
    def __init__(self, url="http://example.com/", html="<p>Hi</p>", status=200, ctype="text/html"):
        self.url = url
        self.status_code = status
        self.headers = {"content-type": ctype}
        self.content = html.encode()
        self.encoding = "utf-8"


def _patch_get(monkeypatch, resp):
    # Neutralize DNS/SSRF validation (no network in unit tests) and fake the fetch.
    monkeypatch.setattr(converters, "_validate_url", lambda url: urllib.parse.urlparse(url))
    monkeypatch.setattr(converters.httpx, "get", lambda *a, **k: resp)


def test_url_to_clean_text_basic(monkeypatch):
    html = (
        "<html><head><title>T</title></head><body><script>evil()</script>"
        "<h1>Head</h1><p>Body text</p></body></html>"
    )
    _patch_get(monkeypatch, _FakeResp(html=html))
    text = url_to_clean_text("http://example.com/")
    assert "Head" in text and "Body text" in text
    assert "evil()" not in text


def test_url_to_clean_text_rejects_private_ip():
    with pytest.raises(ConversionError, match="non-public IP"):
        url_to_clean_text("http://127.0.0.1/admin")


def test_url_to_clean_text_rejects_metadata_ip():
    with pytest.raises(ConversionError, match="non-public IP"):
        url_to_clean_text("http://169.254.169.254/latest/meta-data/")


def test_url_to_clean_text_rejects_non_http():
    with pytest.raises(ConversionError, match="only http"):
        url_to_clean_text("ftp://example.com/file")


def test_url_to_clean_text_rejects_bad_content_type(monkeypatch):
    _patch_get(monkeypatch, _FakeResp(ctype="application/octet-stream"))
    with pytest.raises(ConversionError, match="content type"):
        url_to_clean_text("http://example.com/")


def test_url_to_clean_text_http_error(monkeypatch):
    _patch_get(monkeypatch, _FakeResp(status=404))
    with pytest.raises(ConversionError, match="HTTP 404"):
        url_to_clean_text("http://example.com/")
