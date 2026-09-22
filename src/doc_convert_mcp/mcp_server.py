"""FastMCP server: document-conversion tools over streamable HTTP."""

from __future__ import annotations

import base64
import binascii

from fastmcp import FastMCP

from . import converters
from .converters import ConversionError

mcp = FastMCP(
    "doc-convert-mcp",
    instructions=(
        "Document conversion tools. "
        "pdf_to_markdown: PDF bytes (base64) -> Markdown, one section per page. "
        "ocr_image: image bytes (base64) -> recognized text. "
        "parse_spreadsheet: CSV/XLSX bytes (base64) + filename -> Markdown tables. "
        "url_to_clean_text: fetch a public http(s) URL -> main text content."
    ),
)


def _b64decode(data_b64: str, label: str) -> bytes:
    try:
        return base64.b64decode(data_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ConversionError(f"{label}: invalid base64 ({exc})") from exc


@mcp.tool(name="pdf_to_markdown")
def pdf_to_markdown(pdf_base64: str, max_pages: int = 100) -> str:
    """Convert a PDF (base64-encoded bytes) to Markdown, one section per page.

    Args:
        pdf_base64: The PDF file contents, base64-encoded.
        max_pages: Maximum pages to extract (default 100).
    """
    return converters.pdf_to_markdown(_b64decode(pdf_base64, "PDF"), max_pages=max_pages)


@mcp.tool(name="ocr_image")
def ocr_image(image_base64: str, lang: str = "eng") -> str:
    """Run OCR on an image (base64-encoded bytes) and return recognized text.

    Args:
        image_base64: The image file contents, base64-encoded.
        lang: Tesseract language code (default 'eng').
    """
    return converters.ocr_image(_b64decode(image_base64, "image"), lang=lang)


@mcp.tool(name="parse_spreadsheet")
def parse_spreadsheet(file_base64: str, filename: str) -> str:
    """Parse a CSV or XLSX file (base64-encoded bytes) into Markdown tables.

    Args:
        file_base64: The spreadsheet file contents, base64-encoded.
        filename: Original filename (used to detect .csv vs .xlsx).
    """
    return converters.parse_spreadsheet(_b64decode(file_base64, "spreadsheet"), filename)


@mcp.tool(name="url_to_clean_text")
def url_to_clean_text(url: str) -> str:
    """Fetch a public http(s) URL and return its main text content as plain text.

    Args:
        url: The http(s) URL to fetch. Private/loopback hosts are rejected.
    """
    return converters.url_to_clean_text(url)
