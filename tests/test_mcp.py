"""End-to-end MCP protocol tests via FastMCP's in-memory client."""

from __future__ import annotations

import asyncio
import base64

import pytest
from fastmcp import Client

from doc_convert_mcp.mcp_server import mcp
from tests.test_converters import make_pdf_bytes  # noqa: F401


def _run(coro):
    return asyncio.run(coro)


def test_all_four_tools_registered():
    async def go():
        async with Client(mcp) as client:
            tools = await client.list_tools()
            return {t.name for t in tools}

    names = _run(go())
    assert names == {"pdf_to_markdown", "ocr_image", "parse_spreadsheet", "url_to_clean_text"}


def test_tool_descriptions_present():
    async def go():
        async with Client(mcp) as client:
            return await client.list_tools()

    for tool in _run(go()):
        assert tool.description, f"tool {tool.name} has no description"


def test_mcp_pdf_to_markdown_roundtrip():
    pdf_b64 = base64.b64encode(make_pdf_bytes("MCP Hello")).decode()

    async def go():
        async with Client(mcp) as client:
            return await client.call_tool("pdf_to_markdown", {"pdf_base64": pdf_b64})

    result = _run(go())
    text = "".join(c.text for c in result.content if hasattr(c, "text"))
    assert "MCP Hello" in text


def test_mcp_parse_spreadsheet_roundtrip():
    csv_b64 = base64.b64encode(b"a,b\n1,2\n").decode()

    async def go():
        async with Client(mcp) as client:
            return await client.call_tool(
                "parse_spreadsheet", {"file_base64": csv_b64, "filename": "t.csv"}
            )

    result = _run(go())
    text = "".join(c.text for c in result.content if hasattr(c, "text"))
    assert "| a | b |" in text


def test_mcp_tool_error_surfaces_cleanly():
    from fastmcp.exceptions import ToolError

    async def go():
        async with Client(mcp) as client:
            return await client.call_tool("pdf_to_markdown", {"pdf_base64": "!!!not-base64!!!"})

    with pytest.raises(ToolError, match="invalid base64"):
        _run(go())
