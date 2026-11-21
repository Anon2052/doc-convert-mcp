"""SEP-2640 (MCP Skills) support for doc-convert-mcp.

Extension id: ``io.modelcontextprotocol/skills`` (Final, spec'd against base
protocol 2026-07-28). Minimal implementation: one skill describing this
server's tool surface, served as a ``skill://`` resource plus the
``skills/list`` and ``skills/get`` methods. Optional
``resources/directory/read`` is deliberately not implemented.
"""

from __future__ import annotations

import hashlib

import yaml
from fastmcp.exceptions import MCPError
from fastmcp.server.extensions import MethodBinding, ServerExtension
from mcp.types import INVALID_PARAMS, RequestParams

SKILL_NAME = "doc-convert-mcp"
SKILL_URI = f"skill://{SKILL_NAME}/SKILL.md"
SKILL_MIME = "text/markdown"

EXTENSION_ID = "io.modelcontextprotocol/skills"

SKILL_MD = """\
---
name: doc-convert-mcp
description: Convert documents to clean Markdown — PDFs, images via OCR,
  spreadsheets, and web pages. Use when you need document content as text.
---

# doc-convert-mcp

Document conversion tools. All binary inputs are base64-encoded file bytes.

## Tools

- `pdf_to_markdown(pdf_base64, max_pages=100)` — PDF bytes -> Markdown, one
  section per page.
- `ocr_image(image_base64, lang="eng")` — image bytes -> recognized text
  (Tesseract).
- `parse_spreadsheet(file_base64, filename)` — CSV/XLSX bytes -> Markdown
  tables. The filename decides CSV vs XLSX parsing.
- `url_to_clean_text(url)` — public http(s) URL -> main text content.
  Private/loopback hosts are rejected.

## Workflow

1. Pick the tool that matches the input type; pass the raw file bytes
   base64-encoded — do not decode or pre-process them yourself.
2. For multi-page PDFs, `max_pages` caps extraction; process very large
   documents in chunks if needed.
3. For spreadsheets, include the real filename — the extension matters.

## Notes

- OCR quality depends on image resolution; language defaults to English.
- Binary inputs must be valid base64; invalid input returns a clear error,
  not partial output.
"""


def _skill_bytes() -> bytes:
    return SKILL_MD.encode("utf-8")


def skill_frontmatter() -> dict:
    """Verbatim YAML frontmatter parsed from the skill's SKILL.md."""
    if not SKILL_MD.startswith("---"):
        raise ValueError("SKILL.md must begin with YAML frontmatter")
    _, front, _ = SKILL_MD.split("---", 2)
    data = yaml.safe_load(front)
    if not isinstance(data, dict) or "name" not in data or "description" not in data:
        raise ValueError("SKILL.md frontmatter must define name and description")
    return data


def skill_entry() -> dict:
    """SEP-2640 skill entry: uri + verbatim frontmatter + file manifest."""
    raw = _skill_bytes()
    return {
        "uri": SKILL_URI,
        "frontmatter": skill_frontmatter(),
        "resources": [
            {
                "uri": SKILL_URI,
                "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            }
        ],
    }


class SkillsListParams(RequestParams):
    cursor: str | None = None


class SkillsGetParams(RequestParams):
    uri: str


async def _handle_skills_list(ctx, params) -> dict:  # noqa: ANN001, ANN202
    return {"resultType": "complete", "skills": [skill_entry()]}


async def _handle_skills_get(ctx, params) -> dict:  # noqa: ANN001, ANN202
    if params.uri != SKILL_URI:
        raise MCPError(INVALID_PARAMS, f"unknown skill uri: {params.uri}")
    return {"resultType": "complete", "skill": skill_entry()}


class SkillsExtension(ServerExtension):
    """SEP-2640 skills extension (``io.modelcontextprotocol/skills``)."""

    identifier = EXTENSION_ID

    def methods(self) -> tuple[MethodBinding, ...]:
        return (
            MethodBinding(
                method="skills/list",
                params_type=SkillsListParams,
                handler=_handle_skills_list,
            ),
            MethodBinding(
                method="skills/get",
                params_type=SkillsGetParams,
                handler=_handle_skills_get,
            ),
        )
