"""Bazaar discovery metadata + the new discovery manifest
(manifest-hygiene pass, 2026-10-21).

Covers: the discovery manifest — created in this pass, doc-convert served
none before — at BOTH /.well-known/x402 and /.well-known/x402.json with
identical, truthful content; x402 v1 ``outputSchema`` inside
paymentRequirements; x402 v2 ``extensions.bazaar`` on 402 challenges; and
the additive-only guarantee (legacy challenge fields and free-tier
behavior unchanged).

Format references (verified against primary sources 2026-10-21): the x402
Python SDK (x402/extensions/bazaar — ``declare_discovery_extension`` /
``declare_mcp_discovery_extension`` in resource_service.py, types.py, and
the "V1 Support" extractor contract) and CDP docs "Get discovered
(Bazaar)".
"""

from decimal import Decimal

import jsonschema
import pytest
from fastapi.testclient import TestClient

from doc_convert_mcp import x402 as x402_mod
from doc_convert_mcp.rest_app import create_app

PAY_TO = "0xAbC1230000000000000000000000000000000001"
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"


@pytest.fixture(autouse=True)
def _isolated_billing_db(monkeypatch, tmp_path):
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "billing.db"))


def _enable(monkeypatch, **over):
    env = {
        "X402_ENABLED": "true",
        "X402_PAY_TO": PAY_TO,
        "X402_FACILITATOR_URL": "https://x402.test/facilitator",
        "FREE_TIER_ENABLED": "false",
    }
    env.update(over)
    for k, v in env.items():
        monkeypatch.setenv(k, v)


def _validate_bazaar(extension):
    """The extension's info block must validate against its own schema."""
    jsonschema.validate(extension["info"], extension["schema"])
    assert extension["schema"]["required"] == ["input"]


# ------------------------------------------------------------- manifest


def test_manifest_served_at_both_paths_identically():
    xc = TestClient(create_app())
    bare = xc.get("/.well-known/x402")
    dotted = xc.get("/.well-known/x402.json")
    assert bare.status_code == dotted.status_code == 200
    assert bare.json() == dotted.json()


def test_manifest_content_is_truthful_when_payments_disabled(monkeypatch):
    monkeypatch.delenv("X402_ENABLED", raising=False)
    monkeypatch.delenv("X402_PAY_TO", raising=False)
    manifest = x402_mod.build_discovery_manifest()
    # Honesty contract: never claims live while the gate is off.
    assert manifest["x402_status"] == "implemented_but_disabled"
    assert manifest["service"] == "doc-convert-mcp"
    assert manifest["version"] == 1
    payment = manifest["payment"]
    assert payment["scheme"] == "exact"
    assert payment["network"] == "base"
    assert payment["asset"] == "USDC"
    assert payment["asset_address"] == USDC_BASE
    assert payment["asset_decimals"] == 6
    assert payment["pay_to"] is None  # unset env -> null, never invented
    tools = manifest["tools"]
    assert set(tools) == {
        "pdf_to_markdown",
        "ocr_image",
        "parse_spreadsheet",
        "url_to_clean_text",
    }
    for tool, rest_path in (
        ("pdf_to_markdown", "/convert/pdf"),
        ("ocr_image", "/convert/ocr"),
        ("parse_spreadsheet", "/convert/spreadsheet"),
        ("url_to_clean_text", "/convert/url"),
    ):
        assert tools[tool]["price_usdc"] == "0.008"
        assert tools[tool]["rest_path"] == rest_path
        assert tools[tool]["description"].startswith(f"{tool}: ")
    assert manifest["legal"] == {
        "terms": "/legal/terms",
        "privacy": "/legal/privacy",
        "refunds": "/legal/refunds",
    }


def test_manifest_reflects_live_config(monkeypatch):
    _enable(monkeypatch, X402_PRICE_OCR_IMAGE_USDC="0.05")
    manifest = x402_mod.build_discovery_manifest()
    assert manifest["x402_status"] == "accepting_payments"
    assert manifest["payment"]["pay_to"] == PAY_TO
    # Env price overrides flow through the single source of truth.
    assert manifest["tools"]["ocr_image"]["price_usdc"] == "0.05"
    assert manifest["tools"]["pdf_to_markdown"]["price_usdc"] == "0.008"


# ------------------------------------------------------- v1 outputSchema


def test_requirements_carry_output_schema_for_rest_routes():
    req = x402_mod.build_payment_requirements(
        Decimal("0.008"),
        "https://convert.ioconnex.dev/convert/url",
        "REST /convert/url (tool 'url_to_clean_text')",
    )
    schema = req["outputSchema"]
    assert schema["input"]["type"] == "http"
    assert schema["input"]["method"] == "POST"
    assert schema["input"]["discoverable"] is True
    assert schema["input"]["bodyType"] == "json"
    assert schema["input"]["bodyFields"] == {"url": "https://example.com/article"}
    assert schema["output"]["required"] == ["text"]


def test_requirements_carry_output_schema_for_upload_route():
    req = x402_mod.build_payment_requirements(
        Decimal("0.008"),
        "https://convert.ioconnex.dev/convert/pdf",
        "REST /convert/pdf (tool 'pdf_to_markdown')",
    )
    schema = req["outputSchema"]
    assert schema["input"]["bodyType"] == "form-data"
    assert schema["input"]["bodyFields"] == {"file": "example.pdf"}
    assert schema["output"]["required"] == ["markdown"]


def test_requirements_carry_output_schema_for_mcp_tool_call():
    req = x402_mod.build_payment_requirements(
        Decimal("0.008"),
        "https://convert.ioconnex.dev/mcp",
        "MCP tool 'ocr_image'",
    )
    body = req["outputSchema"]["input"]["bodyFields"]
    assert body["method"] == "tools/call"
    assert body["params"]["name"] == "ocr_image"
    assert body["params"]["arguments"]["lang"] == "eng"
    assert req["outputSchema"]["output"] == {"type": "string"}


def test_no_output_schema_for_uncatalogued_resources():
    req = x402_mod.build_payment_requirements(
        Decimal("0.008"), "https://convert.ioconnex.dev/other", "POST /other"
    )
    assert "outputSchema" not in req


# ------------------------------------------------------ v2 extensions


def test_extensions_bazaar_http_and_mcp_forms_validate():
    http_ext = x402_mod._bazaar_extension(
        "https://convert.ioconnex.dev/convert/pdf", "REST /convert/pdf (tool 'pdf_to_markdown')"
    )
    _validate_bazaar(http_ext)
    assert http_ext["info"]["input"]["type"] == "http"
    assert http_ext["info"]["input"]["method"] == "POST"
    assert http_ext["info"]["input"]["bodyType"] == "form-data"
    assert http_ext["info"]["input"]["body"] == {"file": "example.pdf"}

    mcp_ext = x402_mod._bazaar_extension(
        "https://convert.ioconnex.dev/mcp", "MCP tool 'parse_spreadsheet'"
    )
    _validate_bazaar(mcp_ext)
    assert mcp_ext["info"]["input"]["type"] == "mcp"
    assert mcp_ext["info"]["input"]["toolName"] == "parse_spreadsheet"
    assert mcp_ext["info"]["input"]["transport"] == "streamable-http"
    assert mcp_ext["info"]["input"]["example"]["filename"] == "data.csv"
    assert mcp_ext["info"]["input"]["inputSchema"]["required"] == ["file_base64", "filename"]


def test_challenge_carries_extensions_for_rest_route(monkeypatch):
    _enable(monkeypatch)
    xc = TestClient(create_app())
    resp = xc.post("/convert/url", json={"url": "https://example.com/article"})
    assert resp.status_code == 402
    body = resp.json()
    # Legacy challenge fields unchanged.
    assert body["error"] == "payment_required"
    assert body["accepts"]["pay_to"] == PAY_TO
    assert body["accepts"]["amount_usdc"] == "0.008"
    assert body["paymentRequirements"]["outputSchema"]["input"]["method"] == "POST"
    # New additive block.
    bazaar = body["extensions"]["bazaar"]
    _validate_bazaar(bazaar)
    assert bazaar["info"]["input"]["type"] == "http"
    assert bazaar["info"]["input"]["body"] == {"url": "https://example.com/article"}


def test_challenge_carries_extensions_for_mcp_tool_call(monkeypatch):
    _enable(monkeypatch)
    xc = TestClient(create_app())
    resp = xc.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "pdf_to_markdown",
                "arguments": {"pdf_base64": "JVBERi0xLjQK"},
            },
        },
    )
    assert resp.status_code == 402
    bazaar = resp.json()["extensions"]["bazaar"]
    _validate_bazaar(bazaar)
    assert bazaar["info"]["input"]["type"] == "mcp"
    assert bazaar["info"]["input"]["toolName"] == "pdf_to_markdown"


def test_challenge_without_resource_has_no_extensions():
    requirements = {
        "maxAmountRequired": "8000",
        "asset": USDC_BASE,
        "network": "base",
        "payTo": PAY_TO,
        "scheme": "exact",
    }
    content = x402_mod.challenge_content("payment_required", requirements)
    assert "extensions" not in content


def test_free_tier_behavior_unchanged(monkeypatch):
    _enable(monkeypatch, FREE_TIER_ENABLED="true")
    monkeypatch.setattr(
        "doc_convert_mcp.rest_app._url_to_clean_text", lambda url: "clean text"
    )
    xc = TestClient(create_app())
    resp = xc.post("/convert/url", json={"url": "https://example.com/article"})
    assert resp.status_code == 200
    assert resp.json() == {"text": "clean text"}
