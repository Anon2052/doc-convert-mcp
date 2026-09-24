"""Tests for the public x402 discovery manifest (GET /.well-known/x402.json)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from doc_convert_mcp.rest_app import create_app
from doc_convert_mcp.x402 import (
    DEFAULT_PRICE_USDC,
    NETWORK,
    REST_TOOL_PRICES,
    SCHEME,
    TOOL_PRICES_USDC,
    USDC_BASE_CONTRACT,
    X402_VERSION,
    tool_price_usdc,
    usdc_to_atomic_units,
    x402_price_usdc,
)


@pytest.fixture()
def client():
    return TestClient(create_app())


def _manifest(client):
    r = client.get("/.well-known/x402.json")
    assert r.status_code == 200, r.text
    return r.json()


def test_manifest_200_and_valid_json(client):
    manifest = _manifest(client)
    assert isinstance(manifest, dict)
    assert "x402_status" in manifest
    assert "prices_usdc" in manifest


def test_manifest_prices_match_price_map_exactly(client, monkeypatch):
    # No duplicated prices anywhere in the manifest: every entry must equal
    # the single source of truth (TOOL_PRICES_USDC via tool_price_usdc()).
    for var in ("X402_ENABLED", "X402_PAY_TO", "X402_FACILITATOR_URL"):
        monkeypatch.delenv(var, raising=False)
    manifest = _manifest(client)
    for tool, expected in TOOL_PRICES_USDC.items():
        assert tool in manifest["prices_usdc"], f"tool {tool!r} missing from manifest"
        assert manifest["prices_usdc"][tool] == str(expected), (
            f"manifest price for {tool!r} drifted from TOOL_PRICES_USDC"
        )
        assert manifest["prices_usdc"][tool] == str(tool_price_usdc(tool))
        detail = manifest["tools"][tool]
        assert detail["atomic_units"] == usdc_to_atomic_units(expected)
    assert manifest["default_price_usdc"] == str(DEFAULT_PRICE_USDC)
    assert manifest["default_price_usdc"] == str(x402_price_usdc())
    # Coverage: the manifest covers every priced tool, no extras.
    assert set(manifest["prices_usdc"]) == set(TOOL_PRICES_USDC)


def test_manifest_status_honest_disabled_by_default(client, monkeypatch):
    for var in ("X402_ENABLED", "X402_PAY_TO", "X402_FACILITATOR_URL"):
        monkeypatch.delenv(var, raising=False)
    manifest = _manifest(client)
    # Hard honesty requirement: production has x402 off, so the manifest must
    # say so and never claim live/accepting payments.
    assert manifest["x402_status"] == "implemented_but_disabled"
    assert manifest["enabled"] is False
    assert manifest["x402_status"] not in ("live", "accepting", "enabled")
    body = client.get("/.well-known/x402.json").text
    assert '"accepting_payments": true' not in body


def test_manifest_reports_enabled_truthfully_when_configured(monkeypatch):
    # Honest in the other direction too: when x402 really is effective,
    # the manifest must not claim disabled.
    monkeypatch.setenv("X402_ENABLED", "true")
    monkeypatch.setenv("X402_PAY_TO", "0x000000000000000000000000000000000000dEaD")
    monkeypatch.setenv("X402_FACILITATOR_URL", "https://x402.org/facilitator")
    manifest = _manifest(TestClient(create_app()))
    assert manifest["x402_status"] == "enabled"
    assert manifest["enabled"] is True
    assert manifest["pay_to"] == "0x000000000000000000000000000000000000dEaD"


def test_manifest_accepted_asset_and_network_identifiers(client):
    manifest = _manifest(client)
    # Identifiers come from the x402 module constants — never invented here.
    assert manifest["asset"] == USDC_BASE_CONTRACT
    assert manifest["network"] == NETWORK
    assert manifest["scheme"] == SCHEME
    assert manifest["x402_version"] == X402_VERSION


def test_manifest_pay_to_null_when_unset(client, monkeypatch):
    monkeypatch.delenv("X402_PAY_TO", raising=False)
    assert _manifest(client)["pay_to"] is None


def test_manifest_links_legal_endpoints(client):
    manifest = _manifest(client)
    assert manifest["legal"] == {
        "terms": "/legal/terms",
        "privacy": "/legal/privacy",
        "refunds": "/legal/refunds",
    }
    # And the REST route map is the code's own mapping, not a copy.
    assert manifest["rest_routes"] == dict(REST_TOOL_PRICES)


def test_manifest_free_when_x402_enabled(monkeypatch):
    # Manifest is exempt from the x402 middleware: 200 with no X-Payment
    # header, no subscriber key, no free-tier credit consumption — while a
    # paid path still 402s, proving the gate is actually active.
    monkeypatch.setenv("X402_ENABLED", "true")
    monkeypatch.setenv("X402_PAY_TO", "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
    monkeypatch.setenv("X402_FACILITATOR_URL", "https://x402.org/facilitator")
    # Free tier off so the paid path really hits the 402 challenge.
    monkeypatch.setenv("FREE_TIER_ENABLED", "false")
    client = TestClient(create_app())
    assert client.get("/.well-known/x402.json").status_code == 200
    assert client.post("/convert/url", json={"url": "https://example.com"}).status_code == 402


def test_manifest_exempt_from_rate_limit():
    limited = TestClient(create_app(rate_limit="5/minute"))
    codes = {limited.get("/.well-known/x402.json").status_code for _ in range(10)}
    assert codes == {200}, f"expected all 200, got {codes}"


def test_manifest_not_in_openapi_schema(client):
    paths = client.get("/openapi.json").json()["paths"]
    assert "/.well-known/x402.json" not in paths
