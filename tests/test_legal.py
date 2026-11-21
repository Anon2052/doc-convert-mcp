"""Tests for the public legal-document endpoints (Stripe onboarding URLs)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from doc_convert_mcp.rest_app import create_app


@pytest.fixture()
def client():
    return TestClient(create_app())


ROUTES = {
    "/legal/terms": "# Terms of Service",
    "/legal/privacy": "# Privacy Policy",
    "/legal/refunds": "# Refund Policy",
}


@pytest.mark.parametrize("route,heading", list(ROUTES.items()))
def test_legal_route_serves_markdown(client, route, heading):
    r = client.get(route)
    assert r.status_code == 200, r.text
    assert "text/markdown" in r.headers["content-type"]
    # Verbatim, filled-in document: the heading and the company name both present.
    assert heading in r.text
    assert "IOConnex LLC" in r.text
    assert "[LLC NAME]" not in r.text


@pytest.mark.parametrize("route", list(ROUTES))
def test_legal_routes_never_402_when_x402_enabled(monkeypatch, route):
    monkeypatch.setenv("X402_ENABLED", "true")
    monkeypatch.setenv("X402_PAY_TO", "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
    monkeypatch.setenv("X402_FACILITATOR_URL", "https://x402.org/facilitator")
    # Free tier off for the control probe below: with it on, an unpaid
    # paid-path call is served from the free bucket instead of 402ing.
    monkeypatch.setenv("FREE_TIER_ENABLED", "false")
    client = TestClient(create_app())
    # Legal docs stay free; a paid path with no X-Payment header still 402s,
    # proving the x402 gate is actually active for this client.
    assert client.get(route).status_code == 200
    assert client.post("/convert/url", json={"url": "https://example.com"}).status_code == 402


def test_legal_routes_exempt_from_rate_limit():
    limited = TestClient(create_app(rate_limit="5/minute"))
    codes = set()
    for _ in range(10):
        r = limited.get("/legal/terms")
        codes.add(r.status_code)
    assert codes == {200}, f"expected all 200, got {codes}"


def test_legal_routes_not_in_openapi_schema(client):
    paths = client.get("/openapi.json").json()["paths"]
    for route in ROUTES:
        assert route not in paths
