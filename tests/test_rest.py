"""Tests for the REST API: /health, convert endpoints, rate limiting, x402 hook."""

from __future__ import annotations

import io
import json

import pytest
from fastapi.testclient import TestClient
from openpyxl import Workbook

from doc_convert_mcp.rest_app import create_app
from tests.test_converters import make_pdf_bytes  # noqa: F401  (shared fixture builder)


@pytest.fixture()
def client():
    return TestClient(create_app())


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "version" in body


def test_convert_pdf(client):
    r = client.post(
        "/convert/pdf", files={"file": ("t.pdf", make_pdf_bytes("Hi PDF"), "application/pdf")}
    )
    assert r.status_code == 200, r.text
    assert "Hi PDF" in r.json()["markdown"]


def test_convert_pdf_corrupt_returns_422(client):
    r = client.post("/convert/pdf", files={"file": ("t.pdf", b"garbage", "application/pdf")})
    assert r.status_code == 422
    assert r.json()["error"] == "conversion_failed"


def test_convert_spreadsheet_csv(client):
    r = client.post("/convert/spreadsheet", files={"file": ("a.csv", b"x,y\n1,2\n", "text/csv")})
    assert r.status_code == 200, r.text
    assert "| x | y |" in r.json()["markdown"]


def test_convert_spreadsheet_xlsx(client):
    wb = Workbook()
    wb.active.append(["a", "b"])
    buf = io.BytesIO()
    wb.save(buf)
    r = client.post(
        "/convert/spreadsheet",
        files={
            "file": (
                "a.xlsx",
                buf.getvalue(),
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        },
    )
    assert r.status_code == 200, r.text
    assert "| a | b |" in r.json()["markdown"]


def test_rate_limiting():
    limited = TestClient(create_app(rate_limit="2/minute"))
    for _ in range(2):
        r = limited.get("/health")  # /health is not rate-limited
        assert r.status_code == 200
    codes = set()
    for _ in range(4):
        r = limited.post("/convert/pdf", files={"file": ("t.pdf", b"garbage", "application/pdf")})
        codes.add(r.status_code)
    assert 429 in codes, f"expected a 429, got {codes}"
    # /health stays exempt even under pressure
    assert limited.get("/health").status_code == 200


# ------------------------------------------------------------- x402 hook


def _enable_x402(monkeypatch):
    monkeypatch.setenv("X402_ENABLED", "true")
    monkeypatch.setenv("X402_PRICE_USDC", "0.01")
    monkeypatch.setenv("X402_PAY_TO", "0xAbC123")


def _payment_header(**over):
    payload = {
        "asset": "USDC",
        "network": "base",
        "amount": "0.01",
        "pay_to": "0xAbC123",
        "payer": "0xDeF456",
        "signature": "0xSig789",
    }
    payload.update(over)
    return {"X-Payment": json.dumps(payload)}


def test_x402_disabled_by_default_passes_through(client):
    r = client.post(
        "/convert/pdf", files={"file": ("t.pdf", make_pdf_bytes("Hi"), "application/pdf")}
    )
    assert r.status_code == 200


def test_x402_enabled_blocks_without_payment(monkeypatch):
    _enable_x402(monkeypatch)
    xc = TestClient(create_app())
    r = xc.post("/convert/pdf", files={"file": ("t.pdf", make_pdf_bytes("Hi"), "application/pdf")})
    assert r.status_code == 402
    body = r.json()
    assert body["error"] == "payment_required"
    assert body["accepts"]["asset"] == "USDC"
    assert body["accepts"]["network"] == "base"


def test_x402_enabled_health_stays_free(monkeypatch):
    _enable_x402(monkeypatch)
    xc = TestClient(create_app())
    assert xc.get("/health").status_code == 200


def test_x402_enabled_rejects_malformed_payment(monkeypatch):
    _enable_x402(monkeypatch)
    xc = TestClient(create_app())
    r = xc.post(
        "/convert/pdf",
        files={"file": ("t.pdf", b"x", "application/pdf")},
        headers={"X-Payment": "not-json"},
    )
    assert r.status_code == 402
    r = xc.post(
        "/convert/pdf",
        files={"file": ("t.pdf", b"x", "application/pdf")},
        headers=_payment_header(amount="0.000001"),
    )  # underpriced
    assert r.status_code == 402


def test_x402_enabled_accepts_structurally_valid_payment(monkeypatch):
    _enable_x402(monkeypatch)
    xc = TestClient(create_app())
    r = xc.post(
        "/convert/pdf",
        files={"file": ("t.pdf", make_pdf_bytes("Paid"), "application/pdf")},
        headers=_payment_header(),
    )
    assert r.status_code == 200, r.text
    assert "Paid" in r.json()["markdown"]


# ------------------------------------------------------------- MCP mount paths


def _mcp_ping_body():
    return {"jsonrpc": "2.0", "id": 1, "method": "ping"}


def _mcp_result(response):
    # Streamable HTTP answers as SSE: extract the JSON payload of the message event.
    import json

    assert response.status_code == 200, response.text
    assert "text/event-stream" in response.headers["content-type"]
    for line in response.text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[len("data: ") :])
    raise AssertionError(f"no data event in MCP response: {response.text!r}")


def test_mcp_bare_path_does_not_redirect():
    # Bare /mcp (no trailing slash) must be served directly: many MCP clients
    # don't follow the 307 Starlette's mount would otherwise issue.
    with TestClient(create_app(), follow_redirects=False) as c:
        r = c.post("/mcp", json=_mcp_ping_body())
    assert r.status_code != 307, f"bare /mcp 307-redirected to {r.headers.get('location')}"
    assert _mcp_result(r)["result"] == {}


def test_mcp_trailing_slash_path_still_works():
    with TestClient(create_app(), follow_redirects=False) as c:
        r = c.post("/mcp/", json=_mcp_ping_body())
    assert _mcp_result(r)["result"] == {}
