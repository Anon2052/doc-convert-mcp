"""Free-tier tests: the monthly anonymous credit bucket (aligned across
all three connectors — Scott's call, 2026-10-21).

- Monthly free bucket ``FREE_MONTHLY_CREDITS`` (default 50 credits =
  $0.50 of calls at list price), keyed by client IP (first X-Forwarded-For
  entry behind the proxy). No key, no payment required.
- Same credit math as subscribers: ``credits_for_price`` from the single
  x402 price map (pdf_to_markdown $0.008 -> 0.8 credits).
- Middleware order: valid X-Subscriber-Key -> subscriber path -> X-Payment
  present -> x402 flow (never touches the bucket) -> free bucket -> 402.
  REST + MCP share the hook.
- Exhausted bucket -> 402 ``free_tier_exhausted`` (NOT 429), carrying
  credits_used / free_limit / resets_at plus the canonical x402 payment
  challenge so the caller can pay per call immediately.
- Denied/exhausted calls never consume credits. ``FREE_TIER_ENABLED=0``
  skips the free path entirely (straight to the x402 402).
- IPs are stored as SHA-256 hashes, never raw.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import sqlite3

import pytest
from fastapi.testclient import TestClient

from doc_convert_mcp import billing, x402
from doc_convert_mcp.rest_app import create_app
from tests.test_converters import make_pdf_bytes
from tests.test_payments import _enable_x402, _FakeFacilitator, _payment_header

IP_A = "10.0.0.1"
IP_B = "10.0.0.2"


def _next_month() -> str:
    """Calendar month after the current UTC month.

    The month-reset test must target a month different from 'now' — the
    hardcoded '2026-11' went stale the moment November arrived and the
    patch became a no-op.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    year, month = (now.year + 1, 1) if now.month == 12 else (now.year, now.month + 1)
    return f"{year:04d}-{month:02d}"


@pytest.fixture(autouse=True)
def _isolated_billing_db(monkeypatch, tmp_path):
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "billing.db"))


@pytest.fixture()
def free_client(monkeypatch):
    """App with x402 enabled and the free tier ON, bucket = 2.0 credits
    (two $0.008 PDF conversions = 1.6 credits fit; the third does not)."""
    _enable_x402(monkeypatch)
    monkeypatch.delenv("FREE_TIER_ENABLED", raising=False)  # default: on
    monkeypatch.setenv("FREE_MONTHLY_CREDITS", "2.0")
    with TestClient(create_app()) as client:
        yield client


def _pdf_post(client, ip=IP_A, **headers):
    return client.post(
        "/convert/pdf",
        files={"file": ("t.pdf", make_pdf_bytes("FreeTier"), "application/pdf")},
        headers={"X-Forwarded-For": ip, **headers},
    )


def _mcp_pdf_call(client, ip=IP_A, **headers):
    pdf_b64 = base64.b64encode(make_pdf_bytes("FreeTier MCP")).decode()
    return client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "pdf_to_markdown", "arguments": {"pdf_base64": pdf_b64}},
        },
        headers={"X-Forwarded-For": ip, **headers},
    )


# ---------------------------------------------------------- deduction


def test_free_bucket_serves_and_deducts(free_client):
    assert _pdf_post(free_client).status_code == 200
    assert _pdf_post(free_client).status_code == 200
    usage = billing.get_free_tier_usage(IP_A)
    assert usage["credits_used"] == 1.6
    assert usage["free_limit"] == 2.0


def test_default_free_limit_is_50_credits(monkeypatch):
    monkeypatch.delenv("FREE_MONTHLY_CREDITS", raising=False)
    assert billing.free_monthly_credit_limit() == 50.0


def test_bad_free_limit_env_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("FREE_MONTHLY_CREDITS", "banana")
    assert billing.free_monthly_credit_limit() == 50.0
    monkeypatch.setenv("FREE_MONTHLY_CREDITS", "-5")
    assert billing.free_monthly_credit_limit() == 50.0
    monkeypatch.setenv("FREE_MONTHLY_CREDITS", "0")
    assert billing.free_monthly_credit_limit() == 0.0


def test_free_tier_enabled_default_and_kill_switch(monkeypatch):
    monkeypatch.delenv("FREE_TIER_ENABLED", raising=False)
    assert billing.free_tier_enabled() is True
    monkeypatch.setenv("FREE_TIER_ENABLED", "false")
    assert billing.free_tier_enabled() is False
    monkeypatch.setenv("FREE_TIER_ENABLED", "0")
    assert billing.free_tier_enabled() is False


# ---------------------------------------------------------- exhaustion


def test_exhaustion_returns_402_with_fields(free_client):
    assert _pdf_post(free_client).status_code == 200
    assert _pdf_post(free_client).status_code == 200
    r = _pdf_post(free_client)
    assert r.status_code == 402
    body = r.json()
    assert body["error"] == "free_tier_exhausted"
    assert body["credits_used"] == 1.6
    assert body["free_limit"] == 2.0
    assert body["resets_at"]
    # The canonical x402 challenge rides along so the caller can pay now.
    assert body["paymentRequirements"]["maxAmountRequired"] == "8000"


def test_exhausted_calls_never_consume_credits(free_client):
    _pdf_post(free_client)
    _pdf_post(free_client)
    assert _pdf_post(free_client).status_code == 402
    assert _pdf_post(free_client).status_code == 402
    assert billing.get_free_tier_usage(IP_A)["credits_used"] == 1.6


def test_month_reset_refills_bucket(free_client, monkeypatch):
    _pdf_post(free_client)
    _pdf_post(free_client)
    assert _pdf_post(free_client).status_code == 402
    monkeypatch.setattr(billing, "current_month_utc", lambda: _next_month())
    assert _pdf_post(free_client).status_code == 200
    usage = billing.get_free_tier_usage(IP_A)
    assert usage["period"] == _next_month()
    assert usage["credits_used"] == 0.8


# ---------------------------------------------------------- IP keying


def test_separate_buckets_per_ip(free_client):
    _pdf_post(free_client, ip=IP_A)
    _pdf_post(free_client, ip=IP_A)
    assert _pdf_post(free_client, ip=IP_A).status_code == 402
    assert _pdf_post(free_client, ip=IP_B).status_code == 200
    assert billing.get_free_tier_usage(IP_B)["credits_used"] == 0.8


def test_free_bucket_stores_hash_not_raw_ip(free_client, tmp_path):
    _pdf_post(free_client, ip=IP_A)
    conn = sqlite3.connect(tmp_path / "billing.db")
    rows = conn.execute("SELECT ip_hash FROM free_tier_usage").fetchall()
    assert rows == [(hashlib.sha256(IP_A.encode()).hexdigest(),)]


# ------------------------------------------------- kill switch + discovery


def test_free_tier_disabled_falls_straight_to_402(monkeypatch):
    _enable_x402(monkeypatch)
    monkeypatch.setenv("FREE_TIER_ENABLED", "false")
    with TestClient(create_app()) as client:
        r = _pdf_post(client)
    assert r.status_code == 402
    assert r.json()["error"] == "payment_required"


def test_discovery_never_deducts(free_client):
    for method in ("initialize", "tools/list", "prompts/list", "resources/list"):
        r = free_client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": method},
            headers={"X-Forwarded-For": IP_A},
        )
        assert r.status_code == 200, method
    assert billing.get_free_tier_usage(IP_A)["credits_used"] == 0.0


def test_mcp_tools_call_shares_bucket_with_rest(free_client):
    assert _pdf_post(free_client).status_code == 200  # REST: 0.8 credits
    assert _mcp_pdf_call(free_client).status_code == 200  # MCP: 0.8 credits
    assert billing.get_free_tier_usage(IP_A)["credits_used"] == 1.6
    assert _mcp_pdf_call(free_client).status_code == 402  # bucket spent


# ---------------------------------------------------------- precedence


def test_x402_paid_path_never_touches_bucket(free_client, monkeypatch):
    fake = _FakeFacilitator()
    monkeypatch.setattr(x402, "get_facilitator_client", lambda: fake)
    r = _pdf_post(free_client, **_payment_header())
    assert r.status_code == 200, r.text
    assert billing.get_free_tier_usage(IP_A)["credits_used"] == 0.0


def test_invalid_subscriber_key_falls_through_to_free(free_client):
    r = _pdf_post(free_client, **{"X-Subscriber-Key": "bogus-key"})
    assert r.status_code == 200
    assert billing.get_free_tier_usage(IP_A)["credits_used"] == 0.8


# ---------------------------------------------------------- always-paid alias


def test_paid_alias_unpaid_402s_and_never_touches_bucket(free_client):
    """Paid-route batch: /paid/convert/pdf 402s a first-time unpaid
    caller (the directory-checker probe case) instead of serving from
    the free bucket, and the main route still serves free afterwards."""
    r = free_client.post(
        "/paid/convert/pdf",
        files={"file": ("t.pdf", make_pdf_bytes("FreeTier"), "application/pdf")},
        headers={"X-Forwarded-For": IP_A},
    )
    assert r.status_code == 402
    assert r.json()["error"] == "payment_required"
    assert billing.get_free_tier_usage(IP_A)["credits_used"] == 0.0
    assert _pdf_post(free_client).status_code == 200


def test_paid_alias_serves_valid_payment(free_client, monkeypatch):
    """The alias is always-paid, not a wall: a verified X-Payment serves
    it at the same price, without touching the free bucket."""
    fake = _FakeFacilitator()
    monkeypatch.setattr(x402, "get_facilitator_client", lambda: fake)
    r = free_client.post(
        "/paid/convert/pdf",
        files={"file": ("t.pdf", make_pdf_bytes("FreeTier"), "application/pdf")},
        headers={"X-Forwarded-For": IP_A, **_payment_header()},
    )
    assert r.status_code == 200, r.text
    assert billing.get_free_tier_usage(IP_A)["credits_used"] == 0.0
