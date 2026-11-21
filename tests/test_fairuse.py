"""Tests for the Pro subscription fair-use CREDIT cap
(SUBSCRIBER_MONTHLY_CREDIT_LIMIT).

1 credit = $0.01 of x402 list price; the credit cost of a call derives from
the same per-tool price map the x402 middleware uses (single source of
truth). The cap applies to subscriber-key auth only (REST and MCP); plain
x402 per-call payers are never capped. Counters live in the same SQLite DB
as the subscriber rows and reset on the UTC calendar-month boundary.
GET /billing/usage reports credit usage and is always free.
"""

from __future__ import annotations

import base64
import re
import sqlite3
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient

from doc_convert_mcp import billing, x402
from doc_convert_mcp.rest_app import create_app
from tests.test_converters import make_pdf_bytes  # noqa: F401
from tests.test_payments import (
    _enable_stripe,
    _enable_x402,
    _FakeFacilitator,
    _payment_header,
)


@pytest.fixture(autouse=True)
def _isolated_billing_db(monkeypatch, tmp_path):
    """M-1: the replay table is persistent — point every test at a scratch
    DB so claims can never leak between tests (or touch the real path)."""
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "billing.db"))


# ------------------------------------------------------------- helpers
def _pdf_post(client, **kwargs):
    return client.post(
        "/convert/pdf",
        files={"file": ("t.pdf", make_pdf_bytes("FairUse"), "application/pdf")},
        **kwargs,
    )


def _mcp_tool_call(client, **kwargs):
    pdf_b64 = base64.b64encode(make_pdf_bytes("MCP FairUse")).decode()
    return client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "pdf_to_markdown", "arguments": {"pdf_base64": pdf_b64}},
        },
        **kwargs,
    )


def _usage_rows(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "subscribers.db"))
    return conn.execute("SELECT key_hash, month, credits FROM subscriber_usage").fetchall()


@pytest.fixture()
def fake_facilitator(monkeypatch):
    fake = _FakeFacilitator()
    monkeypatch.setattr(x402, "get_facilitator_client", lambda: fake)
    return fake


# ------------------------------------------------------------- credit math
@pytest.mark.parametrize(
    ("price", "expected"),
    [
        (Decimal("0.03"), 3.0),
        (Decimal("0.02"), 2.0),
        (Decimal("0.01"), 1.0),
        (Decimal("0.008"), 0.8),  # current uniform tool price
        (Decimal("0.015"), 1.5),
    ],
)
def test_credits_for_price(price, expected):
    assert x402.credits_for_price(price) == expected


# ------------------------------------------------------------- cap behavior
def test_subscriber_under_cap_gets_200_and_is_charged_credits(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    monkeypatch.delenv("SUBSCRIBER_MONTHLY_CREDIT_LIMIT", raising=False)
    raw = billing.create_subscriber("cus_cap1", "a@b.c")
    r = _pdf_post(TestClient(create_app()), headers={"X-Subscriber-Key": raw})
    assert r.status_code == 200, r.text
    rows = _usage_rows(tmp_path)
    assert len(rows) == 1
    assert rows[0][1] == billing.current_month_utc()  # month column
    # pdf_to_markdown lists at $0.008 -> 0.8 credits deducted (not 1 "call")
    assert rows[0][2] == pytest.approx(0.8)


def test_mixed_tool_costs_deduct_fractional_credits(monkeypatch, tmp_path):
    """Expensive tools cost more credits than cheap ones."""
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    monkeypatch.delenv("SUBSCRIBER_MONTHLY_CREDIT_LIMIT", raising=False)
    raw = billing.create_subscriber("cus_cap_mix", "a@b.c")
    client = TestClient(create_app())
    headers = {"X-Subscriber-Key": raw}
    assert _pdf_post(client, headers=headers).status_code == 200  # $0.008 -> 0.8
    r = client.post(
        "/convert/spreadsheet",
        files={"file": ("a.csv", b"x,y\n1,2\n", "text/csv")},
        headers=headers,
    )
    assert r.status_code == 200, r.text  # $0.008 -> 0.8
    (credits,) = _usage_rows(tmp_path)[0][2:3]
    assert credits == pytest.approx(1.6)


def test_subscriber_over_cap_gets_actionable_429(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    monkeypatch.setenv("SUBSCRIBER_MONTHLY_CREDIT_LIMIT", "5")
    raw = billing.create_subscriber("cus_cap2", "a@b.c")
    client = TestClient(create_app())
    headers = {"X-Subscriber-Key": raw}
    for _ in range(6):  # 6 x 0.8 = 4.8 <= 5
        assert _pdf_post(client, headers=headers).status_code == 200
    r = _pdf_post(client, headers=headers)  # 5.6 > 5 -> 429
    assert r.status_code == 429, r.text
    body = r.json()
    month = billing.current_month_utc()
    assert body["error"] == "subscriber_monthly_cap_exceeded"
    assert body["credits_used"] == pytest.approx(5.6)
    assert body["credit_limit"] == pytest.approx(5.0)
    assert body["period"] == month
    assert body["resets_at"] == billing.month_reset_iso(month)
    assert re.match(r"^\d{4}-\d{2}-01T00:00:00\+00:00$", body["resets_at"])
    assert "x402" in body["message"].lower()  # fallback spelled out
    assert "x-subscriber-key" in body["message"].lower()
    # still capped afterwards (never silently served)
    assert _pdf_post(client, headers=headers).status_code == 429


def test_cap_covers_mcp_tool_calls(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    monkeypatch.setenv("SUBSCRIBER_MONTHLY_CREDIT_LIMIT", "5")
    raw = billing.create_subscriber("cus_cap_mcp", "a@b.c")
    headers = {"X-Subscriber-Key": raw}
    with TestClient(create_app()) as client:  # lifespan: FastMCP session manager
        for _ in range(6):  # 6 x 0.8 = 4.8 <= 5
            r = _mcp_tool_call(client, headers=headers)
            assert r.status_code == 200, r.text[:400]
        r = _mcp_tool_call(client, headers=headers)  # 5.6 > 5 -> 429
        assert r.status_code == 429, r.text[:400]
        assert r.json()["error"] == "subscriber_monthly_cap_exceeded"


def test_month_rollover_resets_counter(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    monkeypatch.setenv("SUBSCRIBER_MONTHLY_CREDIT_LIMIT", "5")
    raw = billing.create_subscriber("cus_cap_roll", "a@b.c")
    client = TestClient(create_app())
    headers = {"X-Subscriber-Key": raw}
    first_month = billing.current_month_utc()
    for _ in range(6):  # 6 x 0.8 = 4.8 <= 5
        assert _pdf_post(client, headers=headers).status_code == 200
    assert _pdf_post(client, headers=headers).status_code == 429  # 5.6 > 5
    # patch the current month: the old month's credits no longer apply
    monkeypatch.setattr(billing, "current_month_utc", lambda: "2099-02")
    assert _pdf_post(client, headers=headers).status_code == 200
    months = {row[1] for row in _usage_rows(tmp_path)}
    assert months == {first_month, "2099-02"}


def test_x402_per_call_payers_are_never_capped(monkeypatch, tmp_path, fake_facilitator):
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    monkeypatch.setenv("SUBSCRIBER_MONTHLY_CREDIT_LIMIT", "1")
    raw = billing.create_subscriber("cus_cap_payer", "a@b.c")
    client = TestClient(create_app())
    # blow the subscriber cap first (2 x 0.8 = 1.6 > 1)
    assert _pdf_post(client, headers={"X-Subscriber-Key": raw}).status_code == 200
    assert _pdf_post(client, headers={"X-Subscriber-Key": raw}).status_code == 429
    # a per-call payer (no subscriber key, valid x402 payment) still works
    r = _pdf_post(client, headers=_payment_header())
    assert r.status_code == 200, r.text
    assert fake_facilitator.verify_calls == 1
    # the payer was not counted against the subscriber's usage row
    assert len(_usage_rows(tmp_path)) == 1


def test_invalid_key_is_not_counted_and_still_402(monkeypatch, tmp_path, fake_facilitator):
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    # Free tier off: with it on, an invalid key lands in the anonymous
    # free bucket instead of the 402 flow (see test_free_tier.py).
    monkeypatch.setenv("FREE_TIER_ENABLED", "false")
    monkeypatch.setenv("SUBSCRIBER_MONTHLY_CREDIT_LIMIT", "1")
    r = _pdf_post(TestClient(create_app()), headers={"X-Subscriber-Key": "bogus"})
    assert r.status_code == 402
    assert _usage_rows(tmp_path) == []


def test_legacy_calls_schema_upgrades_cleanly(monkeypatch, tmp_path):
    """A DB written by the old call-based build (no `credits` column) still works."""
    _enable_stripe(monkeypatch, tmp_path)
    conn = sqlite3.connect(str(tmp_path / "subscribers.db"))
    conn.execute(
        "CREATE TABLE subscriber_usage ("
        " key_hash TEXT NOT NULL, month TEXT NOT NULL,"
        " calls INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (key_hash, month))"
    )
    conn.commit()
    conn.close()
    raw = billing.create_subscriber("cus_legacy", "a@b.c")
    usage = billing.record_subscriber_credits(raw, 3.0)
    assert usage["credits_used"] == pytest.approx(3.0)
    rows = _usage_rows(tmp_path)
    assert rows[0][2] == pytest.approx(3.0)


# ------------------------------------------------------------- /billing/usage
def test_billing_usage_returns_accurate_numbers(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    monkeypatch.delenv("SUBSCRIBER_MONTHLY_CREDIT_LIMIT", raising=False)
    raw = billing.create_subscriber("cus_usage1", "a@b.c")
    client = TestClient(create_app())
    headers = {"X-Subscriber-Key": raw}
    assert _pdf_post(client, headers=headers).status_code == 200  # 0.8 credits
    r = client.get("/billing/usage", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    month = billing.current_month_utc()
    assert body["credits_used"] == pytest.approx(0.8)
    assert body["credit_limit"] == pytest.approx(1000.0)
    assert body["period"] == month
    assert body["resets_at"] == billing.month_reset_iso(month)
    # reading usage never consumes credits
    r2 = client.get("/billing/usage", headers=headers)
    assert r2.json()["credits_used"] == pytest.approx(0.8)


def test_billing_usage_is_free_when_capped(monkeypatch, tmp_path):
    """The usage endpoint is never 429-gated by the cap itself."""
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    monkeypatch.setenv("SUBSCRIBER_MONTHLY_CREDIT_LIMIT", "1")
    raw = billing.create_subscriber("cus_usage2", "a@b.c")
    client = TestClient(create_app())
    headers = {"X-Subscriber-Key": raw}
    assert _pdf_post(client, headers=headers).status_code == 200  # 0.8 <= 1
    assert _pdf_post(client, headers=headers).status_code == 429  # 1.6 > 1: capped
    r = client.get("/billing/usage", headers=headers)
    assert r.status_code == 200, r.text  # NOT 429
    assert r.json()["credits_used"] == pytest.approx(1.6)


def test_billing_usage_rejects_bad_key(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    client = TestClient(create_app())
    r = client.get("/billing/usage", headers={"X-Subscriber-Key": "bogus"})
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_subscriber_key"
    r = client.get("/billing/usage")
    assert r.status_code == 401


# ------------------------------------------------------------- limit parsing
@pytest.mark.parametrize(
    ("env_value", "expected"),
    [
        (None, 1000.0),  # unset -> default
        ("", 1000.0),
        ("50", 50.0),
        ("2.5", 2.5),  # fractional limits allowed
        ("banana", 1000.0),  # invalid -> default
        ("0", 1000.0),  # non-positive -> default
        ("-5", 1000.0),
    ],
)
def test_limit_env_parsing(monkeypatch, env_value, expected):
    if env_value is None:
        monkeypatch.delenv("SUBSCRIBER_MONTHLY_CREDIT_LIMIT", raising=False)
    else:
        monkeypatch.setenv("SUBSCRIBER_MONTHLY_CREDIT_LIMIT", env_value)
    assert billing.subscriber_monthly_credit_limit() == expected


def test_old_call_limit_env_is_gone(monkeypatch):
    """The old SUBSCRIBER_MONTHLY_CALL_LIMIT env no longer exists anywhere."""
    assert not hasattr(billing, "subscriber_monthly_call_limit")
    assert not hasattr(billing, "DEFAULT_SUBSCRIBER_MONTHLY_CALL_LIMIT")
    monkeypatch.setenv("SUBSCRIBER_MONTHLY_CALL_LIMIT", "5")
    # setting the legacy env must not affect the credit cap
    assert billing.subscriber_monthly_credit_limit() == 1000.0


def test_month_reset_iso():
    assert billing.month_reset_iso("2026-09") == "2026-10-01T00:00:00+00:00"
    assert billing.month_reset_iso("2026-12") == "2027-01-01T00:00:00+00:00"
    assert re.match(r"^\d{4}-\d{2}$", billing.current_month_utc())
