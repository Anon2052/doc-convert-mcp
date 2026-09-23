"""Tests for the anonymous free tier + usage analytics.

Free tier: monthly credit bucket per client IP (FREE_MONTHLY_CREDITS,
default 50 — Scott's call), keyed by the first X-Forwarded-For entry. Same
credit math as subscribers (credits_for_price from the single x402 price
map). Middleware order: valid X-Subscriber-Key -> subscriber path; x402-paid
call -> exempt; else free bucket -> deduct; else 402. Exhaustion is 402
(free_tier_exhausted), never 429. FREE_TIER_ENABLED=false skips the free path.

Analytics: usage_daily rollup (date, tool, plan_type, calls, credits) in the
same billing DB; GET /billing/stats is admin-authed (ADMIN_KEY) and never
consumes quota. No PII in rollups — IPs are hashed for the free bucket and
never stored in usage_daily.
"""

from __future__ import annotations

import base64
import os
import sqlite3

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


# ------------------------------------------------------------- helpers
def _enable_billing_db(monkeypatch, tmp_path):
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "billing.db"))


def _pdf_post(client, **kwargs):
    return client.post(
        "/convert/pdf",
        files={"file": ("t.pdf", make_pdf_bytes("FreeTier"), "application/pdf")},
        **kwargs,
    )


def _spreadsheet_post(client, **kwargs):
    return client.post(
        "/convert/spreadsheet",
        files={"file": ("a.csv", b"x,y\n1,2\n", "text/csv")},
        **kwargs,
    )


def _mcp_tool_call(client, **kwargs):
    pdf_b64 = base64.b64encode(make_pdf_bytes("MCP FreeTier")).decode()
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


def _db_file(tmp_path):
    # Tests point BILLING_DB_PATH at tmp_path/"subscribers.db" (_enable_stripe)
    # or tmp_path/"billing.db" (_enable_billing_db) — read whichever is live.
    return os.environ.get("BILLING_DB_PATH", str(tmp_path / "billing.db"))


def _free_rows(tmp_path):
    conn = sqlite3.connect(_db_file(tmp_path))
    try:
        return conn.execute("SELECT ip_hash, month, credits FROM free_usage").fetchall()
    except sqlite3.OperationalError:
        return []  # table never created: bucket untouched


def _daily_rows(tmp_path):
    conn = sqlite3.connect(_db_file(tmp_path))
    try:
        return conn.execute(
            "SELECT date, tool, plan_type, calls, credits FROM usage_daily"
        ).fetchall()
    except sqlite3.OperationalError:
        return []  # table never created: nothing recorded


@pytest.fixture()
def fake_facilitator(monkeypatch):
    fake = _FakeFacilitator()
    monkeypatch.setattr(x402, "get_facilitator_client", lambda: fake)
    return fake


@pytest.fixture()
def admin(monkeypatch):
    monkeypatch.setenv("ADMIN_KEY", "test-admin-key-123")
    return "test-admin-key-123"


# ------------------------------------------------------------- free: deduction
def test_free_tier_serves_and_deducts_per_price(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_billing_db(monkeypatch, tmp_path)
    monkeypatch.delenv("FREE_TIER_ENABLED", raising=False)  # default ON
    client = TestClient(create_app())
    headers = {"X-Forwarded-For": "203.0.113.7"}
    assert _pdf_post(client, headers=headers).status_code == 200  # $0.03 -> 3.0
    assert _spreadsheet_post(client, headers=headers).status_code == 200  # $0.02 -> 2.0
    rows = _free_rows(tmp_path)
    assert len(rows) == 1
    assert rows[0][0] == billing.hash_client_ip("203.0.113.7")  # hashed, not raw
    assert rows[0][1] == billing.current_month_utc()
    assert rows[0][2] == pytest.approx(5.0)


def test_free_tier_keyed_by_first_xff_entry(monkeypatch, tmp_path):
    """X-Forwarded-For 'a, b' and 'b' are separate buckets (Render-aware)."""
    _enable_x402(monkeypatch)
    _enable_billing_db(monkeypatch, tmp_path)
    monkeypatch.setenv("FREE_MONTHLY_CREDITS", "3")
    client = TestClient(create_app())
    h1 = {"X-Forwarded-For": "10.0.0.1, 10.0.0.2"}
    h2 = {"X-Forwarded-For": "10.0.0.2"}
    assert _pdf_post(client, headers=h1).status_code == 200  # 3.0, bucket full
    assert _pdf_post(client, headers=h1).status_code == 402  # exhausted
    assert _pdf_post(client, headers=h2).status_code == 200  # separate bucket
    hashes = {r[0] for r in _free_rows(tmp_path)}
    assert hashes == {
        billing.hash_client_ip("10.0.0.1"),
        billing.hash_client_ip("10.0.0.2"),
    }


def test_free_tier_falls_back_to_peer_ip_without_xff(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_billing_db(monkeypatch, tmp_path)
    r = _pdf_post(TestClient(create_app()))  # no X-Forwarded-For
    assert r.status_code == 200, r.text
    assert len(_free_rows(tmp_path)) == 1


def test_free_tier_covers_mcp_tool_calls(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_billing_db(monkeypatch, tmp_path)
    headers = {"X-Forwarded-For": "203.0.113.8"}
    with TestClient(create_app()) as client:  # lifespan: FastMCP session manager
        r = _mcp_tool_call(client, headers=headers)
        assert r.status_code == 200, r.text[:400]
    rows = _free_rows(tmp_path)
    assert rows[0][2] == pytest.approx(3.0)  # pdf_to_markdown -> 3.0 credits


# ------------------------------------------------------------- free: exhaustion
def test_free_tier_exhaustion_returns_402_with_shape(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_billing_db(monkeypatch, tmp_path)
    monkeypatch.setenv("FREE_MONTHLY_CREDITS", "5")
    client = TestClient(create_app())
    headers = {"X-Forwarded-For": "203.0.113.9"}
    assert _pdf_post(client, headers=headers).status_code == 200  # 3.0 used
    r = _pdf_post(client, headers=headers)  # 6.0 > 5 -> denied
    assert r.status_code == 402, r.text  # 402, NOT 429
    assert r.status_code != 429
    body = r.json()
    assert body["error"] == "free_tier_exhausted"
    assert body["credits_used"] == pytest.approx(3.0)
    assert body["free_limit"] == pytest.approx(5.0)
    assert body["resets_at"] == billing.month_reset_iso(billing.current_month_utc())
    assert body["upgrade_hint"]  # non-empty
    assert "x402" in body["message"] or "X-Payment" in body["message"]
    assert "$9" in body["message"]


def test_denied_calls_never_consume_credits(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_billing_db(monkeypatch, tmp_path)
    monkeypatch.setenv("FREE_MONTHLY_CREDITS", "5")
    client = TestClient(create_app())
    headers = {"X-Forwarded-For": "203.0.113.10"}
    assert _pdf_post(client, headers=headers).status_code == 200
    assert _pdf_post(client, headers=headers).status_code == 402
    assert _pdf_post(client, headers=headers).status_code == 402  # still denied
    rows = _free_rows(tmp_path)
    assert len(rows) == 1
    assert rows[0][2] == pytest.approx(3.0)  # denied calls added nothing


def test_free_tier_month_reset(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_billing_db(monkeypatch, tmp_path)
    monkeypatch.setenv("FREE_MONTHLY_CREDITS", "3")
    client = TestClient(create_app())
    headers = {"X-Forwarded-For": "203.0.113.11"}
    assert _pdf_post(client, headers=headers).status_code == 200  # 3.0, full
    assert _pdf_post(client, headers=headers).status_code == 402
    monkeypatch.setattr(billing, "current_month_utc", lambda: "2099-03")
    assert _pdf_post(client, headers=headers).status_code == 200  # fresh bucket
    months = {r[1] for r in _free_rows(tmp_path)}
    assert "2099-03" in months


# ------------------------------------------------------------- free: kill switch
@pytest.mark.parametrize("value", ["0", "false", "no", "off"])
def test_free_tier_disabled_skips_to_402(monkeypatch, tmp_path, value):
    _enable_x402(monkeypatch)
    _enable_billing_db(monkeypatch, tmp_path)
    monkeypatch.setenv("FREE_TIER_ENABLED", value)
    r = _pdf_post(TestClient(create_app()), headers={"X-Forwarded-For": "203.0.113.12"})
    assert r.status_code == 402, r.text
    assert r.json()["error"] == "payment_required"  # the plain x402 challenge
    assert _free_rows(tmp_path) == []  # bucket untouched


def test_free_tier_enabled_by_default(monkeypatch):
    monkeypatch.delenv("FREE_TIER_ENABLED", raising=False)
    assert billing.free_tier_enabled() is True
    monkeypatch.setenv("FREE_TIER_ENABLED", "true")
    assert billing.free_tier_enabled() is True


# ------------------------------------------------------------- free: limit parsing
@pytest.mark.parametrize(
    ("env_value", "expected"),
    [
        (None, 50.0),  # unset -> default (Scott's call)
        ("", 50.0),
        ("200", 200.0),
        ("2.5", 2.5),
        ("banana", 50.0),
        ("0", 50.0),
        ("-5", 50.0),
    ],
)
def test_free_limit_env_parsing(monkeypatch, env_value, expected):
    if env_value is None:
        monkeypatch.delenv("FREE_MONTHLY_CREDITS", raising=False)
    else:
        monkeypatch.setenv("FREE_MONTHLY_CREDITS", env_value)
    assert billing.free_monthly_credits() == expected


# ------------------------------------------------------------- middleware order
def test_subscriber_path_unaffected_by_free_tier(monkeypatch, tmp_path):
    """Valid subscriber key -> subscriber path: free bucket untouched."""
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    monkeypatch.delenv("FREE_TIER_ENABLED", raising=False)
    raw = billing.create_subscriber("cus_free1", "a@b.c")
    r = _pdf_post(
        TestClient(create_app()),
        headers={"X-Subscriber-Key": raw, "X-Forwarded-For": "203.0.113.13"},
    )
    assert r.status_code == 200, r.text
    conn = sqlite3.connect(str(tmp_path / "subscribers.db"))
    (sub_credits,) = conn.execute("SELECT credits FROM subscriber_usage").fetchone()
    assert sub_credits == pytest.approx(3.0)
    assert conn.execute("SELECT COUNT(*) FROM free_usage").fetchone()[0] == 0


def test_subscriber_cap_still_429_not_free_fallback(monkeypatch, tmp_path):
    """A capped subscriber is NOT silently served from the free tier."""
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    monkeypatch.setenv("SUBSCRIBER_MONTHLY_CREDIT_LIMIT", "1")
    raw = billing.create_subscriber("cus_free2", "a@b.c")
    headers = {"X-Subscriber-Key": raw, "X-Forwarded-For": "203.0.113.14"}
    r = _pdf_post(TestClient(create_app()), headers=headers)
    assert r.status_code == 429, r.text  # cap code UNTOUCHED
    assert r.json()["error"] == "subscriber_monthly_cap_exceeded"


def test_x402_paid_path_exempt_from_free_bucket(monkeypatch, tmp_path, fake_facilitator):
    """A call presenting X-Payment never touches the free bucket."""
    _enable_x402(monkeypatch)
    _enable_billing_db(monkeypatch, tmp_path)
    client = TestClient(create_app())
    headers = dict(_payment_header())
    headers["X-Forwarded-For"] = "203.0.113.15"
    r = _pdf_post(client, headers=headers)
    assert r.status_code == 200, r.text
    assert fake_facilitator.verify_calls == 1
    assert _free_rows(tmp_path) == []


# ------------------------------------------------------------- analytics rollup
def test_rollup_records_each_plan_type(monkeypatch, tmp_path, fake_facilitator):
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    raw = billing.create_subscriber("cus_an1", "a@b.c")
    client = TestClient(create_app())
    free_h = {"X-Forwarded-For": "203.0.113.20"}
    assert _pdf_post(client, headers=free_h).status_code == 200
    assert _pdf_post(client, headers={"X-Subscriber-Key": raw}).status_code == 200
    pay_h = dict(_payment_header())
    assert _pdf_post(client, headers=pay_h).status_code == 200
    rows = {(t, p): (c, cr) for _, t, p, c, cr in _daily_rows(tmp_path)}
    today = billing.current_date_utc()
    assert rows[("pdf_to_markdown", "free")] == (1, pytest.approx(3.0))
    assert rows[("pdf_to_markdown", "subscriber")] == (1, pytest.approx(3.0))
    # x402 path records the credits that WOULD have been charged (list price)
    assert rows[("pdf_to_markdown", "x402")] == (1, pytest.approx(3.0))
    assert all(r[0] == today for r in _daily_rows(tmp_path))


def test_rollup_separates_tools(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_billing_db(monkeypatch, tmp_path)
    client = TestClient(create_app())
    headers = {"X-Forwarded-For": "203.0.113.21"}
    assert _pdf_post(client, headers=headers).status_code == 200
    assert _spreadsheet_post(client, headers=headers).status_code == 200
    rows = {(t, p): (c, cr) for _, t, p, c, cr in _daily_rows(tmp_path)}
    assert rows[("pdf_to_markdown", "free")] == (1, pytest.approx(3.0))
    assert rows[("parse_spreadsheet", "free")] == (1, pytest.approx(2.0))


def test_rollup_day_boundary_utc(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_billing_db(monkeypatch, tmp_path)
    client = TestClient(create_app())
    headers = {"X-Forwarded-For": "203.0.113.22"}
    assert _pdf_post(client, headers=headers).status_code == 200
    monkeypatch.setattr(billing, "current_date_utc", lambda: "2099-06-15")
    assert _pdf_post(client, headers=headers).status_code == 200
    dates = {r[0] for r in _daily_rows(tmp_path)}
    assert len(dates) == 2
    assert "2099-06-15" in dates


def test_zero_credit_outcomes_recorded_as_zero(monkeypatch, tmp_path):
    """Payments off: served calls roll up with 0 credits (nothing deducted)."""
    monkeypatch.delenv("X402_ENABLED", raising=False)
    _enable_billing_db(monkeypatch, tmp_path)
    r = _pdf_post(TestClient(create_app()))
    assert r.status_code == 200, r.text
    rows = _daily_rows(tmp_path)
    assert len(rows) == 1
    assert rows[0][1:] == ("pdf_to_markdown", "free", 1, pytest.approx(0.0))


def test_denied_calls_not_recorded_in_analytics(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_billing_db(monkeypatch, tmp_path)
    monkeypatch.setenv("FREE_MONTHLY_CREDITS", "3")
    client = TestClient(create_app())
    headers = {"X-Forwarded-For": "203.0.113.23"}
    assert _pdf_post(client, headers=headers).status_code == 200
    assert _pdf_post(client, headers=headers).status_code == 402  # denied
    rows = _daily_rows(tmp_path)
    assert len(rows) == 1
    assert rows[0][3] == 1  # calls not incremented by the denied call


def test_record_usage_rejects_unknown_plan(tmp_path):
    with pytest.raises(ValueError):
        billing.record_usage("pdf_to_markdown", "bogus", 1.0)


def test_no_pii_in_rollup_schema(monkeypatch, tmp_path):
    """usage_daily carries no IP (or other PII) column — aggregates only."""
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "probe.db"))
    billing.record_usage("pdf_to_markdown", "free", 3.0)
    conn = sqlite3.connect(str(tmp_path / "probe.db"))
    cols = [r[1] for r in conn.execute("PRAGMA table_info(usage_daily)").fetchall()]
    assert cols == ["date", "tool", "plan_type", "calls", "credits"]


# ------------------------------------------------------------- /billing/stats
def test_stats_endpoint_shape(monkeypatch, tmp_path, admin):
    _enable_x402(monkeypatch)
    _enable_billing_db(monkeypatch, tmp_path)
    client = TestClient(create_app())
    headers = {"X-Forwarded-For": "203.0.113.30"}
    assert _pdf_post(client, headers=headers).status_code == 200
    assert _spreadsheet_post(client, headers=headers).status_code == 200
    r = client.get("/billing/stats", headers={"X-Admin-Key": admin})
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["days"]) == 30  # default days=30
    today = billing.current_date_utc()
    assert body["days"][-1]["date"] == today
    tools = body["days"][-1]["tools"]
    assert tools["pdf_to_markdown"]["free"] == {"calls": 1, "credits": 3.0}
    assert tools["parse_spreadsheet"]["free"] == {"calls": 1, "credits": 2.0}
    # all three plan buckets present, zero-filled
    assert tools["pdf_to_markdown"]["subscriber"] == {"calls": 0, "credits": 0.0}
    assert tools["pdf_to_markdown"]["x402"] == {"calls": 0, "credits": 0.0}
    totals = body["totals"]
    assert totals["calls"] == 2
    assert totals["credits"] == pytest.approx(5.0)
    assert totals["by_plan"]["free"] == {"calls": 2, "credits": 5.0}


def test_stats_auth(monkeypatch, tmp_path, admin):
    _enable_billing_db(monkeypatch, tmp_path)
    client = TestClient(create_app())
    r = client.get("/billing/stats")
    assert r.status_code == 401
    assert r.json()["error"] == "unauthorized"
    r = client.get("/billing/stats", headers={"X-Admin-Key": "wrong"})
    assert r.status_code == 401
    # query param works too
    r = client.get("/billing/stats", params={"admin_key": admin})
    assert r.status_code == 200, r.text


def test_stats_401_when_admin_key_not_configured(monkeypatch, tmp_path):
    """Fail closed: no ADMIN_KEY set -> every request 401s."""
    _enable_billing_db(monkeypatch, tmp_path)
    monkeypatch.delenv("ADMIN_KEY", raising=False)
    client = TestClient(create_app())
    r = client.get("/billing/stats", headers={"X-Admin-Key": "anything"})
    assert r.status_code == 401


@pytest.mark.parametrize(
    ("param", "expected_days"),
    [("7", 7), ("1", 1), ("0", 1), ("-3", 1), ("9999", 365)],
)
def test_stats_days_clamping(monkeypatch, tmp_path, admin, param, expected_days):
    _enable_billing_db(monkeypatch, tmp_path)
    client = TestClient(create_app())
    r = client.get("/billing/stats", params={"days": param, "admin_key": admin})
    assert r.status_code == 200, r.text
    assert len(r.json()["days"]) == expected_days


def test_stats_never_consumes_quota(monkeypatch, tmp_path, admin):
    """Reading stats touches neither the free bucket nor the rollup."""
    _enable_x402(monkeypatch)
    _enable_billing_db(monkeypatch, tmp_path)
    monkeypatch.setenv("FREE_MONTHLY_CREDITS", "3")
    client = TestClient(create_app())
    for _ in range(3):
        r = client.get("/billing/stats", headers={"X-Admin-Key": admin})
        assert r.status_code == 200
    assert _daily_rows(tmp_path) == []
    assert _free_rows(tmp_path) == []
    # and the bucket is still full afterwards
    r = _pdf_post(client, headers={"X-Forwarded-For": "203.0.113.31"})
    assert r.status_code == 200, r.text
