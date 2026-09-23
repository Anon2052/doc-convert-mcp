"""Tests for the Pro subscription fair-use cap (SUBSCRIBER_MONTHLY_CALL_LIMIT).

The cap applies to subscriber-key auth only (REST and MCP); plain x402
per-call payers are never capped. Counters live in the same SQLite DB as the
subscriber rows and reset on the UTC calendar-month boundary.
"""

from __future__ import annotations

import base64
import re
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
    return conn.execute("SELECT key_hash, month, calls FROM subscriber_usage").fetchall()


@pytest.fixture()
def fake_facilitator(monkeypatch):
    fake = _FakeFacilitator()
    monkeypatch.setattr(x402, "get_facilitator_client", lambda: fake)
    return fake


# ------------------------------------------------------------- cap behavior
def test_subscriber_under_cap_gets_200_and_is_counted(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    monkeypatch.delenv("SUBSCRIBER_MONTHLY_CALL_LIMIT", raising=False)
    raw = billing.create_subscriber("cus_cap1", "a@b.c")
    r = _pdf_post(TestClient(create_app()), headers={"X-Subscriber-Key": raw})
    assert r.status_code == 200, r.text
    rows = _usage_rows(tmp_path)
    assert len(rows) == 1
    assert rows[0][1] == billing.current_month_utc()  # month column
    assert rows[0][2] == 1  # one call counted


def test_subscriber_over_cap_gets_actionable_429(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    monkeypatch.setenv("SUBSCRIBER_MONTHLY_CALL_LIMIT", "2")
    raw = billing.create_subscriber("cus_cap2", "a@b.c")
    client = TestClient(create_app())
    headers = {"X-Subscriber-Key": raw}
    assert _pdf_post(client, headers=headers).status_code == 200
    assert _pdf_post(client, headers=headers).status_code == 200
    r = _pdf_post(client, headers=headers)
    assert r.status_code == 429, r.text
    body = r.json()
    month = billing.current_month_utc()
    assert body["error"] == "subscriber_monthly_cap_exceeded"
    assert body["limit"] == 2
    assert body["usage"] == 3
    assert body["period"] == month
    assert body["resets_at"] == billing.month_reset_iso(month)
    assert re.match(r"^\d{4}-\d{2}-01T00:00:00\+00:00$", body["resets_at"])
    assert "x402" in body["message"].lower()  # fallback spelled out
    # still capped afterwards (never silently served)
    assert _pdf_post(client, headers=headers).status_code == 429


def test_cap_covers_mcp_tool_calls(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    monkeypatch.setenv("SUBSCRIBER_MONTHLY_CALL_LIMIT", "1")
    raw = billing.create_subscriber("cus_cap_mcp", "a@b.c")
    headers = {"X-Subscriber-Key": raw}
    with TestClient(create_app()) as client:  # lifespan: FastMCP session manager
        r = _mcp_tool_call(client, headers=headers)
        assert r.status_code == 200, r.text[:400]
        r = _mcp_tool_call(client, headers=headers)
        assert r.status_code == 429, r.text[:400]
        assert r.json()["error"] == "subscriber_monthly_cap_exceeded"


def test_month_rollover_resets_counter(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    monkeypatch.setenv("SUBSCRIBER_MONTHLY_CALL_LIMIT", "1")
    raw = billing.create_subscriber("cus_cap_roll", "a@b.c")
    client = TestClient(create_app())
    headers = {"X-Subscriber-Key": raw}
    first_month = billing.current_month_utc()
    assert _pdf_post(client, headers=headers).status_code == 200
    assert _pdf_post(client, headers=headers).status_code == 429
    # patch the current month: the old month's counter no longer applies
    monkeypatch.setattr(billing, "current_month_utc", lambda: "2099-02")
    assert _pdf_post(client, headers=headers).status_code == 200
    months = {row[1] for row in _usage_rows(tmp_path)}
    assert months == {first_month, "2099-02"}


def test_x402_per_call_payers_are_never_capped(monkeypatch, tmp_path, fake_facilitator):
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    monkeypatch.setenv("SUBSCRIBER_MONTHLY_CALL_LIMIT", "1")
    raw = billing.create_subscriber("cus_cap_payer", "a@b.c")
    client = TestClient(create_app())
    # blow the subscriber cap first
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
    monkeypatch.setenv("SUBSCRIBER_MONTHLY_CALL_LIMIT", "1")
    r = _pdf_post(TestClient(create_app()), headers={"X-Subscriber-Key": "bogus"})
    assert r.status_code == 402
    assert _usage_rows(tmp_path) == []


# ------------------------------------------------------------- limit parsing
@pytest.mark.parametrize(
    ("env_value", "expected"),
    [
        (None, 1000),  # unset -> default
        ("", 1000),
        ("50", 50),
        ("banana", 1000),  # invalid -> default
        ("0", 1000),  # non-positive -> default
        ("-5", 1000),
    ],
)
def test_limit_env_parsing(monkeypatch, env_value, expected):
    if env_value is None:
        monkeypatch.delenv("SUBSCRIBER_MONTHLY_CALL_LIMIT", raising=False)
    else:
        monkeypatch.setenv("SUBSCRIBER_MONTHLY_CALL_LIMIT", env_value)
    assert billing.subscriber_monthly_call_limit() == expected


def test_month_reset_iso():
    assert billing.month_reset_iso("2026-09") == "2026-10-01T00:00:00+00:00"
    assert billing.month_reset_iso("2026-12") == "2027-01-01T00:00:00+00:00"
    assert re.match(r"^\d{4}-\d{2}$", billing.current_month_utc())
