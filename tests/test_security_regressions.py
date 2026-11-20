"""Regression tests for the pre-launch security fixes (H-1..H-8, M-1..M-5).

Each test pins one audit finding so a future refactor can't silently
re-open it. H-1/H-2/H-3 are covered via tests/test_converters.py's
patched _fetch_guarded seam plus the live checks below.
"""

from __future__ import annotations

import base64
import io
import json
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from doc_convert_mcp import billing as billing_mod
from doc_convert_mcp import converters
from doc_convert_mcp import rest_app as rest_app_mod
from doc_convert_mcp import x402 as x402_mod
from doc_convert_mcp.converters import ConversionError
from doc_convert_mcp.rest_app import create_app

VALID_PAY_TO = "0xAbC1230000000000000000000000000000000001"


@pytest.fixture(autouse=True)
def _isolated_billing_db(monkeypatch, tmp_path):
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "billing.db"))


def _enable_x402(monkeypatch, **over):
    monkeypatch.setenv("X402_ENABLED", "true")
    monkeypatch.setenv("X402_PAY_TO", over.get("pay_to", VALID_PAY_TO))
    monkeypatch.setenv(
        "X402_FACILITATOR_URL", over.get("facilitator", "https://x402.org/facilitator")
    )


def _x402_header(*, valid_after=None, valid_before=None):
    import secrets

    now = int(time.time())
    payload = {
        "x402Version": 1,
        "scheme": "exact",
        "network": "base",
        "payload": {
            "signature": "0x" + secrets.token_hex(32),
            "authorization": {
                "from": "0xPayer000000000000000000000000000000000002",
                "to": VALID_PAY_TO,
                "value": "8000",
                "validAfter": str(now - 60 if valid_after is None else valid_after),
                "validBefore": str(now + 240 if valid_before is None else valid_before),
                "nonce": "0x" + secrets.token_hex(32),
            },
        },
    }
    return {"X-Payment": base64.b64encode(json.dumps(payload).encode()).decode()}


def _fake_facilitator(monkeypatch):
    fake = rest_app_mod  # placeholder to keep linters calm
    del fake

    class _F:
        async def verify(self, payment_payload, payment_requirements):
            return {"isValid": True, "payer": "0xPayer"}

        async def settle(self, payment_payload, payment_requirements):
            return {"success": True, "transaction": "0xTx", "network": "base"}

    monkeypatch.setattr(x402_mod, "get_facilitator_client", lambda: _F())


# ------------------------------------------------------------------ M-1


def test_m1_oversize_validity_window_rejected(monkeypatch):
    """M-1: an authorization window wider than MAX_TIMEOUT_SECONDS (300s)
    is rejected at the sanity check, before any facilitator call."""
    _enable_x402(monkeypatch)
    _fake_facilitator(monkeypatch)
    xc = TestClient(create_app())
    now = int(time.time())
    r = xc.post(
        "/convert/url",
        json={"url": "https://example.com/"},
        headers=_x402_header(valid_after=now - 60, valid_before=now + 300),
    )
    assert r.status_code == 402
    assert r.json()["reason"] == "authorization validity window exceeds maximum"


def test_m1_replay_claim_is_atomic_and_persistent(monkeypatch, tmp_path):
    """M-1: the replay claim is an atomic DB INSERT — the second claim of
    the same signature fails even across app instances (process restarts)."""
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "replay.db"))
    sig = "0x" + "ef" * 32
    assert billing_mod.claim_x402_signature(sig, time.time() + 300) is False
    assert billing_mod.claim_x402_signature(sig, time.time() + 300) is True
    import sqlite3

    rows = (
        sqlite3.connect(str(tmp_path / "replay.db"))
        .execute("SELECT COUNT(*) FROM x402_seen_signatures")
        .fetchone()
    )
    assert rows[0] == 1


# ------------------------------------------------------------------ M-5


def test_m5_bad_pay_to_fails_closed(monkeypatch):
    """M-5: a malformed X402_PAY_TO disables x402 instead of letting paid
    endpoints run unprotected."""
    _enable_x402(monkeypatch, pay_to="0xAbC123")
    assert x402_mod.x402_config_problems() != []
    assert x402_mod.x402_effective_enabled() is False


def test_m5_non_https_facilitator_fails_closed(monkeypatch):
    _enable_x402(monkeypatch, facilitator="http://x402.org/facilitator")
    assert x402_mod.x402_config_problems() != []
    assert x402_mod.x402_effective_enabled() is False


def test_m5_valid_config_stays_enabled(monkeypatch):
    _enable_x402(monkeypatch)
    assert x402_mod.x402_config_problems() == []
    assert x402_mod.x402_effective_enabled() is True


# ------------------------------------------------------------------ H-5


def test_h5_mcp_mount_is_rate_limited(monkeypatch):
    """H-5: the /mcp mount (invisible to SlowAPI's default_limits) is
    throttled by the pure-ASGI wrapper: over the per-minute budget -> 429."""
    _enable_x402(monkeypatch)
    xc = TestClient(create_app(rate_limit="3/minute"))
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    with xc:
        statuses = [xc.post("/mcp", json=body).status_code for _ in range(5)]
    assert statuses[:3] == [200, 200, 200]
    assert statuses[3] == 429
    assert statuses[4] == 429


# ------------------------------------------------------------------ M-3


def _scope(*, peer, xff=None, cf_ip=None):
    headers = []
    if xff is not None:
        headers.append((b"x-forwarded-for", xff.encode("latin-1")))
    if cf_ip is not None:
        headers.append((b"cf-connecting-ip", cf_ip.encode("latin-1")))
    return {"headers": headers, "client": (peer, 12345)}


def test_m3_spoofed_xff_ignored_on_direct_connection():
    """M-3: a direct client (global peer IP) cannot rotate rate-limit
    buckets by spoofing X-Forwarded-For."""
    key = rest_app_mod._client_ip_from_scope(_scope(peer="8.8.8.8", xff="10.9.9.9"))
    assert key == "8.8.8.8"


def test_m3_xff_honored_behind_proxy():
    key = rest_app_mod._client_ip_from_scope(
        _scope(peer="10.0.0.5", xff="8.8.8.8, 10.0.0.5")
    )
    assert key == "8.8.8.8"


def test_m3_garbage_xff_falls_back_to_peer():
    key = rest_app_mod._client_ip_from_scope(_scope(peer="10.0.0.5", xff="not-an-ip"))
    assert key == "10.0.0.5"


# ------------------------------------------------- Cloudflare proxy flip


def test_cf_connecting_ip_honored_from_cloudflare_peer():
    """CF-Connecting-IP is trusted when the TCP peer is a Cloudflare edge
    IP (proxied DNS). 172.64.1.10 is inside 172.64.0.0/13."""
    key = rest_app_mod._client_ip_from_scope(
        _scope(peer="172.64.1.10", cf_ip="8.8.8.8")
    )
    assert key == "8.8.8.8"


def test_cf_connecting_ip_honored_from_cloudflare_ipv6_peer():
    """Same fast path for a Cloudflare IPv6 edge peer (2606:4700::/32)."""
    key = rest_app_mod._client_ip_from_scope(
        _scope(peer="2606:4700:0:0:0:0:0:1", cf_ip="1.1.1.1")
    )
    assert key == "1.1.1.1"


def test_cf_connecting_ip_ignored_from_non_cloudflare_peer():
    """A spoofed CF-Connecting-IP from a direct (non-Cloudflare) peer is
    ignored — falls back to existing direct-connection logic (XFF ignored)."""
    key = rest_app_mod._client_ip_from_scope(
        _scope(peer="8.8.8.8", cf_ip="1.2.3.4")
    )
    assert key == "8.8.8.8"


def test_cf_connecting_ip_garbage_falls_back_to_peer():
    """Garbage CF-Connecting-IP from a Cloudflare peer falls back to the
    peer instead of poisoning the rate-limit bucket."""
    key = rest_app_mod._client_ip_from_scope(
        _scope(peer="172.64.1.10", cf_ip="not-an-ip")
    )
    assert key == "172.64.1.10"


def test_cf_peer_without_cf_header_ignores_xff():
    """Cloudflare peer with no CF-Connecting-IP: XFF is NOT trusted (first
    XFF entry is client-spoofable through Cloudflare) — falls back to the
    peer, same as any global peer."""
    key = rest_app_mod._client_ip_from_scope(
        _scope(peer="172.64.1.10", xff="8.8.8.8")
    )
    assert key == "172.64.1.10"


# ------------------------------------------------------------------ H-4


def test_h4_oversize_upload_rejected_413(monkeypatch):
    """H-4: a /convert/* POST declaring Content-Length over 30MB is 413'd
    by the middleware before the body is read."""
    xc = TestClient(create_app())
    big = b"x" * (31 * 1024 * 1024)
    r = xc.post(
        "/convert/pdf",
        files={"file": ("big.pdf", big, "application/pdf")},
        headers={"Content-Length": str(len(big) + 500)},
    )
    assert r.status_code == 413
    assert r.json()["error"] == "upload_too_large"


# ------------------------------------------------------------------ H-6


def _make_zip_bomb() -> bytes:
    """A tiny zip whose central directory claims >200MB uncompressed.

    zipfile.writestr() overwrites ZipInfo.file_size with the real data
    length, so the claim is patched into the central-directory headers
    (uncompressed size at offset 24 of each PK\\x01\\x02 record) — exactly
    what a real bomb looks like to the pre-scan.
    """
    import struct

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for i in range(4):
            zf.writestr(f"payload{i}.bin", b"tiny")
    data = bytearray(buf.getvalue())
    idx = 0
    patched = 0
    while True:
        idx = data.find(b"PK\x01\x02", idx)
        if idx < 0:
            break
        struct.pack_into("<I", data, idx + 24, 60 * 1024 * 1024)  # 60MB claimed
        patched += 1
        idx += 4
    assert patched == 4
    return bytes(data)


def test_h6_zip_bomb_rejected_before_inflation():
    """H-6: an xlsx whose entries claim >200MB uncompressed is rejected by
    the central-directory pre-scan — openpyxl never inflates it."""
    with pytest.raises(ConversionError, match="uncompressed"):
        converters._guard_zip(_make_zip_bomb(), "workbook.xlsx")


def test_h6_zip_entry_count_cap():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for i in range(10_001):
            zf.writestr(f"f{i}.txt", b"x")
    with pytest.raises(ConversionError, match="entries"):
        converters._guard_zip(buf.getvalue(), "workbook.xlsx")


def test_h6_pdf_text_cap_constant_sane():
    """H-6: the extracted-text cap exists and is 10M chars."""
    assert converters.MAX_PDF_TEXT_CHARS == 10 * 1024 * 1024


# ------------------------------------------------------------------ M-2


def test_m2_one_time_webhook_mode_does_not_create_subscriber(monkeypatch, tmp_path):
    """M-2: a checkout.session.completed webhook for a one-time (non
    subscription) checkout must NOT create a subscriber."""
    monkeypatch.setenv("STRIPE_ENABLED", "true")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_fixture")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_fixture")
    monkeypatch.setenv("STRIPE_PRICE_ID", "price_fixture")
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "subscribers.db"))
    event = billing_mod.stripe.Event.construct_from(
        {
            "id": "evt_once",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_once",
                    "mode": "payment",  # one-time, not subscription
                    "customer": "cus_once",
                    "customer_details": {"email": "o@example.com"},
                }
            },
        },
        "sk_test_fixture",
    )
    monkeypatch.setattr(
        billing_mod.stripe.Webhook, "construct_event", lambda payload, sig, secret: event
    )
    r = TestClient(create_app()).post("/billing/stripe-webhook", content=b"{}")
    assert r.status_code == 200  # acknowledged, not acted on
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "subscribers.db"))
    tables = [row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='subscribers'"
    )]
    if tables:
        rows = conn.execute("SELECT COUNT(*) FROM subscribers").fetchone()
        assert rows[0] == 0
