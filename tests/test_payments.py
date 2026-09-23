"""Tests for real x402 verification + Stripe billing (payments OFF by default)."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from doc_convert_mcp import billing, x402
from doc_convert_mcp.rest_app import create_app
from doc_convert_mcp.x402 import (
    USDC_BASE_CONTRACT,
    FacilitatorClient,
    build_payment_requirements,
    check_payment_sanity,
    decode_x_payment,
    mint_cdp_jwt,
    tool_price_usdc,
    usdc_to_atomic_units,
    x402_effective_enabled,
)
from tests.test_converters import make_pdf_bytes  # noqa: F401

PAY_TO = "0xAbC1230000000000000000000000000000000001"


# ------------------------------------------------------------- helpers
def _enable_x402(monkeypatch, **over):
    monkeypatch.setenv("X402_ENABLED", "true")
    monkeypatch.setenv("X402_PAY_TO", PAY_TO)
    monkeypatch.setenv("X402_FACILITATOR_URL", "https://x402.org/facilitator")
    for k, v in over.items():
        monkeypatch.setenv(k, v)


def _enable_stripe(monkeypatch, tmp_path, **over):
    monkeypatch.setenv("STRIPE_ENABLED", "true")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_fixture")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_fixture")
    monkeypatch.setenv("STRIPE_PRICE_ID", "price_fixture")
    monkeypatch.setenv("STRIPE_SUCCESS_URL", "https://example.com/success")
    monkeypatch.setenv("STRIPE_CANCEL_URL", "https://example.com/cancel")
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "subscribers.db"))
    for k, v in over.items():
        monkeypatch.setenv(k, v)


def _auth(**over):
    now = int(time.time())
    auth = {
        "from": "0xPayer000000000000000000000000000000000002",
        "to": PAY_TO,
        "value": "30000",  # 0.03 USDC in atomic units
        "validAfter": str(now - 60),
        "validBefore": str(now + 300),
        "nonce": "0x" + "ab" * 32,
    }
    auth.update(over)
    return auth


def _payment_header(**auth_over):
    import secrets as _secrets

    payload = {
        "x402Version": 1,
        "scheme": "exact",
        "network": "base",
        "payload": {
            # unique per call so the anti-replay set never collides across tests
            "signature": "0x" + _secrets.token_hex(32),
            "authorization": _auth(**auth_over),
        },
    }
    raw = base64.b64encode(json.dumps(payload).encode()).decode()
    return {"X-Payment": raw}


class _FakeFacilitator:
    def __init__(self, verify_result=True, verify_exc=None, settle_exc=None):
        self.verify_result = verify_result
        self.verify_exc = verify_exc
        self.settle_exc = settle_exc
        self.verify_calls = 0
        self.settle_calls = 0

    async def verify(self, payment_payload, payment_requirements):
        self.verify_calls += 1
        if self.verify_exc:
            raise self.verify_exc
        if isinstance(self.verify_result, dict):
            return self.verify_result
        return {"isValid": bool(self.verify_result), "payer": "0xPayer"}

    async def settle(self, payment_payload, payment_requirements):
        self.settle_calls += 1
        if self.settle_exc:
            raise self.settle_exc
        return {"success": True, "transaction": "0xTxHash123", "network": "base"}


@pytest.fixture()
def fake_facilitator(monkeypatch):
    fake = _FakeFacilitator()
    monkeypatch.setattr(x402, "get_facilitator_client", lambda: fake)
    return fake


# ------------------------------------------------------------- disabled by default
def test_disabled_by_default_serves_without_payment(tmp_path, monkeypatch):
    monkeypatch.delenv("X402_ENABLED", raising=False)
    monkeypatch.delenv("STRIPE_ENABLED", raising=False)
    client = TestClient(create_app())
    r = client.post(
        "/convert/pdf", files={"file": ("t.pdf", make_pdf_bytes("Hi"), "application/pdf")}
    )
    assert r.status_code == 200
    assert not x402_effective_enabled()
    assert not billing.stripe_effective_enabled()


def test_enabled_but_incomplete_config_stays_disabled(monkeypatch, caplog):
    monkeypatch.setenv("X402_ENABLED", "true")
    monkeypatch.delenv("X402_PAY_TO", raising=False)
    assert not x402_effective_enabled()
    client = TestClient(create_app())
    r = client.post("/convert/pdf", files={"file": ("t.pdf", b"x", "application/pdf")})
    assert r.status_code != 402  # fail closed = disabled, not half-enforcing


# ------------------------------------------------------------- 402 challenge shape
def test_402_challenge_shape(monkeypatch):
    _enable_x402(monkeypatch)
    monkeypatch.setenv("FREE_TIER_ENABLED", "0")  # test the x402 path, not the free bucket
    client = TestClient(create_app())
    r = client.post(
        "/convert/pdf", files={"file": ("t.pdf", make_pdf_bytes("Hi"), "application/pdf")}
    )
    assert r.status_code == 402
    body = r.json()
    assert body["error"] == "payment_required"
    assert body["accepts"]["scheme"] == "exact"
    assert "STUB" not in json.dumps(body)
    reqs = body["paymentRequirements"]
    assert reqs["asset"] == USDC_BASE_CONTRACT
    assert reqs["network"] == "base"
    assert reqs["scheme"] == "exact"
    assert reqs["payTo"] == PAY_TO
    # pdf_to_markdown default $0.03 -> 30000 atomic units
    assert reqs["maxAmountRequired"] == "30000"


def test_per_tool_pricing_and_env_override(monkeypatch):
    _enable_x402(monkeypatch, X402_PRICE_OCR_IMAGE_USDC="0.05")
    monkeypatch.setenv("FREE_TIER_ENABLED", "0")  # test the x402 path, not the free bucket
    client = TestClient(create_app())
    r = client.post("/convert/ocr", files={"file": ("t.png", b"x", "image/png")})
    assert r.status_code == 402
    assert r.json()["paymentRequirements"]["maxAmountRequired"] == "50000"
    # other tools unaffected
    r = client.post(
        "/convert/pdf", files={"file": ("t.pdf", make_pdf_bytes("Hi"), "application/pdf")}
    )
    assert r.json()["paymentRequirements"]["maxAmountRequired"] == "30000"
    r = client.post("/convert/url", json={"url": "https://example.com/"})
    assert r.json()["paymentRequirements"]["maxAmountRequired"] == "10000"


def test_invalid_price_env_falls_back_to_default(monkeypatch):
    _enable_x402(monkeypatch, X402_PRICE_OCR_IMAGE_USDC="bogus")
    monkeypatch.setenv("FREE_TIER_ENABLED", "0")  # test the x402 path, not the free bucket
    client = TestClient(create_app())
    r = client.post("/convert/ocr", files={"file": ("t.png", b"x", "image/png")})
    assert r.status_code == 402
    # ocr_image code default $0.02 -> 20000, never zero
    assert r.json()["paymentRequirements"]["maxAmountRequired"] == "20000"


def test_generic_default_price(monkeypatch):
    _enable_x402(monkeypatch)
    assert tool_price_usdc("no_such_tool") == x402.tool_price_usdc(None)
    assert usdc_to_atomic_units(tool_price_usdc(None)) == 15000


# ------------------------------------------------------------- MCP discovery exemption
def test_mcp_discovery_methods_exempt(monkeypatch):
    _enable_x402(monkeypatch)
    with TestClient(create_app()) as client:
        for method in ("initialize", "tools/list", "ping"):
            r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method})
            assert r.status_code == 200, f"{method} should be free, got {r.status_code}"


def test_mcp_tools_call_requires_payment(monkeypatch):
    _enable_x402(monkeypatch)
    monkeypatch.setenv("FREE_TIER_ENABLED", "0")  # test the x402 path, not the free bucket
    client = TestClient(create_app())
    r = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "ocr_image", "arguments": {}},
        },
    )
    assert r.status_code == 402
    assert r.json()["paymentRequirements"]["maxAmountRequired"] == "20000"


def test_mcp_unparseable_body_gets_default_price_not_500(monkeypatch):
    _enable_x402(monkeypatch)
    monkeypatch.setenv("FREE_TIER_ENABLED", "0")  # test the x402 path, not the free bucket
    client = TestClient(create_app())
    r = client.post("/mcp", content=b"not json", headers={"Content-Type": "application/json"})
    assert r.status_code == 402  # default price, not a 500


# ------------------------------------------------------------- X-Payment decode + sanity
def test_decode_x_payment_roundtrip():
    headers = _payment_header()
    payload = decode_x_payment(headers["X-Payment"])
    assert payload["scheme"] == "exact"
    assert payload["payload"]["authorization"]["to"] == PAY_TO


def test_decode_x_payment_malformed():
    assert decode_x_payment("not-base64!!!") is None
    assert decode_x_payment(base64.b64encode(b"[1,2]").decode()) is None


def _requirements(price="0.03"):
    from decimal import Decimal

    return build_payment_requirements(Decimal(price), "http://t/", "test")


def test_sanity_rejects_bad_recipient(monkeypatch):
    _enable_x402(monkeypatch)
    payload = decode_x_payment(_payment_header(to="0xWrong")["X-Payment"])
    assert check_payment_sanity(payload, _requirements()) == "bad recipient"


def test_sanity_rejects_low_value(monkeypatch):
    _enable_x402(monkeypatch)
    payload = decode_x_payment(_payment_header(value="1")["X-Payment"])
    assert check_payment_sanity(payload, _requirements()) == "insufficient value"


def test_sanity_rejects_expired(monkeypatch):
    _enable_x402(monkeypatch)
    now = int(time.time())
    payload = decode_x_payment(
        _payment_header(validAfter=str(now - 600), validBefore=str(now - 60))["X-Payment"]
    )
    assert check_payment_sanity(payload, _requirements()) == "authorization not currently valid"


def test_sanity_rejects_wrong_network(monkeypatch):
    _enable_x402(monkeypatch)
    raw = base64.b64encode(
        json.dumps(
            {
                "x402Version": 1,
                "scheme": "exact",
                "network": "ethereum",
                "payload": {"signature": "0xabc", "authorization": _auth()},
            }
        ).encode()
    ).decode()
    assert check_payment_sanity(decode_x_payment(raw), _requirements()) == "bad network"


def test_sanity_accepts_well_formed(monkeypatch):
    _enable_x402(monkeypatch)
    payload = decode_x_payment(_payment_header()["X-Payment"])
    assert check_payment_sanity(payload, _requirements()) is None


# ------------------------------------------------------------- facilitator verify/settle
def test_verify_false_gives_402_payment_invalid(monkeypatch, fake_facilitator):
    _enable_x402(monkeypatch)
    fake_facilitator.verify_result = {"isValid": False, "invalidReason": "bad signature"}
    client = TestClient(create_app())
    r = client.post(
        "/convert/pdf",
        files={"file": ("t.pdf", make_pdf_bytes("Hi"), "application/pdf")},
        headers=_payment_header(),
    )
    assert r.status_code == 402
    body = r.json()
    assert body["error"] == "payment_invalid"
    assert body["invalidReason"] == "bad signature"


def test_verify_true_serves_and_settles(monkeypatch, fake_facilitator):
    _enable_x402(monkeypatch)
    client = TestClient(create_app())
    r = client.post(
        "/convert/pdf",
        files={"file": ("t.pdf", make_pdf_bytes("Paid"), "application/pdf")},
        headers=_payment_header(),
    )
    assert r.status_code == 200, r.text
    assert "Paid" in r.json()["markdown"]
    assert fake_facilitator.verify_calls == 1
    assert fake_facilitator.settle_calls == 1


def test_settle_failure_still_serves(monkeypatch, caplog):
    _enable_x402(monkeypatch)
    fake = _FakeFacilitator(settle_exc=RuntimeError("settle down"))
    monkeypatch.setattr(x402, "get_facilitator_client", lambda: fake)
    client = TestClient(create_app())
    with caplog.at_level("ERROR", logger="doc_convert_mcp.x402"):
        r = client.post(
            "/convert/pdf",
            files={"file": ("t.pdf", make_pdf_bytes("Hi"), "application/pdf")},
            headers=_payment_header(),
        )
    assert r.status_code == 200
    assert "SETTLE FAILED" in caplog.text


def test_facilitator_unreachable_gives_503(monkeypatch):
    import httpx

    _enable_x402(monkeypatch)
    fake = _FakeFacilitator(verify_exc=httpx.ConnectError("no route"))
    monkeypatch.setattr(x402, "get_facilitator_client", lambda: fake)
    client = TestClient(create_app())
    r = client.post(
        "/convert/pdf",
        files={"file": ("t.pdf", make_pdf_bytes("Hi"), "application/pdf")},
        headers=_payment_header(),
    )
    assert r.status_code == 503
    assert r.json()["error"] == "payment_verification_unavailable"


def test_replay_same_signature_twice(monkeypatch, fake_facilitator):
    _enable_x402(monkeypatch)
    client = TestClient(create_app())
    sig = "0xReplay" + "ee" * 32
    headers = _payment_header()
    payload = decode_x_payment(headers["X-Payment"])
    payload["payload"]["signature"] = sig
    headers = {"X-Payment": base64.b64encode(json.dumps(payload).encode()).decode()}
    files = {"file": ("t.pdf", make_pdf_bytes("Hi"), "application/pdf")}
    r1 = client.post("/convert/pdf", files=files, headers=headers)
    assert r1.status_code == 200
    r2 = client.post(
        "/convert/pdf",
        files={"file": ("t.pdf", make_pdf_bytes("Hi"), "application/pdf")},
        headers=headers,
    )
    assert r2.status_code == 402
    assert r2.json()["error"] == "duplicate_payment"


def test_malformed_x_payment_header_gets_402(monkeypatch, fake_facilitator):
    _enable_x402(monkeypatch)
    client = TestClient(create_app())
    r = client.post(
        "/convert/pdf",
        files={"file": ("t.pdf", b"x", "application/pdf")},
        headers={"X-Payment": "not-json"},
    )
    assert r.status_code == 402
    assert fake_facilitator.verify_calls == 0


# ------------------------------------------------------------- CDP JWT
def _b64url_decode(part: str) -> dict:
    padded = part + "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def test_mint_cdp_jwt_structure_and_signature():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    seed_hex = key.private_bytes_raw().hex()
    jwt = mint_cdp_jwt("test-key-id", seed_hex)
    header_b64, claims_b64, sig_b64 = jwt.split(".")
    header, claims = _b64url_decode(header_b64), _b64url_decode(claims_b64)
    assert header["alg"] == "EdDSA"
    assert header["kid"] == "test-key-id"
    assert len(header["nonce"]) == 32
    assert claims["sub"] == "test-key-id"
    assert claims["iss"] == "coinbase-cloud"
    assert claims["exp"] > claims["nbf"]
    # signature verifies against the derived public key
    signing_input = f"{header_b64}.{claims_b64}".encode()
    sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    key.public_key().verify(sig, signing_input)


def test_mint_cdp_jwt_accepts_pem():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    jwt = mint_cdp_jwt("pem-key", pem)
    assert jwt.count(".") == 2
    assert _b64url_decode(jwt.split(".")[0])["kid"] == "pem-key"


def test_mint_cdp_jwt_rejects_garbage():
    import pytest as _pytest

    with _pytest.raises(ValueError):
        mint_cdp_jwt("x", "not-a-key")


def test_facilitator_client_sends_api_key_header(monkeypatch):
    captured = {}

    class _CapClient:
        async def post(self, url, json=None, headers=None):
            captured["headers"] = headers
            captured["url"] = url

            class _Resp:
                def raise_for_status(self): ...
                def json(self):
                    return {"isValid": True}

            return _Resp()

    monkeypatch.setenv("X402_FACILITATOR_API_KEY", "fac-key-123")
    client = FacilitatorClient(http_client=_CapClient())
    import asyncio

    asyncio.run(client.verify({}, {}))
    assert captured["headers"]["X-API-Key"] == "fac-key-123"
    assert captured["url"].endswith("/verify")


# ------------------------------------------------------------- Stripe
def test_stripe_disabled_checkout_404(monkeypatch, tmp_path):
    monkeypatch.delenv("STRIPE_ENABLED", raising=False)
    client = TestClient(create_app())
    assert client.post("/billing/checkout").status_code == 404
    assert client.post("/billing/stripe-webhook", content=b"{}").status_code == 404
    assert client.get("/billing/key?session_id=cs_x").status_code == 404


def test_billing_status_reports_effective_state(monkeypatch, tmp_path):
    monkeypatch.delenv("STRIPE_ENABLED", raising=False)
    monkeypatch.delenv("X402_ENABLED", raising=False)
    client = TestClient(create_app())
    assert client.get("/billing/status").json() == {
        "stripe_enabled": False,
        "x402_enabled": False,
    }
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    assert TestClient(create_app()).get("/billing/status").json() == {
        "stripe_enabled": True,
        "x402_enabled": True,
    }


def test_health_reports_payment_state(monkeypatch, tmp_path):
    _enable_x402(monkeypatch)
    _enable_stripe(monkeypatch, tmp_path)
    body = TestClient(create_app()).get("/health").json()
    assert body["x402"] == "enabled"
    assert body["stripe"] == "enabled"
    assert "secret" not in json.dumps(body).lower()


def test_webhook_completed_creates_subscriber(monkeypatch, tmp_path):
    _enable_stripe(monkeypatch, tmp_path)
    event = {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer": "cus_123",
                "customer_details": {"email": "buyer@example.com"},
            }
        },
    }
    monkeypatch.setattr(
        billing.stripe.Webhook, "construct_event", lambda payload, sig, secret: event
    )
    r = TestClient(create_app()).post("/billing/stripe-webhook", content=b"{}")
    assert r.status_code == 200
    conn = sqlite3.connect(str(tmp_path / "subscribers.db"))
    rows = conn.execute("SELECT key_hash, customer_id, email, status FROM subscribers").fetchall()
    assert len(rows) == 1
    key_hash, customer_id, email, status = rows[0]
    assert customer_id == "cus_123"
    assert email == "buyer@example.com"
    assert status == "active"
    assert len(key_hash) == 64  # sha256 hex, not the raw token


def test_create_subscriber_stores_hash_not_raw(monkeypatch, tmp_path):
    _enable_stripe(monkeypatch, tmp_path)
    raw = billing.create_subscriber("cus_9", "a@b.c")
    assert len(raw) == 64
    conn = sqlite3.connect(str(tmp_path / "subscribers.db"))
    (stored,) = conn.execute("SELECT key_hash FROM subscribers").fetchone()
    assert stored == hashlib.sha256(raw.encode()).hexdigest()
    assert stored != raw
    assert billing.subscriber_key_valid(raw)
    assert not billing.subscriber_key_valid("wrong-key")


def test_webhook_bad_signature_400(monkeypatch, tmp_path):
    _enable_stripe(monkeypatch, tmp_path)

    def boom(payload, sig, secret):
        raise ValueError("bad sig")

    monkeypatch.setattr(billing.stripe.Webhook, "construct_event", boom)
    r = TestClient(create_app()).post("/billing/stripe-webhook", content=b"{}")
    assert r.status_code == 400


def test_webhook_subscription_deleted_deactivates(monkeypatch, tmp_path):
    _enable_stripe(monkeypatch, tmp_path)
    raw = billing.create_subscriber("cus_7", "a@b.c")
    assert billing.subscriber_key_valid(raw)
    event = {
        "type": "customer.subscription.deleted",
        "data": {"object": {"customer": "cus_7"}},
    }
    monkeypatch.setattr(
        billing.stripe.Webhook, "construct_event", lambda payload, sig, secret: event
    )
    r = TestClient(create_app()).post("/billing/stripe-webhook", content=b"{}")
    assert r.status_code == 200
    assert not billing.subscriber_key_valid(raw)


def test_webhook_subscription_updated_syncs_status(monkeypatch, tmp_path):
    _enable_stripe(monkeypatch, tmp_path)
    billing.create_subscriber("cus_8", "a@b.c")
    event = {
        "type": "customer.subscription.updated",
        "data": {"object": {"customer": "cus_8", "status": "past_due"}},
    }
    monkeypatch.setattr(
        billing.stripe.Webhook, "construct_event", lambda payload, sig, secret: event
    )
    TestClient(create_app()).post("/billing/stripe-webhook", content=b"{}")
    conn = sqlite3.connect(str(tmp_path / "subscribers.db"))
    (status,) = conn.execute("SELECT status FROM subscribers").fetchone()
    assert status == "past_due"


def test_subscriber_key_bypasses_x402(monkeypatch, tmp_path, fake_facilitator):
    _enable_x402(monkeypatch)
    monkeypatch.setenv("FREE_TIER_ENABLED", "0")  # test the x402 path, not the free bucket
    _enable_stripe(monkeypatch, tmp_path)
    raw = billing.create_subscriber("cus_bypass", "a@b.c")
    client = TestClient(create_app())
    r = client.post(
        "/convert/pdf",
        files={"file": ("t.pdf", make_pdf_bytes("Sub"), "application/pdf")},
        headers={"X-Subscriber-Key": raw},
    )
    assert r.status_code == 200, r.text
    assert "Sub" in r.json()["markdown"]
    assert fake_facilitator.verify_calls == 0  # no facilitator call needed
    # bad key falls through to the normal 402 flow
    r = client.post(
        "/convert/pdf",
        files={"file": ("t.pdf", make_pdf_bytes("Hi"), "application/pdf")},
        headers={"X-Subscriber-Key": "bogus"},
    )
    assert r.status_code == 402


def test_billing_key_issues_token_for_paid_session(monkeypatch, tmp_path):
    _enable_stripe(monkeypatch, tmp_path)
    session = {
        "payment_status": "paid",
        "customer": "cus_key",
        "customer_details": {"email": "k@example.com"},
    }
    monkeypatch.setattr(billing.stripe.checkout.Session, "retrieve", lambda session_id: session)
    r = TestClient(create_app()).get("/billing/key?session_id=cs_test_123")
    assert r.status_code == 200, r.text
    token = r.json()["subscriber_key"]
    assert billing.subscriber_key_valid(token)


def test_billing_key_rejects_unpaid_session(monkeypatch, tmp_path):
    _enable_stripe(monkeypatch, tmp_path)
    monkeypatch.setattr(
        billing.stripe.checkout.Session,
        "retrieve",
        lambda session_id: {"payment_status": "open", "customer": "cus_x"},
    )
    r = TestClient(create_app()).get("/billing/key?session_id=cs_test_123")
    assert r.status_code == 404


def test_checkout_creates_session(monkeypatch, tmp_path):
    _enable_stripe(monkeypatch, tmp_path)
    captured = {}

    class _Session:
        url = "https://checkout.stripe.com/pay/cs_test"

    def fake_create(**kwargs):
        captured.update(kwargs)
        return _Session()

    monkeypatch.setattr(billing.stripe.checkout.Session, "create", fake_create)
    r = TestClient(create_app()).post("/billing/checkout")
    assert r.status_code == 200
    assert r.json()["checkout_url"] == "https://checkout.stripe.com/pay/cs_test"
    assert captured["mode"] == "subscription"
    assert captured["line_items"] == [{"price": "price_fixture", "quantity": 1}]
