"""Solana x402 leg tests (SOLANA_PORT_PLAN §4c).

The Solana leg is opt-in via X402_NETWORKS; with it unset, behavior is the
Base-only behavior covered by test_payments.py. Facilitator calls are
monkeypatched via ``get_facilitator_client`` (same pattern as
test_payments.py); fee-payer discovery is stubbed except in the tests that
exercise it against a fake httpx client.

All Solana addresses here are SYNTHETIC base58 strings for tests only —
the real pay-to address is env-config (X402_PAY_TO_SOLANA), never code.

Doc-convert contract notes (kept deliberately, unlike search-mcp):
- ``decode_x_payment`` returns None on malformed input (pinned by
  ``test_decode_x_payment_malformed``); the middleware re-issues the 402.
- Sanity failures surface as ``payment_required`` with a reason;
  facilitator rejections are the ``payment_invalid`` ones.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import secrets
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient

from doc_convert_mcp import x402 as x402_mod
from doc_convert_mcp.rest_app import create_app
from tests.test_converters import make_pdf_bytes  # noqa: F401

# Synthetic base58 (alphabet-checked: no 0/O/I/l), 41-42 chars.
SOL_PAY_TO = "So1anaPayToTest1111111111111111111111111111"
FEE_PAYER = "FeePayerTestSo1ana111111111111111111111111"
BASE_PAY_TO = "0x000000000000000000000000000000000000dEaD"

_REAL_RESOLVE = x402_mod.resolve_solana_fee_payer


@pytest.fixture(autouse=True)
def _isolated_billing_db(monkeypatch, tmp_path):
    """M-1: the replay table is persistent — point every test at a scratch DB."""
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "billing.db"))


@pytest.fixture(autouse=True)
def _no_network_discovery(monkeypatch):
    """Keep the suite hermetic: fee-payer discovery is stubbed to 'no
    resolution' unless a test re-enables the real resolver, and the
    discovered-value cache never leaks between tests."""

    async def _stub_resolve():
        return None

    monkeypatch.setattr(x402_mod, "resolve_solana_fee_payer", _stub_resolve)
    monkeypatch.setattr(x402_mod, "_solana_fee_payer_cache", None)


def _enable_multi(monkeypatch, **over):
    env = {
        "X402_ENABLED": "true",
        "X402_PAY_TO": BASE_PAY_TO,
        "X402_FACILITATOR_URL": "https://x402.test/facilitator",
        "X402_NETWORKS": "base,solana",
        "X402_PAY_TO_SOLANA": SOL_PAY_TO,
        "X402_SOLANA_FEE_PAYER": FEE_PAYER,
        "FREE_TIER_ENABLED": "false",
    }
    env.update(over)
    for k, v in env.items():
        monkeypatch.setenv(k, v)


def _solana_payload(tx: bytes | None = None, **over):
    if tx is None:
        tx = b"\x01\x02\x03" + secrets.token_bytes(16)
    payload = {
        "x402Version": 1,
        "scheme": "exact",
        "network": "solana",
        "payload": {"transaction": base64.b64encode(tx).decode()},
    }
    payload.update(over)
    return payload


def _header(payload_dict):
    raw = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).decode().rstrip("=")
    return {"X-Payment": raw}


def _pdf_files():
    return {"file": ("t.pdf", make_pdf_bytes("Hi"), "application/pdf")}


class _FakeFacilitator:
    def __init__(self, valid=True, unreachable=False):
        self.valid = valid
        self.unreachable = unreachable
        self.verify_calls = []
        self.settle_calls = []

    async def verify(self, payment_payload, payment_requirements):
        self.verify_calls.append((payment_payload, payment_requirements))
        if self.unreachable:
            raise RuntimeError("down")
        return {"isValid": self.valid, "invalidReason": None if self.valid else "bad tx"}

    async def settle(self, payment_payload, payment_requirements):
        self.settle_calls.append((payment_payload, payment_requirements))
        if self.unreachable:
            raise RuntimeError("down")
        return {"success": True, "transaction": "Base58SettleSig111", "network": "solana"}


def _fake_solana_facilitator(monkeypatch, **kwargs):
    fake = _FakeFacilitator(**kwargs)
    monkeypatch.setattr(x402_mod, "get_facilitator_client", lambda: fake)
    return fake


# ------------------------------------------------- §4c.1 multi-network 402


def test_402_multi_network_accepts(monkeypatch, tmp_path):
    _enable_multi(monkeypatch)
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "sub.db"))
    xc = TestClient(create_app())
    body = xc.post("/convert/pdf", files=_pdf_files()).json()

    accepts = body["accepts"]
    assert isinstance(accepts, list) and len(accepts) == 2
    requirements = body["paymentRequirements"]
    assert isinstance(requirements, list) and len(requirements) == 2

    by_network = {entry["network"]: entry for entry in requirements}
    solana = by_network["solana"]
    assert solana["scheme"] == "exact"
    assert solana["asset"] == x402_mod.USDC_SOLANA_MINT
    assert solana["payTo"] == SOL_PAY_TO
    assert solana["extra"]["feePayer"] == FEE_PAYER
    # /convert/pdf is priced at 0.008 USDC; 6 decimals on Solana too.
    assert solana["maxAmountRequired"] == "8000"
    assert by_network["base"]["asset"] == x402_mod.USDC_BASE_ADDRESS

    accepts_by_network = {entry["network"]: entry for entry in accepts}
    sol_accepts = accepts_by_network["solana"]
    assert sol_accepts["asset_contract"] == x402_mod.USDC_SOLANA_MINT
    assert sol_accepts["pay_to"] == SOL_PAY_TO
    assert sol_accepts["amount_atomic"] == "8000"
    assert sol_accepts["amount_usdc"] == "0.008"


def test_requirements_list_builder(monkeypatch):
    _enable_multi(monkeypatch)
    entries = x402_mod.build_requirements_list(
        Decimal("0.008"), "https://x.test/convert/pdf", "desc"
    )
    assert [entry["network"] for entry in entries] == ["base", "solana"]
    # The Base entry must stay byte-identical to the single-network builder.
    assert entries[0] == x402_mod.build_payment_requirements(
        Decimal("0.008"), "https://x.test/convert/pdf", "desc"
    )


def test_solana_only_challenge_collapses_to_single_shape(monkeypatch, tmp_path):
    _enable_multi(monkeypatch, X402_NETWORKS="solana")
    monkeypatch.delenv("X402_PAY_TO", raising=False)
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "sub.db"))
    xc = TestClient(create_app())
    body = xc.post("/convert/pdf", files=_pdf_files()).json()
    assert isinstance(body["accepts"], dict)
    assert body["accepts"]["network"] == "solana"
    assert isinstance(body["paymentRequirements"], dict)
    assert body["paymentRequirements"]["extra"]["feePayer"] == FEE_PAYER


# ------------------------------------------------- §4c.2 payload sanity


def _solana_requirements():
    return {"network": "solana", "payTo": SOL_PAY_TO, "maxAmountRequired": "8000"}


def test_solana_sanity_checks():
    requirements = _solana_requirements()
    assert x402_mod.check_solana_payment_sanity(_solana_payload(), requirements) is None

    missing_tx = _solana_payload()
    missing_tx["payload"] = {}
    assert x402_mod.check_solana_payment_sanity(missing_tx, requirements) == "missing transaction"

    # An EVM-shaped payload (signature + authorization) is not a Solana payment.
    evm_shaped = _solana_payload()
    evm_shaped["payload"] = {"signature": "0xabc", "authorization": {"value": "8000"}}
    assert x402_mod.check_solana_payment_sanity(evm_shaped, requirements) == "missing transaction"

    bad_b64 = _solana_payload()
    bad_b64["payload"] = {"transaction": "!!! not base64 !!!"}
    assert (
        x402_mod.check_solana_payment_sanity(bad_b64, requirements)
        == "invalid transaction encoding"
    )

    empty_tx = _solana_payload()
    empty_tx["payload"] = {"transaction": "   "}
    assert x402_mod.check_solana_payment_sanity(empty_tx, requirements) == "missing transaction"

    wrong_network = _solana_payload(network="base")
    assert x402_mod.check_solana_payment_sanity(wrong_network, requirements) == "bad network"


def test_unknown_network_rejected(monkeypatch, tmp_path):
    _enable_multi(monkeypatch)
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "sub.db"))
    _fake_solana_facilitator(monkeypatch)
    xc = TestClient(create_app())
    payload = _solana_payload(network="bitcoin")
    resp = xc.post("/convert/pdf", files=_pdf_files(), headers=_header(payload))
    assert resp.status_code == 402
    body = resp.json()
    # Doc-convert contract: sanity failures are payment_required + reason.
    assert body["error"] == "payment_required"
    assert body["reason"] == "unsupported network"


# ------------------------------------------------- §4c.3 replay


def test_solana_replay(monkeypatch, tmp_path):
    _enable_multi(monkeypatch)
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "sub.db"))
    _fake_solana_facilitator(monkeypatch)
    xc = TestClient(create_app())
    headers = _header(_solana_payload(tx=b"\x07\x08\x09" + secrets.token_bytes(8)))

    first = xc.post("/convert/pdf", files=_pdf_files(), headers=headers)
    assert first.status_code == 200
    second = xc.post("/convert/pdf", files=_pdf_files(), headers=headers)
    assert second.status_code == 402
    assert second.json()["error"] == "duplicate_payment"


# ------------------------------------------------- §4c.4 facilitator flow


def test_solana_facilitator_flow(monkeypatch, tmp_path):
    _enable_multi(monkeypatch)
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "sub.db"))
    fake = _fake_solana_facilitator(monkeypatch)
    xc = TestClient(create_app())
    payload = _solana_payload()
    resp = xc.post("/convert/pdf", files=_pdf_files(), headers=_header(payload))
    assert resp.status_code == 200

    assert len(fake.verify_calls) == 1 and len(fake.settle_calls) == 1
    sent_payload, sent_requirements = fake.verify_calls[0]
    assert sent_payload == payload
    assert sent_requirements["network"] == "solana"
    assert sent_requirements["payTo"] == SOL_PAY_TO
    assert fake.settle_calls[0][1]["network"] == "solana"


def test_solana_facilitator_down_fails_closed(monkeypatch, tmp_path):
    _enable_multi(monkeypatch)
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "sub.db"))
    _fake_solana_facilitator(monkeypatch, unreachable=True)
    xc = TestClient(create_app())
    resp = xc.post("/convert/pdf", files=_pdf_files(), headers=_header(_solana_payload()))
    assert resp.status_code == 503
    assert resp.json()["error"] == "payment_verification_unavailable"


def test_facilitator_client_routes_solana_to_solana_url(monkeypatch):
    """The real client posts the v1 envelope to the SOLANA facilitator URL
    when the requirements are for the Solana leg (§4b.4)."""
    _enable_multi(
        monkeypatch,
        X402_FACILITATOR_URL_SOLANA="https://solana-fac.test/facilitator",
    )
    captured = {}

    class FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"isValid": True, "payer": "payer"}

    class FakeHttpClient:
        async def post(self, url, json=None, headers=None):
            captured["url"] = url
            captured["json"] = json
            return FakeResp()

        async def aclose(self):
            pass

    client = x402_mod.FacilitatorClient(http_client=FakeHttpClient())
    requirements = {"network": "solana", "payTo": SOL_PAY_TO}
    payload = _solana_payload()
    result = asyncio.run(client.verify(payload, requirements))
    assert result["isValid"] is True
    assert captured["url"] == "https://solana-fac.test/facilitator/verify"
    assert captured["json"] == {
        "x402Version": 1,
        "paymentPayload": payload,
        "paymentRequirements": requirements,
    }
    # And the Base leg still routes to the shared facilitator.
    captured.clear()
    asyncio.run(client.verify(payload, {"network": "base", "payTo": BASE_PAY_TO}))
    assert captured["url"] == "https://x402.test/facilitator/verify"


# ------------------------------------------------- §4c.5 misconfigured leg


def test_solana_leg_dropped_when_misconfigured(monkeypatch, tmp_path, caplog):
    _enable_multi(monkeypatch)
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "sub.db"))
    monkeypatch.delenv("X402_PAY_TO_SOLANA")
    xc = TestClient(create_app())
    with caplog.at_level(logging.ERROR):
        resp = xc.post("/convert/pdf", files=_pdf_files())
    assert resp.status_code == 402
    body = resp.json()
    # Base keeps serving with the original single-network shape.
    assert isinstance(body["accepts"], dict)
    assert body["accepts"]["network"] == "base"
    assert body["paymentRequirements"]["network"] == "base"
    assert any(
        "solana" in record.message and "X402_PAY_TO_SOLANA" in record.message
        for record in caplog.records
        if record.levelno >= logging.ERROR
    )


# ------------------------------------------------- §4c.6 discovery manifest


def test_discovery_manifest_multi_network(monkeypatch, tmp_path):
    _enable_multi(monkeypatch)
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "sub.db"))
    xc = TestClient(create_app())
    manifest = xc.get("/.well-known/x402.json").json()
    networks = {entry["network"]: entry for entry in manifest["networks"]}
    assert set(networks) == {"base", "solana"}
    assert networks["solana"]["asset_contract"] == x402_mod.USDC_SOLANA_MINT
    assert networks["solana"]["pay_to"] == SOL_PAY_TO
    assert networks["base"]["asset_contract"] == x402_mod.USDC_BASE_ADDRESS
    assert networks["base"]["pay_to"] == BASE_PAY_TO
    # Top-level fields still describe the primary (Base) leg.
    assert manifest["payment"]["network"] == "base"
    assert manifest["payment"]["pay_to"] == BASE_PAY_TO


def test_discovery_manifest_default_lists_base_only(monkeypatch, tmp_path):
    monkeypatch.delenv("X402_NETWORKS", raising=False)
    monkeypatch.delenv("X402_PAY_TO", raising=False)
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "sub.db"))
    xc = TestClient(create_app())
    manifest = xc.get("/.well-known/x402.json").json()
    assert [entry["network"] for entry in manifest["networks"]] == ["base"]
    assert manifest["networks"][0]["pay_to"] is None


# ------------------------------------------------- fee payer discovery (§3b)


def test_fee_payer_discovery_from_supported(monkeypatch):
    _enable_multi(monkeypatch)
    monkeypatch.delenv("X402_SOLANA_FEE_PAYER")
    monkeypatch.setattr(x402_mod, "resolve_solana_fee_payer", _REAL_RESOLVE)

    class FakeResp:
        def json(self):
            return {
                "kinds": [
                    {"scheme": "exact", "network": "base", "extra": {}},
                    {"scheme": "exact", "network": "solana", "extra": {"feePayer": FEE_PAYER}},
                ]
            }

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url, headers=None):
            assert url == "https://x402.test/facilitator/supported"
            return FakeResp()

    monkeypatch.setattr(x402_mod.httpx, "AsyncClient", FakeClient)
    assert asyncio.run(x402_mod.resolve_solana_fee_payer()) == FEE_PAYER
    assert x402_mod.solana_fee_payer() == FEE_PAYER
    # With the fee payer resolved, the Solana leg becomes servable.
    configs = x402_mod.network_configs()
    assert configs["solana"]["extra"] == {"feePayer": FEE_PAYER}


def test_solana_leg_dropped_when_fee_payer_unresolved(monkeypatch):
    _enable_multi(monkeypatch)
    monkeypatch.delenv("X402_SOLANA_FEE_PAYER")
    # Discovery stub (autouse) resolves nothing -> leg must drop out.
    configs = x402_mod.network_configs()
    assert set(configs) == {"base"}
