"""Tier 1 deferral tests (Card 56): XRP / XLM / HBAR / ALGO must NOT be servable.

Verified research (2026-10-27): the configured Coinbase CDP facilitator
supports mainnets Base, Polygon, Arbitrum, Monad, World, and Solana only,
so no Tier 1 settlement leg may be built or advertised. These tests pin
the deferral in code: requesting the Tier 1 names in X402_NETWORKS must
not create an accepts entry, a discovery-manifest entry, or a servable
leg, and a payment payload naming a Tier 1 network must be rejected via
the existing unsupported-network path without ever reaching verify/settle.

All addresses and values here are SYNTHETIC test values only. No
production code is touched by this file; the deferral holds because the
existing fail-closed path already drops unknown network names (see
``leg_config_problems`` / ``valid_networks`` in x402.py).

Doc-convert contract notes (same as test_x402_solana.py):
- ``decode_x_payment`` returns None on malformed input; the middleware
  re-issues the 402.
- Sanity failures surface as ``payment_required`` with a reason;
  facilitator rejections are the ``payment_invalid`` ones.
"""

from __future__ import annotations

import base64
import json
import logging

import pytest
from fastapi.testclient import TestClient

from doc_convert_mcp import x402 as x402_mod
from doc_convert_mcp.rest_app import create_app
from tests.test_converters import make_pdf_bytes  # noqa: F401

# Synthetic values for tests only — never real addresses.
SOL_PAY_TO = "So1anaPayToTest1111111111111111111111111111"
FEE_PAYER = "FeePayerTestSo1ana111111111111111111111111"
BASE_PAY_TO = "0x000000000000000000000000000000000000dEaD"
TIER1_NETWORKS = ["xrp", "xlm", "hbar", "algo"]

# Hypothetical Tier 1 pay-to values. No code reads these env vars; they
# exist only to prove that setting them creates no leg.
TIER1_PAY_TO_ENV = {
    "X402_PAY_TO_XRP": "SYNTHETIC_TEST_XRP_PAYTO_0001",
    "X402_PAY_TO_XLM": "SYNTHETIC_TEST_XLM_PAYTO_0001",
    "X402_PAY_TO_HBAR": "SYNTHETIC_TEST_HBAR_PAYTO_0001",
    "X402_PAY_TO_ALGO": "SYNTHETIC_TEST_ALGO_PAYTO_0001",
}


@pytest.fixture(autouse=True)
def _isolated_billing_db(monkeypatch, tmp_path):
    """M-1: the replay table is persistent — point every test at a scratch DB."""
    monkeypatch.setenv("BILLING_DB_PATH", str(tmp_path / "billing.db"))


@pytest.fixture(autouse=True)
def _no_network_discovery(monkeypatch):
    """Keep the suite hermetic: fee-payer discovery is stubbed to 'no
    resolution' unless a test re-enables it, and the discovered-value
    cache never leaks between tests."""

    async def _stub_resolve():
        return None

    monkeypatch.setattr(x402_mod, "resolve_solana_fee_payer", _stub_resolve)
    monkeypatch.setattr(x402_mod, "_solana_fee_payer_cache", None)


def _enable_tier1_env(monkeypatch, **over):
    env = {
        "X402_ENABLED": "true",
        "X402_PAY_TO": BASE_PAY_TO,
        "X402_FACILITATOR_URL": "https://x402.test/facilitator",
        "X402_NETWORKS": "base,solana,xrp,xlm,hbar,algo",
        "X402_PAY_TO_SOLANA": SOL_PAY_TO,
        "X402_SOLANA_FEE_PAYER": FEE_PAYER,
        "FREE_TIER_ENABLED": "false",
    }
    env.update(TIER1_PAY_TO_ENV)
    env.update(over)
    for k, v in env.items():
        monkeypatch.setenv(k, v)


def _pdf_files():
    return {"file": ("t.pdf", make_pdf_bytes("Hi"), "application/pdf")}


def _header(payload_dict):
    raw = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).decode().rstrip("=")
    return {"X-Payment": raw}


def _tier1_payload(network):
    return {
        "x402Version": 1,
        "scheme": "exact",
        "network": network,
        "payload": {"transaction": "synthetic-test-payload"},
    }


class _FakeFacilitator:
    """Records verify/settle calls; must stay at zero for Tier 1 payloads."""

    def __init__(self):
        self.verify_calls = []
        self.settle_calls = []

    async def verify(self, payment_payload, payment_requirements):
        self.verify_calls.append((payment_payload, payment_requirements))
        return {"isValid": True, "invalidReason": None}

    async def settle(self, payment_payload, payment_requirements):
        self.settle_calls.append((payment_payload, payment_requirements))
        return {"success": True, "transaction": "SyntheticSettleSig111", "network": "base"}


# ------------------------------------------------- Tier 1 names are dropped


def test_tier1_names_produce_no_accepts_entry(monkeypatch):
    _enable_tier1_env(monkeypatch)
    # The names are still *requested* — the drop happens at leg validation.
    assert x402_mod.requested_networks() == ["base", "solana", "xrp", "xlm", "hbar", "algo"]
    assert x402_mod.valid_networks() == ["base", "solana"]
    assert set(x402_mod.network_configs()) == {"base", "solana"}

    xc = TestClient(create_app())
    body = xc.post("/convert/pdf", files=_pdf_files()).json()

    accepts = body["accepts"]
    assert isinstance(accepts, list) and len(accepts) == 2
    assert {entry["network"] for entry in accepts} == {"base", "solana"}
    requirements = body["paymentRequirements"]
    assert isinstance(requirements, list) and len(requirements) == 2
    assert {entry["network"] for entry in requirements} == {"base", "solana"}
    for tier1 in TIER1_NETWORKS:
        assert tier1 not in json.dumps(body)


def test_tier1_names_dropped_with_error_log(monkeypatch, caplog):
    _enable_tier1_env(monkeypatch)
    xc = TestClient(create_app())
    with caplog.at_level(logging.ERROR):
        resp = xc.post("/convert/pdf", files=_pdf_files())
    assert resp.status_code == 402
    for tier1 in TIER1_NETWORKS:
        assert any(
            tier1 in record.message and "unknown x402 network" in record.message
            for record in caplog.records
            if record.levelno >= logging.ERROR
        )


@pytest.mark.parametrize("network", TIER1_NETWORKS)
def test_tier1_leg_config_problems_unknown_network(network):
    problems = x402_mod.leg_config_problems(network)
    assert problems == [f"unknown x402 network {network!r} in X402_NETWORKS"]


def test_discovery_manifest_contains_no_tier1(monkeypatch):
    _enable_tier1_env(monkeypatch)
    xc = TestClient(create_app())
    manifest = xc.get("/.well-known/x402.json").json()
    networks = {entry["network"]: entry for entry in manifest["networks"]}
    assert set(networks) == {"base", "solana"}
    assert networks["solana"]["pay_to"] == SOL_PAY_TO
    assert networks["base"]["pay_to"] == BASE_PAY_TO
    for tier1 in TIER1_NETWORKS:
        assert tier1 not in json.dumps(manifest)


# ------------------------------------------------- Tier 1 payloads rejected


@pytest.mark.parametrize("network", TIER1_NETWORKS)
def test_tier1_payment_payload_rejected_unsupported_network(monkeypatch, network):
    _enable_tier1_env(monkeypatch)
    fake = _FakeFacilitator()
    monkeypatch.setattr(x402_mod, "get_facilitator_client", lambda: fake)
    xc = TestClient(create_app())
    resp = xc.post("/convert/pdf", files=_pdf_files(), headers=_header(_tier1_payload(network)))
    assert resp.status_code == 402
    body = resp.json()
    # Doc-convert contract: sanity failures are payment_required + reason.
    assert body["error"] == "payment_required"
    assert body["reason"] == "unsupported network"
    # Rejected before verification: nothing was verified or settled.
    assert fake.verify_calls == []
    assert fake.settle_calls == []


# ------------------------------------------------- Default behavior unchanged


def test_default_base_only_behaviour_unchanged(monkeypatch):
    monkeypatch.setenv("X402_ENABLED", "true")
    monkeypatch.setenv("X402_PAY_TO", BASE_PAY_TO)
    monkeypatch.setenv("X402_FACILITATOR_URL", "https://x402.test/facilitator")
    monkeypatch.setenv("FREE_TIER_ENABLED", "false")
    monkeypatch.delenv("X402_NETWORKS", raising=False)
    monkeypatch.delenv("X402_PAY_TO_SOLANA", raising=False)
    monkeypatch.delenv("X402_SOLANA_FEE_PAYER", raising=False)
    for var in TIER1_PAY_TO_ENV:
        monkeypatch.delenv(var, raising=False)

    assert x402_mod.requested_networks() == ["base"]
    assert set(x402_mod.network_configs()) == {"base"}

    xc = TestClient(create_app())
    body = xc.post("/convert/pdf", files=_pdf_files()).json()
    # Single-network challenge shape, exactly as before.
    assert isinstance(body["accepts"], dict)
    assert body["accepts"]["network"] == "base"
    assert isinstance(body["paymentRequirements"], dict)
    assert body["paymentRequirements"]["network"] == "base"

    manifest = xc.get("/.well-known/x402.json").json()
    assert [entry["network"] for entry in manifest["networks"]] == ["base"]
    assert manifest["networks"][0]["pay_to"] == BASE_PAY_TO


def test_hypothetical_tier1_payto_env_creates_no_leg(monkeypatch):
    """Tier 1 pay-to env vars are inert: even as the only extra names
    beside Base, they produce no leg and the challenge collapses to the
    single-network Base shape."""
    _enable_tier1_env(monkeypatch, X402_NETWORKS="base,xrp,xlm,hbar,algo")
    assert set(x402_mod.network_configs()) == {"base"}

    xc = TestClient(create_app())
    body = xc.post("/convert/pdf", files=_pdf_files()).json()
    assert isinstance(body["accepts"], dict)
    assert body["accepts"]["network"] == "base"
    assert isinstance(body["paymentRequirements"], dict)
    assert body["paymentRequirements"]["network"] == "base"
    for tier1 in TIER1_NETWORKS:
        assert tier1 not in json.dumps(body)

    manifest = xc.get("/.well-known/x402.json").json()
    assert [entry["network"] for entry in manifest["networks"]] == ["base"]
