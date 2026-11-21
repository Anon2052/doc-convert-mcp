"""x402 (USDC on Base; opt-in Solana leg) metering middleware.

Real facilitator-backed verification of EIP-3009 USDC authorizations.

Flow per paid request (when effectively enabled, see ``x402_effective_enabled``):

1. Resolve the price for the request (per-tool pricing, §5 of the payments spec).
2. Missing/invalid ``X-Payment`` header -> 402 challenge carrying the
   ``paymentRequirements`` object so real x402 clients can pay.
3. Base64-decode the v1 payment payload and run local sanity checks.
4. Anti-replay: reject already-seen authorization signatures.
5. ``POST {facilitator}/verify`` -> ``isValid`` must be true.
6. Serve the request.
7. ``POST {facilitator}/settle`` -> log the transaction hash. Settle failures
   are logged loudly but never fail the already-served request.

Fail-closed everywhere: facilitator unreachable -> 503, never serve paid
content without verification. Payments are OFF by default.

Free tier: before the step-2 challenge, anonymous callers (no subscriber
key, no X-Payment) draw from a monthly free credit bucket keyed by
client IP (``FREE_MONTHLY_CREDITS``, default 50 — Scott's call, aligned
across all three connectors 2026-10-21; kill switch
``FREE_TIER_ENABLED``). Same credit math as subscribers
(``credits_for_price`` on the single per-tool price map). Exhaustion ->
HTTP 402 ``free_tier_exhausted`` — 429 stays exclusive to the subscriber
cap. See ``billing.record_free_tier_usage``.
"""

from __future__ import annotations

import base64
import binascii
import copy
import ipaddress
import json
import logging
import os
import re
import secrets
import threading
import time
import urllib.parse
from decimal import Decimal, InvalidOperation

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .billing import (
    claim_x402_signature,
    free_tier_enabled,
    record_free_tier_usage,
    record_subscriber_credits,
    stripe_effective_enabled,
    subscriber_key_valid,
)

log = logging.getLogger("doc_convert_mcp.x402")

# --- x402 v1 "exact" scheme constants ---------------------------------------
X402_VERSION = 1
SCHEME = "exact"
NETWORK = "base"
#: Circle's canonical USDC contract on Base (6 decimals).
USDC_BASE_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
#: Backwards-compat alias (pre-normalization name).
USDC_BASE_CONTRACT = USDC_BASE_ADDRESS
USDC_DECIMALS = 6
MAX_TIMEOUT_SECONDS = 300
FACILITATOR_TIMEOUT_SECONDS = 15.0
#: Backwards-compat alias (pre-normalization name).
FACILITATOR_TIMEOUT = FACILITATOR_TIMEOUT_SECONDS
#: Default facilitator. Base Sepolia (testnet) ONLY — not mainnet.
#: For Base mainnet Scott must set X402_FACILITATOR_URL to the Coinbase CDP
#: facilitator (https://api.cdp.coinbase.com/platform/v2/x402) with CDP creds.
DEFAULT_FACILITATOR_URL = "https://x402.org/facilitator"
CDP_FACILITATOR_URL = "https://api.cdp.coinbase.com/platform/v2/x402"

# Solana leg (opt-in via X402_NETWORKS). SOLANA_NETWORK is the x402 v1
# plain network name (SOLANA_PORT_PLAN §2); the CAIP-2 form
# (solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp) is a v2 identifier. Plan open
# question 1 — confirm the exact string against CDP /supported — stays
# open until the devnet round-trip (§4d); "solana" is the plan default.
SOLANA_NETWORK = "solana"
# Circle's canonical USDC SPL mint on Solana mainnet (6 decimals).
USDC_SOLANA_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
KNOWN_NETWORKS = (NETWORK, SOLANA_NETWORK)

# Paths that never require payment (health checks, docs, billing endpoints,
# legal documents).
EXEMPT_PREFIXES = (
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon.ico",
    "/billing",
    "/legal",
    "/support",
    "/demo-walkthrough.mp4",
    "/.well-known",
)

# JSON-RPC methods that are discovery, not paid tool calls.
DISCOVERY_METHODS = frozenset(
    {
        "initialize",
        "tools/list",
        "prompts/list",
        "resources/list",
        "resources/templates/list",
        "ping",
    }
)

# --- Pricing ----------------------------------------------------------------
#: Fallback price for any paid call without a per-tool default.
DEFAULT_PRICE_USDC = Decimal("0.008")
#: Per-tool price defaults, in USDC. Pricing is a business decision — Scott
#: adjusts these before enabling payments (env overrides, see below).
TOOL_PRICES_USDC: dict[str, Decimal] = {
    "pdf_to_markdown": Decimal("0.008"),
    "ocr_image": Decimal("0.008"),
    "parse_spreadsheet": Decimal("0.008"),
    "url_to_clean_text": Decimal("0.008"),
}
# Always-paid route prefix (2026-10-24 paid-route batch): POSTs under this
# prefix NEVER draw from the monthly free-credit bucket — without a valid
# X-Payment they fall through to the 402 challenge. Directory checkers
# (PayAPI preflight) and router dispatch (Agent402) must see a 402 to
# price a route, and the free tier answers them 200 instead. Normal
# routes keep the free tier unchanged; only /paid/* aliases skip it.
PAID_ROUTE_PREFIX = "/paid/"

#: REST route -> tool price mapping.
REST_TOOL_PRICES: dict[str, str] = {
    "/convert/pdf": "pdf_to_markdown",
    "/convert/ocr": "ocr_image",
    "/convert/spreadsheet": "parse_spreadsheet",
    "/convert/url": "url_to_clean_text",
    # Always-paid alias: same tool as /convert/pdf, never free-tiered.
    "/paid/convert/pdf": "pdf_to_markdown",
}


def _env_flag(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def x402_pay_to() -> str:
    return os.environ.get("X402_PAY_TO", "").strip()


def x402_pay_to_solana() -> str:
    return os.environ.get("X402_PAY_TO_SOLANA", "").strip()


def facilitator_url() -> str:
    return os.environ.get("X402_FACILITATOR_URL", DEFAULT_FACILITATOR_URL).strip()


#: Backwards-compat alias (pre-normalization name).
def x402_facilitator_url() -> str:
    return facilitator_url()


def solana_facilitator_url() -> str:
    """Facilitator for the Solana leg: dedicated override, else the shared one."""
    return os.environ.get("X402_FACILITATOR_URL_SOLANA", "").strip() or facilitator_url()


def x402_asset_solana() -> str:
    return os.environ.get("X402_ASSET_SOLANA", USDC_SOLANA_MINT).strip() or USDC_SOLANA_MINT


def requested_networks() -> list[str]:
    """Networks named by X402_NETWORKS. Unset = ["base"] (today's behavior)."""
    raw = os.environ.get("X402_NETWORKS", "").strip()
    if not raw:
        return [NETWORK]
    names = [part.strip().lower() for part in raw.split(",") if part.strip()]
    return names or [NETWORK]


# Cached facilitator Solana fee payer, filled lazily by
# resolve_solana_fee_payer() from GET {facilitator}/supported (plan §3b).
_solana_fee_payer_cache: str | None = None


def solana_fee_payer() -> str | None:
    """The facilitator's Solana fee-payer key: X402_SOLANA_FEE_PAYER env
    override, else the /supported-discovered value. None = unresolved."""
    override = os.environ.get("X402_SOLANA_FEE_PAYER", "").strip()
    if override:
        return override
    return _solana_fee_payer_cache


def x402_effective_enabled() -> bool:
    """True only when x402 is fully and VALIDLY configured. Fail closed otherwise."""
    if not _env_flag("X402_ENABLED"):
        return False
    problems = x402_config_problems()
    if problems:
        for problem in problems:
            log.error(
                "x402 misconfigured: %s — x402 DISABLED (fail closed).",
                problem,
            )
        return False
    return True


_PAY_TO_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BASE58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


def _https_url_problem(label: str, url: str) -> str | None:
    if not url:
        return f"{label} is empty"
    try:
        parts = urllib.parse.urlparse(url)
    except ValueError:
        parts = None
    if parts is None or parts.scheme != "https" or not parts.hostname:
        return (
            f"{label}={url!r} must be an https URL "
            "(http would leak facilitator credentials in cleartext)"
        )
    return None


def leg_config_problems(network: str) -> list[str]:
    """Config problems for ONE network leg. Empty list = leg is servable."""
    problems: list[str] = []
    if network == NETWORK:
        pay_to = x402_pay_to()
        if not pay_to:
            problems.append("X402_PAY_TO is empty")
        elif not _PAY_TO_RE.match(pay_to):
            problems.append(f"X402_PAY_TO={pay_to!r} is not a valid 0x Ethereum address")
        problem = _https_url_problem("X402_FACILITATOR_URL", facilitator_url())
        if problem:
            problems.append(problem)
    elif network == SOLANA_NETWORK:
        pay_to = x402_pay_to_solana()
        if not pay_to:
            problems.append("X402_PAY_TO_SOLANA is empty")
        elif not _BASE58_RE.match(pay_to):
            problems.append(f"X402_PAY_TO_SOLANA={pay_to!r} is not a valid base58 Solana address")
        override = os.environ.get("X402_FACILITATOR_URL_SOLANA", "").strip()
        if override:
            problem = _https_url_problem("X402_FACILITATOR_URL_SOLANA", override)
            if problem:
                problems.append(problem)
    else:
        problems.append(f"unknown x402 network {network!r} in X402_NETWORKS")
    return problems


def valid_networks() -> list[str]:
    """Requested networks whose leg config is complete.

    Per-leg fail-closed (plan §4b.5): a leg with incomplete config is
    dropped with an ERROR log; the remaining legs keep working.
    """
    valid: list[str] = []
    for name in requested_networks():
        problems = leg_config_problems(name)
        if problems:
            for problem in problems:
                log.error("x402 %s leg dropped: %s", name, problem)
        else:
            valid.append(name)
    return valid


def x402_config_problems() -> list[str]:
    """Fail-closed config validation (M-5). Empty list = safe to enable.

    A typo'd X402_PAY_TO would otherwise verify-and-settle real USDC to a
    dead address (service delivered, revenue burned, no error ever raised),
    and an http:// facilitator URL would send facilitator credentials in
    cleartext. Validation is per-leg: one bad leg disables x402 entirely
    only when NO valid leg remains (in which case every leg's problems are
    surfaced so the operator sees exactly what to fix).
    """
    problems: list[str] = []
    if not _env_flag("X402_ENABLED"):
        return problems  # disabled by flag: nothing to validate
    if not valid_networks():
        for name in requested_networks():
            problems.extend(leg_config_problems(name))
        if not problems:
            problems.append("no x402 network legs configured")
    return problems


def network_configs() -> dict[str, dict]:
    """Per-network config table for every currently servable leg (§4b.1)."""
    configs: dict[str, dict] = {}
    for name in valid_networks():
        if name == NETWORK:
            configs[name] = {
                "network_id": NETWORK,
                "asset": USDC_BASE_ADDRESS,
                "pay_to": x402_pay_to(),
                "decimals": USDC_DECIMALS,
                "extra": {"name": "USD Coin", "version": "2"},
            }
        elif name == SOLANA_NETWORK:
            fee_payer = solana_fee_payer()
            if not fee_payer:
                # §4b.5: without a fee payer the client cannot build the
                # transaction — the leg is unservable, drop it loudly.
                log.error(
                    "x402 solana leg dropped: fee payer unresolved (set "
                    "X402_SOLANA_FEE_PAYER or make the facilitator "
                    "/supported endpoint reachable)"
                )
                continue
            configs[name] = {
                "network_id": SOLANA_NETWORK,
                "asset": x402_asset_solana(),
                "pay_to": x402_pay_to_solana(),
                "decimals": USDC_DECIMALS,
                "extra": {"feePayer": fee_payer},
            }
    return configs


def _parse_price(raw: str | None, default: Decimal, label: str) -> Decimal:
    """Parse a USDC price env var; invalid/non-positive -> default (never zero)."""
    if raw is None:
        return default
    try:
        value = Decimal(raw.strip())
    except (InvalidOperation, AttributeError):
        log.warning("Invalid %s=%r; falling back to default %s USDC.", label, raw, default)
        return default
    if value <= 0:
        log.warning("Non-positive %s=%r; falling back to default %s USDC.", label, raw, default)
        return default
    return value


def x402_price_usdc() -> Decimal:
    """Generic default price for any paid call."""
    return _parse_price(os.environ.get("X402_PRICE_USDC"), DEFAULT_PRICE_USDC, "X402_PRICE_USDC")


def tool_price_usdc(tool_name: str | None) -> Decimal:
    """Resolve the USDC price for a tool (env override wins, else code default)."""
    default = TOOL_PRICES_USDC.get(tool_name or "", DEFAULT_PRICE_USDC)
    if tool_name:
        env_name = "X402_PRICE_" + re.sub(r"[^A-Z0-9]", "_", tool_name.upper()) + "_USDC"
        return _parse_price(os.environ.get(env_name), default, env_name)
    return x402_price_usdc()


def usdc_to_atomic_units(price: Decimal) -> int:
    return int((price * (10**USDC_DECIMALS)).to_integral_value(rounding="ROUND_DOWN"))


# --- Subscriber credits ------------------------------------------------------
#: 1 credit = $0.01 of x402 list price. The credit cost of a call derives
#: from the SAME per-tool price map the x402 middleware uses (see
#: ``tool_price_usdc`` / ``X402PaymentMiddleware._resolve_price``) — this is
#: the only place the conversion lives, never a duplicated price table.
def credits_for_price(price_usdc: Decimal) -> float:
    """Credit cost of one call at the given x402 list price.

    $0.03 -> 3.0, $0.02 -> 2.0, $0.01 -> 1.0, $0.015 (default) -> 1.5.
    """
    return round(float(price_usdc) / 0.01, 1)


# --- CDP JWT minting ----------------------------------------------------------
def _load_ed25519_private_key(secret: str):
    """Load an Ed25519 private key from PEM or a raw base64/hex seed."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    s = secret.strip()
    if "PRIVATE KEY" in s:
        key = serialization.load_pem_private_key(s.encode("utf-8"), password=None)
    else:
        raw = _decode_seed(s)
        if raw is None:
            raise ValueError("CDP_API_KEY_SECRET is not PEM, base64, or hex")
        if len(raw) == 64:
            raw = raw[:32]  # seed || pubkey form -> seed
        key = Ed25519PrivateKey.from_private_bytes(raw)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("CDP_API_KEY_SECRET is not an Ed25519 private key")
    return key


def _decode_seed(s: str) -> bytes | None:
    """Decode a raw Ed25519 seed, base64 (padded or not) or hex.

    Tries base64 first, but only accepts it when it yields a plausible seed
    length — a hex seed is also valid base64 alphabet and would otherwise
    mis-decode to the wrong length.
    """
    try:
        padded = s + "=" * (-len(s) % 4)
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        raw = b""
    if len(raw) not in (32, 64):
        try:
            raw = bytes.fromhex(s)
        except ValueError:
            return None
    return raw if len(raw) in (32, 64) else None


def mint_cdp_jwt(
    key_id: str, key_secret: str, now: int | None = None, uris: list[str] | None = None
) -> str:
    """Mint a CDP EdDSA JWT for facilitator auth.

    Claim set verified live against the CDP facilitator 2026-10-20: CDP
    requires the ``uris`` claim scoping the token to the exact endpoints
    (``POST <host><path>/verify`` etc.) — without it the API returns 401.
    ``now`` is injectable for tests (search-mcp convention); it defaults to
    the current time.
    """
    key = _load_ed25519_private_key(key_secret)
    now = now if now is not None else int(time.time())
    header = {"alg": "EdDSA", "typ": "JWT", "kid": key_id, "nonce": secrets.token_hex(16)}
    claims = {"sub": key_id, "iss": "coinbase-cloud", "nbf": now - 30, "exp": now + 120}
    if uris:
        claims["uris"] = list(uris)

    def b64u(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    signing_input = (
        b64u(json.dumps(header, separators=(",", ":")).encode("ascii"))
        + "."
        + b64u(json.dumps(claims, separators=(",", ":")).encode("ascii"))
    )
    signature = key.sign(signing_input.encode("ascii"))
    return signing_input + "." + b64u(signature)


# --- Facilitator client -------------------------------------------------------
def _facilitator_auth_headers(base_url: str) -> dict[str, str]:
    """Auth headers for a facilitator base URL (CDP JWTs are scoped via the
    ``uris`` claim to the exact base being called)."""
    api_key = os.environ.get("X402_FACILITATOR_API_KEY", "").strip()
    if api_key:
        return {"X-API-Key": api_key}
    key_id = os.environ.get("CDP_API_KEY_ID", "").strip()
    key_secret = os.environ.get("CDP_API_KEY_SECRET", "").strip()
    if key_id and key_secret:
        stripped = base_url.split("://", 1)[-1].rstrip("/")
        uris = [f"POST {stripped}/verify", f"POST {stripped}/settle"]
        return {"Authorization": "Bearer " + mint_cdp_jwt(key_id, key_secret, uris=uris)}
    return {}


async def resolve_solana_fee_payer() -> str | None:
    """Best-effort feePayer discovery from GET {facilitator}/supported (§3b).

    Cached on success. Any failure returns None (the Solana leg then drops
    with an ERROR log) — discovery must never crash a request.
    """
    global _solana_fee_payer_cache
    known = solana_fee_payer()
    if known:
        return known
    url = solana_facilitator_url().rstrip("/") + "/supported"
    try:
        async with httpx.AsyncClient(timeout=FACILITATOR_TIMEOUT_SECONDS) as client:
            headers = _facilitator_auth_headers(solana_facilitator_url())
            resp = await client.get(url, headers=headers)
        data = resp.json()
    except Exception:
        log.warning("x402 solana fee payer discovery failed: %s unreachable", url)
        return None
    kinds = data.get("kinds") if isinstance(data, dict) else None
    if isinstance(kinds, list):
        for kind in kinds:
            if not isinstance(kind, dict):
                continue
            if kind.get("scheme") != SCHEME:
                continue
            network = str(kind.get("network", ""))
            if not network.startswith(SOLANA_NETWORK):
                continue
            extra = kind.get("extra") or {}
            fee_payer = extra.get("feePayer")
            if isinstance(fee_payer, str) and fee_payer:
                _solana_fee_payer_cache = fee_payer
                return fee_payer
    log.warning("x402 facilitator /supported lists no Solana fee payer")
    return None


class FacilitatorClient:
    """Thin async client for the x402 facilitator HTTP API (v1 'exact' scheme)."""

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = FACILITATOR_TIMEOUT_SECONDS,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = (base_url or facilitator_url()).rstrip("/")
        self.timeout = timeout
        self._http_client = http_client
        self._owns_client = http_client is None

    def _auth_headers(self, base_url: str | None = None) -> dict[str, str]:
        return _facilitator_auth_headers(base_url or self.base_url)

    def _base_for(self, payment_requirements: dict | None) -> str:
        """Per-network facilitator routing (plan §4b.4): the Solana leg uses
        X402_FACILITATOR_URL_SOLANA when set, else the shared facilitator.
        Routing lives here (not in the factory) so the 0-arg
        ``get_facilitator_client()`` seam tests patch keeps working."""
        if (
            payment_requirements is not None
            and payment_requirements.get("network") == SOLANA_NETWORK
        ):
            return solana_facilitator_url().rstrip("/")
        return self.base_url

    async def _post(self, path: str, body: dict, payment_requirements: dict | None = None) -> dict:
        base = self._base_for(payment_requirements)
        client = self._http_client or httpx.AsyncClient(timeout=self.timeout)
        try:
            resp = await client.post(base + path, json=body, headers=self._auth_headers(base))
            resp.raise_for_status()
            data = resp.json()
            return data if isinstance(data, dict) else {}
        finally:
            if self._owns_client:
                await client.aclose()

    async def verify(self, payment_payload: dict, payment_requirements: dict) -> dict:
        return await self._post(
            "/verify",
            {
                "x402Version": X402_VERSION,
                "paymentPayload": payment_payload,
                "paymentRequirements": payment_requirements,
            },
            payment_requirements,
        )

    async def settle(self, payment_payload: dict, payment_requirements: dict) -> dict:
        return await self._post(
            "/settle",
            {
                "x402Version": X402_VERSION,
                "paymentPayload": payment_payload,
                "paymentRequirements": payment_requirements,
            },
            payment_requirements,
        )


def get_facilitator_client() -> FacilitatorClient:
    """Factory indirection so tests can inject a fake facilitator."""
    return FacilitatorClient()


# --- Discovery manifest (/.well-known/x402[.json]) -----------------------------

#: Human-readable per-tool descriptions for the discovery manifest, in the
#: sibling services' "<tool>: <summary>" style. Summaries mirror the MCP
#: tool docstrings in mcp_server.py.
TOOL_DESCRIPTIONS: dict[str, str] = {
    "pdf_to_markdown": "pdf_to_markdown: convert a PDF to Markdown, one section per page",
    "ocr_image": "ocr_image: run OCR on an image and return the recognized text",
    "parse_spreadsheet": (
        "parse_spreadsheet: parse a CSV or XLSX spreadsheet into Markdown tables"
    ),
    "url_to_clean_text": (
        "url_to_clean_text: fetch a URL and return its main text content as clean text"
    ),
}


def build_discovery_manifest() -> dict:
    """Public x402 discovery manifest.

    HONESTY CONTRACT (shared with the sibling services): x402 is
    implemented but DISABLED until the business entity / Stripe go-live,
    so this manifest NEVER claims payments are live. ``x402_status`` is
    ``"implemented_but_disabled"`` whenever ``x402_effective_enabled()``
    is False. Every price is derived from ``TOOL_PRICES_USDC`` via
    ``tool_price_usdc()`` — there is deliberately NO duplicated price
    table here. ``pay_to`` is the live ``X402_PAY_TO`` value or None
    (never an invented address).
    """
    live = x402_effective_enabled()
    tools: dict[str, dict] = {}
    for tool in TOOL_PRICES_USDC:
        rest_path = next((p for p, t in REST_TOOL_PRICES.items() if t == tool), None)
        tools[tool] = {
            "price_usdc": str(tool_price_usdc(tool)),
            "rest_path": rest_path,
            "description": TOOL_DESCRIPTIONS.get(tool, tool),
        }
    networks: list[dict] = []
    for name in requested_networks():
        if name == NETWORK:
            networks.append(
                {
                    "network": NETWORK,
                    "asset": "USDC",
                    "asset_contract": USDC_BASE_ADDRESS,
                    "asset_decimals": USDC_DECIMALS,
                    "pay_to": x402_pay_to() or None,
                }
            )
        elif name == SOLANA_NETWORK:
            networks.append(
                {
                    "network": SOLANA_NETWORK,
                    "asset": "USDC",
                    "asset_contract": x402_asset_solana(),
                    "asset_decimals": USDC_DECIMALS,
                    "pay_to": x402_pay_to_solana() or None,
                }
            )
    return {
        "x402_status": "accepting_payments" if live else "implemented_but_disabled",
        "status_note": (
            "x402 payments are enabled: per-call USDC micropayments on Base "
            "are verified against the configured facilitator."
            if live
            else "x402 payments go live after business entity setup; currently disabled."
        ),
        "service": "doc-convert-mcp",
        "version": X402_VERSION,
        "payment": {
            "scheme": SCHEME,
            "network": NETWORK,
            "asset": "USDC",
            "asset_address": USDC_BASE_ADDRESS,
            "asset_decimals": USDC_DECIMALS,
            "pay_to": x402_pay_to() or None,
        },
        "networks": networks,
        "tools": tools,
        "legal": {
            "terms": "/legal/terms",
            "privacy": "/legal/privacy",
            "refunds": "/legal/refunds",
        },
    }


# ---------------------------------------------------------------------------
# Bazaar discovery metadata (x402 v1 outputSchema + v2 extensions.bazaar).
# ---------------------------------------------------------------------------
# Two cataloging surfaces fed by the single set of tables below:
#
# * x402 v1 (the protocol these servers speak): the facilitator's bazaar
#   extractor reads discovery metadata from ``outputSchema`` INSIDE each
#   paymentRequirements object — ``input`` must carry ``type: "http"`` and
#   the HTTP ``method``; for body endpoints the example request body rides
#   in ``bodyFields`` (reference: x402 Python SDK, x402/extensions/bazaar —
#   "V1 Support" — and the v1 facilitator extractor contract).
# * x402 v2: the same metadata as a top-level ``extensions.bazaar`` block on
#   the 402 body, emitted in the facilitator-facing form the SDK's
#   ``declare_discovery_extension`` / ``declare_mcp_discovery_extension``
#   produce after resource-server enrichment (``info.input`` carries the
#   real method and validates against the sibling JSON Schema; reference:
#   the same SDK's resource_service.py / types.py, mirrored field-for-field
#   below).
#
# Purely additive: existing x402 clients ignore both keys, and no existing
# field changes value.

_BAZAAR_SCHEMA_URL = "https://json-schema.org/draft/2020-12/schema"

#: Per-tool discovery metadata for the MCP surface. ``input_schema`` mirrors
#: the FastMCP-generated argument schema of each tool in mcp_server.py;
#: ``output_schema`` / ``output_example`` describe the tool's return value.
_BAZAAR_TOOLS: dict[str, dict] = {
    "pdf_to_markdown": {
        "description": "Convert a PDF to Markdown, one section per page.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pdf_base64": {"type": "string"},
                "max_pages": {"type": "integer", "default": 100},
            },
            "required": ["pdf_base64"],
        },
        "example_args": {"pdf_base64": "JVBERi0xLjQK", "max_pages": 100},
        "output_schema": {"type": "string"},
        "output_example": "# Example document\n\nConverted markdown text.",
    },
    "ocr_image": {
        "description": "Run OCR on an image and return the recognized text.",
        "input_schema": {
            "type": "object",
            "properties": {
                "image_base64": {"type": "string"},
                "lang": {"type": "string", "default": "eng"},
            },
            "required": ["image_base64"],
        },
        "example_args": {"image_base64": "iVBORw0KGgo=", "lang": "eng"},
        "output_schema": {"type": "string"},
        "output_example": "Example OCR text.",
    },
    "parse_spreadsheet": {
        "description": "Parse a CSV or XLSX spreadsheet into Markdown tables.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_base64": {"type": "string"},
                "filename": {"type": "string"},
            },
            "required": ["file_base64", "filename"],
        },
        "example_args": {"file_base64": "Y29sMSxjb2wyCg==", "filename": "data.csv"},
        "output_schema": {"type": "string"},
        "output_example": "| col1 | col2 |\n| --- | --- |",
    },
    "url_to_clean_text": {
        "description": "Fetch a public http(s) URL and return its main text content as plain text.",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        "example_args": {"url": "https://example.com/article"},
        "output_schema": {"type": "string"},
        "output_example": "Example page text.",
    },
}

#: Per-route discovery metadata for the REST surface. The three conversion
#: routes take multipart file uploads (``file`` form field); /convert/url
#: takes a JSON body (the UrlRequest model in rest_app.py). Output shapes
#: mirror the route handlers' return values.
_BAZAAR_ROUTES: dict[str, dict] = {
    "/convert/pdf": {
        "tool": "pdf_to_markdown",
        "body_type": "form-data",
        "body_example": {"file": "example.pdf"},
        "body_schema": {
            "type": "object",
            "properties": {"file": {"type": "string", "format": "binary"}},
            "required": ["file"],
        },
        "output_schema": {
            "type": "object",
            "properties": {"markdown": {"type": "string"}},
            "required": ["markdown"],
        },
        "output_example": {"markdown": "# Example document\n\nConverted markdown text."},
    },
    "/convert/ocr": {
        "tool": "ocr_image",
        "body_type": "form-data",
        "body_example": {"file": "example.png"},
        "body_schema": {
            "type": "object",
            "properties": {"file": {"type": "string", "format": "binary"}},
            "required": ["file"],
        },
        "output_schema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
        "output_example": {"text": "Example OCR text."},
    },
    "/convert/spreadsheet": {
        "tool": "parse_spreadsheet",
        "body_type": "form-data",
        "body_example": {"file": "example.csv"},
        "body_schema": {
            "type": "object",
            "properties": {"file": {"type": "string", "format": "binary"}},
            "required": ["file"],
        },
        "output_schema": {
            "type": "object",
            "properties": {"markdown": {"type": "string"}},
            "required": ["markdown"],
        },
        "output_example": {"markdown": "| col1 | col2 |\n| --- | --- |"},
    },
    "/convert/url": {
        "tool": "url_to_clean_text",
        "body_type": "json",
        "body_example": {"url": "https://example.com/article"},
        "body_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        "output_schema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
        "output_example": {"text": "Example page text."},
    },
}


def _bazaar_target(resource: str, description: str) -> tuple[str, dict, str] | None:
    """Resolve a requirements resource to its bazaar metadata table entry.

    Returns ``(kind, meta, tool_name)`` — kind ``"rest"`` (meta from
    ``_BAZAAR_ROUTES``) or ``"mcp"`` (meta from ``_BAZAAR_TOOLS``) — or
    None when the resource is not a catalogable endpoint. The tool for a
    resource comes from the REST route map or from the requirements
    description (``_resolve_price`` embeds it as ``tool '<name>'`` for
    both REST and MCP calls).
    """
    path = urllib.parse.urlsplit(resource).path or resource
    route = _BAZAAR_ROUTES.get(path)
    if route is not None:
        return "rest", route, route["tool"]
    match = re.search(r"tool '([a-z0-9_]+)'", description)
    if match and match.group(1) in _BAZAAR_TOOLS:
        return "mcp", _BAZAAR_TOOLS[match.group(1)], match.group(1)
    return None


def _bazaar_output_schema(resource: str, description: str) -> dict | None:
    """x402 v1 ``outputSchema`` for one resource (None = not catalogable).

    For MCP tools/call resources the endpoint is HTTP, so the input is the
    http form whose ``bodyFields`` carry the JSON-RPC envelope example —
    exactly what the v1 bazaar extractor turns into a catalog entry.
    """
    target = _bazaar_target(resource, description)
    if target is None:
        return None
    kind, meta, name = target
    if kind == "rest":
        body: dict = copy.deepcopy(meta["body_example"])
    else:
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": copy.deepcopy(meta["example_args"])},
        }
    return {
        "input": {
            "type": "http",
            "method": "POST",
            "discoverable": True,
            "bodyType": meta.get("body_type", "json"),
            "bodyFields": body,
        },
        "output": copy.deepcopy(meta["output_schema"]),
    }


def _bazaar_extension(resource: str, description: str) -> dict | None:
    """x402 v2 ``extensions.bazaar`` block for one resource (None = skip).

    Mirrors the x402 SDK's declare functions' output in its served
    (post-enrichment) state: ``info.input`` carries the real HTTP method /
    tool name and validates against the sibling ``schema``.
    """
    target = _bazaar_target(resource, description)
    if target is None:
        return None
    kind, meta, name = target
    if kind == "rest":
        info_input: dict = {
            "type": "http",
            "method": "POST",
            "bodyType": meta["body_type"],
            "body": copy.deepcopy(meta["body_example"]),
        }
        input_schema_block: dict = {
            "type": "object",
            "properties": {
                "type": {"type": "string", "const": "http"},
                "method": {"type": "string", "enum": ["POST", "PUT", "PATCH"]},
                "bodyType": {"type": "string", "enum": ["json", "form-data", "text"]},
                "body": copy.deepcopy(meta["body_schema"]),
            },
            "required": ["type", "method", "bodyType", "body"],
            "additionalProperties": False,
        }
        output_example_schema: dict = {"type": "object"}
    else:
        info_input = {
            "type": "mcp",
            "toolName": name,
            "description": meta["description"],
            "transport": "streamable-http",
            "inputSchema": copy.deepcopy(meta["input_schema"]),
            "example": copy.deepcopy(meta["example_args"]),
        }
        input_schema_block = {
            "type": "object",
            "properties": {
                "type": {"type": "string", "const": "mcp"},
                "toolName": {"type": "string"},
                "inputSchema": {"type": "object"},
                "description": {"type": "string"},
                "transport": {"type": "string", "enum": ["streamable-http", "sse"]},
                "example": {"type": "object"},
            },
            "required": ["type", "toolName", "inputSchema"],
            "additionalProperties": False,
        }
        output_example_schema = {}
    return {
        "info": {
            "input": info_input,
            "output": {"type": "json", "example": copy.deepcopy(meta["output_example"])},
        },
        "schema": {
            "$schema": _BAZAAR_SCHEMA_URL,
            "type": "object",
            "properties": {
                "input": input_schema_block,
                "output": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string"},
                        "example": output_example_schema,
                    },
                    "required": ["type"],
                },
            },
            "required": ["input"],
        },
    }


def _bazaar_extension_for_requirements(requirements: dict) -> dict | None:
    """``extensions.bazaar`` for a challenge built from these requirements.

    Derived from the requirements' own resource + description, so every
    challenge variant (payment_required / payment_invalid /
    free_tier_exhausted) is covered without threading new parameters
    through the response helpers.
    """
    return _bazaar_extension(
        requirements.get("resource", ""),
        requirements.get("description", ""),
    )


# --- Payment payload handling -------------------------------------------------
def _requirements_for_config(config: dict, price: Decimal, resource: str, description: str) -> dict:
    requirements = {
        "x402Version": X402_VERSION,
        "scheme": SCHEME,
        "network": config["network_id"],
        "maxAmountRequired": str(usdc_to_atomic_units(price)),
        "resource": resource,
        "description": description,
        "payTo": config["pay_to"],
        "maxTimeoutSeconds": MAX_TIMEOUT_SECONDS,
        "asset": config["asset"],
        # CDP facilitator schema-validates v1 requirements: mimeType is
        # REQUIRED (400 without it, verified live 2026-10-20); extra carries
        # the USDC EIP-712 domain on Base / the fee payer on Solana.
        "mimeType": "application/json",
        "extra": dict(config["extra"]),
    }
    # Bazaar discovery metadata (additive; see the bazaar block above).
    output_schema = _bazaar_output_schema(resource, description)
    if output_schema is not None:
        requirements["outputSchema"] = output_schema
    return requirements


def _base_config() -> dict:
    """The Base leg's config, built from env whether or not it is servable."""
    return {
        "network_id": NETWORK,
        "asset": USDC_BASE_ADDRESS,
        "pay_to": x402_pay_to(),
        "decimals": USDC_DECIMALS,
        "extra": {"name": "USD Coin", "version": "2"},
    }


def build_payment_requirements(price: Decimal, resource: str, description: str) -> dict:
    """Server-side payment requirements for the x402 v1 exact scheme (Base leg)."""
    return _requirements_for_config(_base_config(), price, resource, description)


def build_requirements_list(price: Decimal, resource: str, description: str) -> list[dict]:
    """One requirements entry per servable network leg (plan §4b.2)."""
    return [
        _requirements_for_config(config, price, resource, description)
        for config in network_configs().values()
    ]


# ---------------------------------------------------------------------------
# Canonical 402 challenge body.
# ---------------------------------------------------------------------------
# This exact shape is shared by all IOConnex MCP servers (search-mcp,
# doc-convert-mcp, price-tracker-mcp): the same ``error`` codes, the same
# ``accepts`` fields, and ``reason`` on every payment rejection. ``accepts``
# is derived from the x402 ``paymentRequirements`` so the two can never drift
# apart. Only OUR extension fields are normalized here — the
# ``paymentRequirements`` object itself stays x402-protocol-compliant.

CHALLENGE_MESSAGE = (
    "This endpoint requires an x402 USDC micropayment on Base. "
    "Send an X-Payment header with a base64-encoded signed EIP-3009 "
    "authorization (x402 v1 'exact' scheme)."
)

CHALLENGE_MESSAGE_MULTI = (
    "This endpoint requires an x402 USDC micropayment (Base or Solana). "
    "Send an X-Payment header with a base64-encoded x402 v1 'exact' "
    "scheme payment for one of the accepted networks."
)

FACILITATOR_DOWN_MESSAGE = "Payment verification is temporarily unavailable; try again."


def _accepts_entry(requirements: dict) -> dict:
    amount_atomic = int(requirements["maxAmountRequired"])
    return {
        "asset": "USDC",
        "asset_contract": requirements["asset"],
        "network": requirements["network"],
        "amount_usdc": str(Decimal(amount_atomic) / 10**USDC_DECIMALS),
        "amount_atomic": str(amount_atomic),
        "pay_to": requirements["payTo"],
        "scheme": requirements["scheme"],
    }


def challenge_content(
    error: str,
    requirements: dict | list[dict],
    reason: str | None = None,
    message: str | None = None,
) -> dict:
    """Build the canonical 402 body for an x402 payment rejection.

    ``error`` is one of ``payment_required`` / ``payment_invalid`` /
    ``duplicate_payment`` (or a repo-specific 402 code like
    ``free_tier_exhausted``). ``reason`` carries the human/machine-readable
    detail when known; ``message`` overrides the default challenge text when
    the caller has something more specific to say.

    ``requirements`` is a single requirements dict (the original shape,
    unchanged) or a list of per-network dicts. A one-entry list collapses
    to the single shape; with more than one network, ``accepts`` becomes
    an ARRAY of per-network options and ``paymentRequirements`` the
    matching array (plan §4b.3).
    """
    if isinstance(requirements, list):
        if len(requirements) == 1:
            requirements = requirements[0]
        else:
            content_multi: dict = {
                "error": error,
                "message": message or CHALLENGE_MESSAGE_MULTI,
                "accepts": [_accepts_entry(entry) for entry in requirements],
                # Real x402 clients need this to build a valid payment.
                "paymentRequirements": requirements,
            }
            # Bazaar discovery metadata (additive; one block describes the
            # resource — identical across network legs).
            extension_multi = _bazaar_extension_for_requirements(requirements[0])
            if extension_multi is not None:
                content_multi["extensions"] = {"bazaar": extension_multi}
            if reason:
                content_multi["reason"] = reason
            return content_multi
    content: dict = {
        "error": error,
        "message": message or CHALLENGE_MESSAGE,
        "accepts": _accepts_entry(requirements),
        # Real x402 clients need this to build a valid payment.
        "paymentRequirements": requirements,
    }
    # Bazaar discovery metadata (additive; see the bazaar block above).
    extension = _bazaar_extension_for_requirements(requirements)
    if extension is not None:
        content["extensions"] = {"bazaar": extension}
    if reason:
        content["reason"] = reason
    return content


def payment_required_response(
    *,
    price: Decimal | None = None,
    resource: str | None = None,
    description: str | None = None,
    error: str = "payment_required",
    reason: str | None = None,
    requirements: dict | list[dict] | None = None,
) -> JSONResponse:
    """402 challenge response.

    Callers pass either the price/resource/description triple (the
    original form — a single Base requirements dict is rebuilt) or a
    ready-built ``requirements`` dict/list (the multi-network form, used
    by the middleware once the servable legs are known).
    """
    if requirements is None:
        assert price is not None and resource is not None and description is not None
        requirements = build_payment_requirements(price, resource, description)
    return JSONResponse(
        status_code=402,
        content=challenge_content(error, requirements, reason),
    )


def subscriber_monthly_cap_exceeded_response(usage: dict) -> JSONResponse:
    """HTTP 429 for a subscriber over the monthly credit fair-use cap.

    The body is user-actionable: the credit cap, current credit usage, the
    period, the reset date (first of next month, UTC), and the per-call x402
    fallback — never silently served.
    """
    limit = usage["credit_limit"]
    return JSONResponse(
        status_code=429,
        content={
            "error": "subscriber_monthly_cap_exceeded",
            "message": (
                f"Monthly fair-use cap reached: {usage['credits_used']}/{limit} "
                f"credits in {usage['month']} (UTC). Your Pro subscription "
                f"renews its allowance on {usage['resets_at']}. Until then, "
                "per-call x402 payment still works: resend this request WITHOUT "
                "the X-Subscriber-Key header and include a valid X-Payment "
                "authorization."
            ),
            "credits_used": usage["credits_used"],
            "credit_limit": limit,
            "period": usage["month"],
            "resets_at": usage["resets_at"],
        },
    )


def free_tier_exhausted_response(usage: dict, requirements: dict | list[dict]) -> JSONResponse:
    """HTTP 402 when the monthly free credit bucket is exhausted.

    Deliberately 402, NOT 429: 429 stays exclusive to the subscriber
    fair-use cap (``subscriber_monthly_cap_exceeded``). The body carries
    the same canonical x402 payment challenge so the caller can pay per
    call immediately, plus the free-tier usage fields.
    """
    content = challenge_content(
        "free_tier_exhausted",
        requirements,
        message=(
            f"Free tier exhausted: {usage['credits_used']} of {usage['free_limit']} "
            f"free credits used this month (resets {usage['resets_at']}). "
            "Pay per call with x402 or subscribe for $9/mo ($10 of calls included)."
        ),
    )
    content.update(
        {
            "credits_used": usage["credits_used"],
            "free_limit": usage["free_limit"],
            "resets_at": usage["resets_at"],
        }
    )
    return JSONResponse(status_code=402, content=content)


def decode_x_payment(raw: str) -> dict | None:
    """Base64-decode the X-Payment header into a v1 payment payload dict.

    Kept None-returning (not the raising decoder search-mcp uses): the
    middleware and the existing test suite treat a malformed header as
    "no usable payment" and re-issue the 402 challenge, and
    ``test_decode_x_payment_malformed`` pins the None contract. Changing
    it to raise would break both without adding any check the challenge
    path does not already provide.
    """
    try:
        text = raw.strip()
        padded = text + "=" * (-len(text) % 4)
        obj = json.loads(base64.b64decode(padded, validate=True))
    except (binascii.Error, ValueError, json.JSONDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def check_payment_sanity(payload: dict, requirements: dict) -> str | None:
    """Local checks before calling the facilitator. None = OK, else a reason."""
    if payload.get("x402Version") != X402_VERSION:
        return "bad x402Version"
    if payload.get("scheme") != SCHEME:
        return "bad scheme"
    if payload.get("network") != NETWORK:
        return "bad network"
    inner = payload.get("payload")
    if not isinstance(inner, dict):
        return "missing payload"
    auth = inner.get("authorization")
    if not isinstance(auth, dict):
        return "missing authorization"
    pay_to = x402_pay_to()
    if not pay_to or str(auth.get("to", "")).lower() != pay_to.lower():
        return "bad recipient"
    try:
        value = int(str(auth.get("value", "0")))
    except (ValueError, TypeError):
        return "bad value"
    if value < int(requirements["maxAmountRequired"]):
        return "insufficient value"
    now = int(time.time())
    try:
        valid_after = int(str(auth.get("validAfter", "0")))
        valid_before = int(str(auth.get("validBefore", "0")))
    except (ValueError, TypeError):
        return "bad validity window"
    if not valid_after <= now < valid_before:
        return "authorization not currently valid"
    # M-1: bound the authorization lifetime so the replay-claim TTL always
    # covers it. Without this, a payer could submit an authorization valid
    # for days while the seen-signature cache evicts after 300s, enabling
    # pay-once/replay-for-free (the facilitator only rejects the spent nonce
    # at /settle, which happens AFTER the response is served).
    window = valid_before - valid_after
    if window <= 0 or window > MAX_TIMEOUT_SECONDS:
        return "authorization validity window exceeds maximum"
    if not str(inner.get("signature", "")).startswith("0x"):
        return "missing signature"
    return None


def check_solana_payment_sanity(payload: dict, requirements: dict) -> str | None:
    """Local sanity checks for a Solana x402 payload (plan §3b).

    Deliberately light: the payload carries a partially-signed transaction,
    not EIP-3009 fields, and deserializing it locally would need a Solana
    codec (new dependency — deferred hardening follow-up). Recipient and
    amount validation is the facilitator's job here, same trust anchor as
    on Base; what we check locally is shape only.
    """
    if payload.get("x402Version") != X402_VERSION:
        return "bad x402Version"
    if payload.get("scheme") != SCHEME:
        return "bad scheme"
    if payload.get("network") != requirements.get("network"):
        return "bad network"
    inner = payload.get("payload")
    if not isinstance(inner, dict):
        return "missing payload"
    transaction = inner.get("transaction")
    if not isinstance(transaction, str) or not transaction.strip():
        return "missing transaction"
    try:
        # Standard base64 per spec; tolerate the URL-safe alphabet too.
        raw = base64.b64decode(transaction.strip(), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return "invalid transaction encoding"
    if not raw:
        return "invalid transaction encoding"
    return None


def check_payment_sanity_for_network(payload: dict, requirements: dict) -> str | None:
    """Dispatch the local sanity checks on the requirements' network."""
    if requirements.get("network") == SOLANA_NETWORK:
        return check_solana_payment_sanity(payload, requirements)
    return check_payment_sanity(payload, requirements)


def replay_key_for(payload: dict, requirements: dict) -> str:
    """Anti-replay claim key: the 0x signature on EVM; on Solana the base64
    transaction string itself (the spec's recommended mitigation, §3b).
    The "solana:" prefix keeps the shared claim table collision-free."""
    inner = payload["payload"]
    if requirements.get("network") == SOLANA_NETWORK:
        return "solana:" + inner["transaction"]
    return inner["signature"]


# --- Anti-replay --------------------------------------------------------------
# M-1: claims persist in the billing SQLite DB — they survive restarts and
# are shared across workers, closing the in-memory cache's gaps. The claim
# is atomic (INSERT PRIMARY KEY), so the old check-then-mark split across
# the facilitator /verify await (a double-spend race) collapses to a single
# serve. signature_seen() performs the atomic claim; an in-memory dict is
# the fallback when the DB is unreachable.
_seen_signatures: dict[str, float] = {}
_replay_lock = threading.Lock()


def signature_seen(signature: str, ttl_seconds: int = MAX_TIMEOUT_SECONDS) -> bool:
    """True if this authorization signature was already used (replay).

    Atomically claims new signatures: the first caller wins, concurrent
    duplicates are rejected. Called BEFORE the facilitator /verify so the
    claim holds across the settle gap too.
    """
    try:
        return claim_x402_signature(signature, time.time() + ttl_seconds)
    except Exception:  # noqa: BLE001 — DB failure must not break payments
        log.warning("x402 replay-claim DB unavailable; using in-memory fallback")
    now = time.time()
    with _replay_lock:
        expired = [sig for sig, exp in _seen_signatures.items() if exp <= now]
        for sig in expired:
            del _seen_signatures[sig]
        if signature in _seen_signatures:
            return True
        _seen_signatures[signature] = now + ttl_seconds
        return False


def _settle_tx_hash(receipt: dict) -> str | None:
    for field in ("transaction", "txHash", "transactionHash", "hash"):
        value = receipt.get(field)
        if isinstance(value, str) and value:
            return value
    return None


# --- Middleware ---------------------------------------------------------------
_CLOUDFLARE_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        # IPv4
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        # IPv6
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    )
)


def _peer_is_cloudflare(peer: str) -> bool:
    """True when the direct TCP peer is a Cloudflare edge IP."""
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(addr in net for net in _CLOUDFLARE_NETWORKS)


def client_ip(request: Request) -> str:
    """Client IP for the monthly free credit bucket, proxy-aware (M-3).

    Mirrors ``rest_app._client_ip_from_scope`` (kept in step deliberately —
    the middleware cannot import the app module). Render terminates TLS at
    its proxy and appends the original client address to
    ``X-Forwarded-For``; the first entry is trusted ONLY when the direct
    TCP peer is a non-global address (i.e. we really are behind the
    proxy). A client connecting directly always has a global peer address,
    so a spoofed XFF from a direct connection is ignored — the bucket
    cannot be reset at will by rotating the header. An unparseable peer
    (the TestClient's ``"testclient"``) means a test harness, where XFF is
    trusted as before.

    When the domain is proxied through Cloudflare, the direct TCP peer is
    a Cloudflare edge IP and ``CF-Connecting-IP`` carries the real client
    address — trusted ONLY for verifiably Cloudflare peers, so spoofing
    from any other peer is impossible. The bucket stores only the SHA-256
    of this value, never the raw IP.
    """
    peer = request.client.host if request.client else ""
    if _peer_is_cloudflare(peer):
        cf_ip = request.headers.get("cf-connecting-ip", "").strip()
        if cf_ip:
            try:
                ipaddress.ip_address(cf_ip)
                return cf_ip
            except ValueError:
                pass  # garbage header: fall through to existing logic
    xff = request.headers.get("x-forwarded-for", "")
    try:
        behind_proxy = not ipaddress.ip_address(peer).is_global
    except ValueError:
        behind_proxy = True  # test harness (e.g. TestClient): no real peer
    if behind_proxy and xff:
        first = xff.split(",")[0].strip()
        if first:
            try:
                ipaddress.ip_address(first)
                return first
            except ValueError:
                pass  # garbage XFF value: fall through to the peer
    return peer or "unknown"


class X402PaymentMiddleware(BaseHTTPMiddleware):
    """Require facilitator-verified x402 payment on paid paths when enabled."""

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001, ANN202
        path = request.url.path
        if any(path == p or path.startswith(p + "/") for p in EXEMPT_PREFIXES):
            return await call_next(request)
        if path.startswith("/mcp") and request.method == "GET":
            # MCP discovery/info GETs stay free; tool calls are POST.
            return await call_next(request)
        if not x402_effective_enabled():
            return await call_next(request)

        # Stripe subscriber bypass: a valid subscriber key skips per-call x402,
        # subject to the Pro monthly fair-use CREDIT cap. The credit cost of
        # this call derives from the same price map the x402 path below uses,
        # so expensive tools cost more credits than cheap ones.
        sub_key = request.headers.get("x-subscriber-key")
        if sub_key and stripe_effective_enabled() and subscriber_key_valid(sub_key):
            price, _, exempt = await self._resolve_price(request)
            if exempt:
                # Free discovery/info calls cost nothing and are never capped.
                return await call_next(request)
            credit_cost = credits_for_price(price)
            usage = record_subscriber_credits(sub_key, credit_cost)
            if usage["credits_used"] > usage["credit_limit"]:
                log.info(
                    "Subscriber fair-use credit cap exceeded: %s/%s credits in %s",
                    usage["credits_used"],
                    usage["credit_limit"],
                    usage["month"],
                )
                return subscriber_monthly_cap_exceeded_response(usage)
            return await call_next(request)

        price, description, exempt = await self._resolve_price(request)
        if exempt:
            return await call_next(request)

        resource = str(request.url)
        # Solana fee payer discovery is lazy (plan §3b): resolve it before
        # building the challenge so the Solana leg can be offered at all.
        if SOLANA_NETWORK in requested_networks() and not solana_fee_payer():
            await resolve_solana_fee_payer()

        requirements_list = build_requirements_list(price, resource, description)
        if not requirements_list:
            # x402 is enabled but no leg is servable right now (e.g. the
            # Solana fee payer could not be resolved): fail closed rather
            # than serve a paid endpoint for free.
            log.error("x402 enabled but no servable network legs — failing closed")
            return JSONResponse(
                status_code=503,
                content={
                    "error": "payment_verification_unavailable",
                    "message": FACILITATOR_DOWN_MESSAGE,
                },
            )
        requirements_by_network = {entry["network"]: entry for entry in requirements_list}
        requirements = requirements_list[0]

        raw = request.headers.get("x-payment")
        if not raw:
            # Free tier: anonymous callers draw from the monthly per-IP
            # credit bucket before the 402 challenge (see billing.py).
            # Denied/exhausted calls never consume credits; the deduction
            # happens here, before serving, exactly like the subscriber cap.
            # Always-paid aliases never draw from the free bucket: without
            # a valid X-Payment they fall through to the 402 challenge
            # below, so directory checkers and router dispatch see a price.
            if free_tier_enabled() and not path.startswith(PAID_ROUTE_PREFIX):
                verdict = record_free_tier_usage(client_ip(request), credits_for_price(price))
                if verdict["allowed"]:
                    return await call_next(request)
                return free_tier_exhausted_response(verdict, requirements_list)
            return payment_required_response(requirements=requirements_list)
        payload = decode_x_payment(raw)
        if payload is None:
            return payment_required_response(
                requirements=requirements_list,
                reason="X-Payment header is not valid base64-encoded JSON",
            )
        # Select the requirements for the network the client actually paid
        # on (plan §4b.4); an unknown network is rejected outright.
        network = payload.get("network")
        leg = requirements_by_network.get(network) if isinstance(network, str) else None
        if leg is None and network is None:
            # No network asserted: fall back to the Base requirements so
            # the EVM sanity checks report the mismatch, as before.
            leg = requirements_by_network.get(NETWORK)
        if leg is None and len(requirements_list) == 1:
            # Single-network configs keep their exact pre-port behavior:
            # the one servable leg's sanity checks report the mismatch
            # (e.g. "bad network"), as before.
            leg = requirements_list[0]
        if leg is None:
            # This repo's contract: sanity failures surface as
            # payment_required with a reason (facilitator rejections are
            # the payment_invalid ones) — preserved for the multi-network
            # unknown-network case too.
            return payment_required_response(
                requirements=requirements_list,
                reason="unsupported network",
            )
        requirements = leg
        sanity_reason = check_payment_sanity_for_network(payload, requirements)
        if sanity_reason is not None:
            log.info("x402 local sanity check failed: %s", sanity_reason)
            return payment_required_response(
                requirements=requirements_list,
                reason=sanity_reason,
            )

        replay_key = replay_key_for(payload, requirements)
        if signature_seen(replay_key):
            return JSONResponse(
                status_code=402,
                content=challenge_content(
                    "duplicate_payment", requirements_list, "payment already used"
                ),
            )

        client = get_facilitator_client()
        try:
            verdict = await client.verify(payload, requirements)
        except Exception as exc:  # noqa: BLE001 — any transport failure fails closed
            log.error("x402 facilitator /verify unreachable: %r", exc)
            return JSONResponse(
                status_code=503,
                content={
                    "error": "payment_verification_unavailable",
                    "message": FACILITATOR_DOWN_MESSAGE,
                },
            )
        if not isinstance(verdict, dict) or not verdict.get("isValid"):
            invalid_reason = (
                verdict.get("invalidReason", "unknown") if isinstance(verdict, dict) else "unknown"
            )
            log.info("x402 facilitator rejected payment: %s", invalid_reason)
            return JSONResponse(
                status_code=402,
                content=challenge_content("payment_invalid", requirements, str(invalid_reason)),
            )

        payer = verdict.get("payer") if isinstance(verdict, dict) else None

        response = await call_next(request)

        # Settle AFTER serving. Settle failure never fails the served request,
        # but it may mean money is unclaimed — log loudly.
        try:
            receipt = await client.settle(payload, requirements)
        except Exception as exc:  # noqa: BLE001
            log.error(
                "x402 SETTLE FAILED after serving %s (payer=%s amount=%s atomic): %r — "
                "authorization was verified but funds may be UNCLAIMED",
                resource,
                payer,
                requirements["maxAmountRequired"],
                exc,
            )
        else:
            tx_hash = _settle_tx_hash(receipt) if isinstance(receipt, dict) else None
            if isinstance(receipt, dict) and receipt.get("success") and tx_hash:
                log.info(
                    "x402 settled: tx=%s payer=%s amount=%s atomic",
                    tx_hash,
                    payer,
                    requirements["maxAmountRequired"],
                )
            else:
                log.error(
                    "x402 SETTLE REPORTED FAILURE after serving %s (payer=%s amount=%s atomic): "
                    "%r — funds may be UNCLAIMED",
                    resource,
                    payer,
                    requirements["maxAmountRequired"],
                    receipt,
                )
        return response

    async def _resolve_price(self, request: Request) -> tuple[Decimal, str, bool]:
        """Return (price_usdc, description, exempt). Unparseable bodies get the
        default price, never a 500."""
        path = request.url.path
        method = request.method
        if path.startswith("/mcp") and method == "POST":
            try:
                body = await request.body()
                message = json.loads(body)
            except (ValueError, json.JSONDecodeError):
                return x402_price_usdc(), "MCP request", False
            rpc_method = message.get("method") if isinstance(message, dict) else None
            if rpc_method in DISCOVERY_METHODS or (
                isinstance(rpc_method, str) and rpc_method.startswith("notifications/")
            ):
                return Decimal("0"), "", True  # discovery stays free
            if rpc_method == "tools/call":
                params = message.get("params") if isinstance(message, dict) else None
                tool = params.get("name") if isinstance(params, dict) else None
                if isinstance(tool, str) and tool in TOOL_PRICES_USDC:
                    return tool_price_usdc(tool), f"MCP tool '{tool}'", False
                return x402_price_usdc(), f"MCP tool '{tool}'", False
            return x402_price_usdc(), "MCP request", False
        if method == "POST" and path in REST_TOOL_PRICES:
            tool = REST_TOOL_PRICES[path]
            return tool_price_usdc(tool), f"REST {path} (tool '{tool}')", False
        return x402_price_usdc(), f"{method} {path}", False


def warn_if_payments_misconfigured() -> None:
    """Startup safety rails: loud logs when payments are half-configured or live."""
    if _env_flag("X402_ENABLED") and not x402_effective_enabled():
        log.error(
            "X402_ENABLED=true but configuration is incomplete "
            "(need X402_PAY_TO and X402_FACILITATOR_URL) — x402 DISABLED (fail closed)."
        )
    elif x402_effective_enabled():
        servable = valid_networks()
        if NETWORK in servable:
            if facilitator_url() == DEFAULT_FACILITATOR_URL:
                log.warning(
                    "X402 payments LIVE against the DEFAULT facilitator "
                    "(https://x402.org/facilitator — Base Sepolia testnet ONLY, not mainnet). "
                    "For Base mainnet, set X402_FACILITATOR_URL to the CDP facilitator + CDP keys."
                )
            else:
                log.warning(
                    "X402 payments LIVE — real USDC charges on Base. Confirm AZ LLC is formed."
                )
        if SOLANA_NETWORK in servable:
            if solana_facilitator_url() == DEFAULT_FACILITATOR_URL:
                log.warning(
                    "X402 Solana leg LIVE against %s — that default facilitator is "
                    "Base Sepolia only; Solana needs the CDP facilitator + keys.",
                    DEFAULT_FACILITATOR_URL,
                )
            else:
                log.warning(
                    "X402 payments LIVE — real USDC charges on Solana. Confirm AZ LLC is formed."
                )
    if _env_flag("STRIPE_ENABLED") and not stripe_effective_enabled():
        log.error(
            "STRIPE_ENABLED=true but configuration is incomplete "
            "(need STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_ID) — "
            "Stripe DISABLED (fail closed)."
        )
