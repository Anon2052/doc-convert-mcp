"""x402 (USDC on Base) metering middleware.

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
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import secrets
import threading
import time
from decimal import Decimal, InvalidOperation

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .billing import (
    free_tier_enabled,
    record_subscriber_credits,
    record_usage,
    stripe_effective_enabled,
    subscriber_key_valid,
    try_consume_free_credits,
)

log = logging.getLogger("doc_convert_mcp.x402")

# --- x402 v1 "exact" scheme constants ---------------------------------------
X402_VERSION = 1
SCHEME = "exact"
NETWORK = "base"
#: Circle's canonical USDC contract on Base (6 decimals).
USDC_BASE_CONTRACT = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA38bD"
USDC_DECIMALS = 6
MAX_TIMEOUT_SECONDS = 300
FACILITATOR_TIMEOUT = 15.0
#: Default facilitator. Base Sepolia (testnet) ONLY — not mainnet.
#: For Base mainnet Scott must set X402_FACILITATOR_URL to the Coinbase CDP
#: facilitator (https://api.cdp.coinbase.com/platform/v2/x402) with CDP creds.
DEFAULT_FACILITATOR_URL = "https://x402.org/facilitator"

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
)

# JSON-RPC methods that are discovery, not paid tool calls.
DISCOVERY_METHODS = frozenset({"initialize", "tools/list", "ping"})

# --- Pricing ----------------------------------------------------------------
#: Fallback price for any paid call without a per-tool default.
DEFAULT_PRICE_USDC = Decimal("0.015")
#: Per-tool price defaults, in USDC. Pricing is a business decision — Scott
#: adjusts these before enabling payments (env overrides, see below).
TOOL_PRICES_USDC: dict[str, Decimal] = {
    "pdf_to_markdown": Decimal("0.03"),
    "ocr_image": Decimal("0.02"),
    "parse_spreadsheet": Decimal("0.02"),
    "url_to_clean_text": Decimal("0.01"),
}
#: REST route -> tool price mapping.
REST_TOOL_PRICES: dict[str, str] = {
    "/convert/pdf": "pdf_to_markdown",
    "/convert/ocr": "ocr_image",
    "/convert/spreadsheet": "parse_spreadsheet",
    "/convert/url": "url_to_clean_text",
}


def _env_flag(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def x402_pay_to() -> str:
    return os.environ.get("X402_PAY_TO", "").strip()


def x402_facilitator_url() -> str:
    return os.environ.get("X402_FACILITATOR_URL", DEFAULT_FACILITATOR_URL).strip()


def x402_effective_enabled() -> bool:
    """True only when x402 is fully configured. Fail closed otherwise."""
    if not _env_flag("X402_ENABLED"):
        return False
    if not x402_pay_to():
        log.error("X402_ENABLED=true but X402_PAY_TO is empty — x402 DISABLED (fail closed).")
        return False
    if not x402_facilitator_url():
        log.error(
            "X402_ENABLED=true but X402_FACILITATOR_URL is empty — x402 DISABLED (fail closed)."
        )
        return False
    return True


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


def mint_cdp_jwt(key_id: str, key_secret: str) -> str:
    """Mint a CDP EdDSA JWT for facilitator auth.

    NOTE: the exact CDP claim set needs a live smoke test with Scott's keys
    before mainnet enablement.
    """
    key = _load_ed25519_private_key(key_secret)
    now = int(time.time())
    header = {"alg": "EdDSA", "typ": "JWT", "kid": key_id, "nonce": secrets.token_hex(16)}
    claims = {"sub": key_id, "iss": "coinbase-cloud", "nbf": now - 30, "exp": now + 120}

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
class FacilitatorClient:
    """Thin async client for the x402 facilitator HTTP API (v1 'exact' scheme)."""

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = FACILITATOR_TIMEOUT,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = (base_url or x402_facilitator_url()).rstrip("/")
        self.timeout = timeout
        self._http_client = http_client
        self._owns_client = http_client is None

    def _auth_headers(self) -> dict[str, str]:
        api_key = os.environ.get("X402_FACILITATOR_API_KEY", "").strip()
        if api_key:
            return {"X-API-Key": api_key}
        key_id = os.environ.get("CDP_API_KEY_ID", "").strip()
        key_secret = os.environ.get("CDP_API_KEY_SECRET", "").strip()
        if key_id and key_secret:
            return {"Authorization": "Bearer " + mint_cdp_jwt(key_id, key_secret)}
        return {}

    async def _post(self, path: str, body: dict) -> dict:
        client = self._http_client or httpx.AsyncClient(timeout=self.timeout)
        try:
            resp = await client.post(self.base_url + path, json=body, headers=self._auth_headers())
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
        )

    async def settle(self, payment_payload: dict, payment_requirements: dict) -> dict:
        return await self._post(
            "/settle",
            {
                "x402Version": X402_VERSION,
                "paymentPayload": payment_payload,
                "paymentRequirements": payment_requirements,
            },
        )


def get_facilitator_client() -> FacilitatorClient:
    """Factory indirection so tests can inject a fake facilitator."""
    return FacilitatorClient()


# --- Payment payload handling -------------------------------------------------
def build_payment_requirements(price: Decimal, resource: str, description: str) -> dict:
    return {
        "x402Version": X402_VERSION,
        "scheme": SCHEME,
        "network": NETWORK,
        "maxAmountRequired": str(usdc_to_atomic_units(price)),
        "resource": resource,
        "description": description,
        "payTo": x402_pay_to(),
        "maxTimeoutSeconds": MAX_TIMEOUT_SECONDS,
        "asset": USDC_BASE_CONTRACT,
    }


def payment_required_response(
    *,
    price: Decimal,
    resource: str,
    description: str,
    error: str = "payment_required",
    message: str | None = None,
    invalid_reason: str | None = None,
) -> JSONResponse:
    content: dict = {
        "error": error,
        "message": message
        or (
            "This endpoint requires an x402 USDC micropayment on Base. "
            "Send an X-Payment header with the base64-encoded v1 payment payload "
            "containing a signed EIP-3009 authorization. Alternatively, subscribe "
            "to Pro for $9/mo (includes $10 of API calls) and send your "
            "X-Subscriber-Key."
        ),
        "accepts": {
            "asset": USDC_BASE_CONTRACT,
            "network": NETWORK,
            "amount": str(price),
            "pay_to": x402_pay_to() or "<set X402_PAY_TO>",
            "scheme": SCHEME,
            "x402Version": X402_VERSION,
        },
        "paymentRequirements": build_payment_requirements(price, resource, description),
    }
    if invalid_reason:
        content["invalidReason"] = invalid_reason
    return JSONResponse(status_code=402, content=content)


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


def free_tier_exhausted_response(usage: dict) -> JSONResponse:
    """HTTP 402 for a client IP over the monthly free credit bucket.

    402, NOT 429 — 429 stays exclusively for the subscriber fair-use cap.
    The body is user-actionable: credits used vs the free limit, the reset
    date (first of next month UTC), and how to keep calling (pay per-call via
    x402, or subscribe to Pro for $9/mo — $10 of calls included).
    """
    limit = usage["free_limit"]
    return JSONResponse(
        status_code=402,
        content={
            "error": "free_tier_exhausted",
            "message": (
                f"Free tier exhausted: {usage['credits_used']}/{limit} credits "
                f"used in {usage['month']} (UTC); the bucket resets on "
                f"{usage['resets_at']}. To keep calling now, pay per-call via "
                "x402 (resend this request with a valid X-Payment "
                "authorization) or subscribe to Pro for $9/mo — includes $10 "
                "of API calls — and send your X-Subscriber-Key."
            ),
            "credits_used": usage["credits_used"],
            "free_limit": limit,
            "resets_at": usage["resets_at"],
            "upgrade_hint": (
                "Pay per-call with an X-Payment x402 authorization, or "
                "subscribe to Pro ($9/mo, $10 of calls included) and use "
                "X-Subscriber-Key."
            ),
        },
    )


def client_ip(request: Request) -> str:
    """Client IP for the free-tier bucket, Render-aware.

    First entry of ``X-Forwarded-For`` when present (Render terminates TLS at
    its edge and forwards the real client IP); otherwise the direct peer
    address. Only the SHA-256 hash is ever stored — see
    :func:`billing.hash_client_ip`.
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    client = request.client
    return client.host if client else "unknown"


def decode_x_payment(raw: str) -> dict | None:
    """Base64-decode the X-Payment header into a v1 payment payload dict."""
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
    if not str(inner.get("signature", "")).startswith("0x"):
        return "missing signature"
    return None


# --- Anti-replay --------------------------------------------------------------
_seen_signatures: dict[str, float] = {}
_replay_lock = threading.Lock()


def _prune_seen_locked(now: float) -> None:
    expired = [sig for sig, exp in _seen_signatures.items() if exp <= now]
    for sig in expired:
        del _seen_signatures[sig]


def signature_seen(signature: str) -> bool:
    """True if this authorization signature was already used (replay)."""
    now = time.time()
    with _replay_lock:
        _prune_seen_locked(now)
        return signature in _seen_signatures


def mark_signature_seen(signature: str, ttl_seconds: int = MAX_TIMEOUT_SECONDS) -> None:
    with _replay_lock:
        _prune_seen_locked(time.time())
        _seen_signatures[signature] = time.time() + ttl_seconds


def _settle_tx_hash(receipt: dict) -> str | None:
    for field in ("transaction", "txHash", "transactionHash", "hash"):
        value = receipt.get(field)
        if isinstance(value, str) and value:
            return value
    return None


# --- Middleware ---------------------------------------------------------------
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
            # Unmetered: serve everything. Analytics records these as
            # zero-credit "free" calls (nothing deducted, nothing paid).
            # Price resolution happens BEFORE serving: downstream consumes the
            # request body stream.
            _, _, exempt, tool_label = await self._resolve_price(request)
            response = await call_next(request)
            if not exempt:
                self._record_served_call(tool_label, "free", 0.0)
            return response

        # Stripe subscriber bypass: a valid subscriber key skips per-call x402,
        # subject to the Pro monthly fair-use CREDIT cap. The credit cost of
        # this call derives from the same price map the x402 path below uses,
        # so expensive tools cost more credits than cheap ones.
        sub_key = request.headers.get("x-subscriber-key")
        if sub_key and stripe_effective_enabled() and subscriber_key_valid(sub_key):
            price, _, exempt, tool_label = await self._resolve_price(request)
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
            response = await call_next(request)
            self._record_served_call(tool_label, "subscriber", credit_cost)
            return response

        price, description, exempt, tool_label = await self._resolve_price(request)
        if exempt:
            return await call_next(request)

        # Anonymous free tier: no valid subscriber key and no x402 payment
        # presented. A call presenting X-Payment goes through the payment flow
        # below and never touches the free bucket. Denied/exhausted calls
        # consume nothing (check-then-deduct is atomic in
        # try_consume_free_credits). FREE_TIER_ENABLED=false skips this branch
        # entirely — the request falls straight to the 402 challenge.
        if not request.headers.get("x-payment") and free_tier_enabled():
            credit_cost = credits_for_price(price)
            served, usage = try_consume_free_credits(client_ip(request), credit_cost)
            if not served:
                log.info(
                    "Free tier exhausted: %s/%s credits in %s",
                    usage["credits_used"],
                    usage["free_limit"],
                    usage["month"],
                )
                return free_tier_exhausted_response(usage)
            response = await call_next(request)
            self._record_served_call(tool_label, "free", credit_cost)
            return response

        resource = str(request.url)
        requirements = build_payment_requirements(price, resource, description)

        raw = request.headers.get("x-payment")
        if not raw:
            return payment_required_response(
                price=price, resource=resource, description=description
            )
        payload = decode_x_payment(raw)
        if payload is None:
            return payment_required_response(
                price=price, resource=resource, description=description
            )
        sanity_reason = check_payment_sanity(payload, requirements)
        if sanity_reason is not None:
            log.info("x402 local sanity check failed: %s", sanity_reason)
            return payment_required_response(
                price=price, resource=resource, description=description
            )

        signature = str(payload["payload"]["signature"])
        if signature_seen(signature):
            return JSONResponse(
                status_code=402,
                content={
                    "error": "duplicate_payment",
                    "message": "This payment authorization has already been used.",
                },
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
                    "message": "Payment verification is temporarily unavailable; try again.",
                },
            )
        if not isinstance(verdict, dict) or not verdict.get("isValid"):
            invalid_reason = (
                verdict.get("invalidReason", "unknown") if isinstance(verdict, dict) else "unknown"
            )
            log.info("x402 facilitator rejected payment: %s", invalid_reason)
            return payment_required_response(
                price=price,
                resource=resource,
                description=description,
                error="payment_invalid",
                invalid_reason=str(invalid_reason),
            )

        mark_signature_seen(signature)
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
        # Paid and served: analytics credits are the list-price credits that
        # WOULD have been charged (the payment itself was USDC, not credits).
        self._record_served_call(tool_label, "x402", credits_for_price(price))
        return response

    def _record_served_call(self, tool_label: str, plan_type: str, credits: float) -> None:
        """Best-effort usage analytics: a failed write must never break serving."""
        if not tool_label:
            return
        try:
            record_usage(tool_label, plan_type, credits)
        except Exception:  # noqa: BLE001 — analytics is observability, not gating
            log.exception("usage analytics write failed (non-fatal)")

    async def _resolve_price(self, request: Request) -> tuple[Decimal, str, bool, str]:
        """Return (price_usdc, description, exempt, tool_label). Unparseable
        bodies get the default price, never a 500. ``tool_label`` is the
        per-tool name for the usage-analytics rollup ("" when exempt)."""
        path = request.url.path
        method = request.method
        if path.startswith("/mcp") and method == "POST":
            try:
                body = await request.body()
                message = json.loads(body)
            except (ValueError, json.JSONDecodeError):
                return x402_price_usdc(), "MCP request", False, "mcp_request"
            rpc_method = message.get("method") if isinstance(message, dict) else None
            if rpc_method in DISCOVERY_METHODS or (
                isinstance(rpc_method, str) and rpc_method.startswith("notifications/")
            ):
                return Decimal("0"), "", True, ""  # discovery stays free
            if rpc_method == "tools/call":
                params = message.get("params") if isinstance(message, dict) else None
                tool = params.get("name") if isinstance(params, dict) else None
                if isinstance(tool, str) and tool in TOOL_PRICES_USDC:
                    return tool_price_usdc(tool), f"MCP tool '{tool}'", False, tool
                label = tool if isinstance(tool, str) and tool else "mcp_tool_call"
                return x402_price_usdc(), f"MCP tool '{tool}'", False, label
            return x402_price_usdc(), "MCP request", False, "mcp_request"
        if method == "POST" and path in REST_TOOL_PRICES:
            tool = REST_TOOL_PRICES[path]
            return tool_price_usdc(tool), f"REST {path} (tool '{tool}')", False, tool
        return x402_price_usdc(), f"{method} {path}", False, f"{method} {path}"


def warn_if_payments_misconfigured() -> None:
    """Startup safety rails: loud logs when payments are half-configured or live."""
    if _env_flag("X402_ENABLED") and not x402_effective_enabled():
        log.error(
            "X402_ENABLED=true but configuration is incomplete "
            "(need X402_PAY_TO and X402_FACILITATOR_URL) — x402 DISABLED (fail closed)."
        )
    elif x402_effective_enabled():
        if x402_facilitator_url() == DEFAULT_FACILITATOR_URL:
            log.warning(
                "X402 payments LIVE against the DEFAULT facilitator "
                "(https://x402.org/facilitator — Base Sepolia testnet ONLY, not mainnet). "
                "For Base mainnet, set X402_FACILITATOR_URL to the CDP facilitator with CDP keys."
            )
        else:
            log.warning("X402 payments LIVE — real USDC charges on Base. Confirm AZ LLC is formed.")
    if _env_flag("STRIPE_ENABLED") and not stripe_effective_enabled():
        log.error(
            "STRIPE_ENABLED=true but configuration is incomplete "
            "(need STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_ID) — "
            "Stripe DISABLED (fail closed)."
        )
