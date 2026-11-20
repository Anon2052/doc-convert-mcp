"""Combined ASGI app: REST API + FastMCP (streamable HTTP) + /health.

Run with:  uvicorn doc_convert_mcp.rest_app:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import collections
import ipaddress
import logging
import os
import threading
import time

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.responses import FileResponse, Response
from starlette.routing import Route

from . import __version__
from .billing import (
    create_checkout_session,
    get_subscriber_credit_usage,
    handle_stripe_webhook,
    issue_key_for_session,
    stripe_effective_enabled,
    subscriber_key_valid,
)
from .converters import ConversionError, ocr_image, parse_spreadsheet, pdf_to_markdown
from .converters import url_to_clean_text as _url_to_clean_text
from .legal_docs import PRIVACY_POLICY, REFUND_POLICY, SUPPORT_PAGE, TERMS_OF_SERVICE
from .mcp_server import mcp
from .x402 import (
    X402PaymentMiddleware,
    build_discovery_manifest,
    warn_if_payments_misconfigured,
    x402_effective_enabled,
)

log = logging.getLogger("doc_convert_mcp")

DEFAULT_RATE_LIMIT = os.environ.get("RATE_LIMIT", "60/minute")
MAX_UPLOAD_BYTES = 30 * 1024 * 1024  # 30 MB — matches the 25 MB file cap + headroom (H-4)


# Cloudflare edge IP ranges, hardcoded 2026-10-01 from
# https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6.
# Refresh these if Cloudflare publishes an update; stale ranges would
# silently disable the CF-Connecting-IP fast path in _client_ip_from_scope.
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


def _client_ip_from_scope(scope) -> str:  # noqa: ANN001, ANN202
    """Proxy-aware client IP for rate limiting (M-3).

    The X-Forwarded-For first entry is trusted ONLY when the direct TCP peer
    is a non-global address (i.e. we are behind Render's load balancer or
    another proxy). A client connecting directly always has a global peer
    address, so a spoofed XFF from a direct connection is ignored.

    When the direct TCP peer is a Cloudflare edge IP (the domain is proxied
    through Cloudflare), CF-Connecting-IP is trusted instead — spoof-proof,
    because the header is honored only for verifiably Cloudflare peers.
    """
    headers = {
        k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])
    }
    client = scope.get("client")
    peer = client[0] if client else ""
    if _peer_is_cloudflare(peer):
        # Proxied through Cloudflare: CF-Connecting-IP carries the real
        # client IP. The header is honored ONLY when the TCP peer is
        # verifiably a Cloudflare edge IP, so spoofing from any other
        # peer is impossible.
        cf_ip = headers.get("cf-connecting-ip", "").strip()
        if cf_ip:
            try:
                ipaddress.ip_address(cf_ip)
                return cf_ip
            except ValueError:
                pass  # garbage header: fall through to existing logic
    try:
        behind_proxy = not ipaddress.ip_address(peer).is_global
    except ValueError:
        # Unparseable peer (e.g. TestClient's "testclient"): a test harness
        # with no real TCP peer — trust XFF as before. A real direct client
        # always presents a parseable global IP, so spoofing stays blocked.
        behind_proxy = True
    if behind_proxy:
        first = headers.get("x-forwarded-for", "").split(",")[0].strip()
        if first:
            try:
                ipaddress.ip_address(first)
                return first
            except ValueError:
                pass  # garbage XFF value: fall through to the peer
    return peer or "unknown"


def _rate_limit_key(request: Request) -> str:
    """slowapi key_func: one bucket per real client IP (M-3)."""
    return _client_ip_from_scope(request.scope)


def _mcp_scope_key(scope) -> str:  # noqa: ANN001, ANN202
    """Key func for the MCP rate-limit wrapper (takes the raw ASGI scope)."""
    return _client_ip_from_scope(scope)


def _parse_per_minute(limit: str) -> int:
    """Parse a slowapi-style limit string ('60/minute') to requests/minute."""
    try:
        count_raw, _, per = limit.strip().partition("/")
        count = int(count_raw)
        factor = {"second": 60, "minute": 1, "hour": 1 / 60, "day": 1 / 1440}.get(
            (per or "minute").strip().lower()
        )
        if factor is None or count <= 0:
            raise ValueError
        return max(1, int(count * factor))
    except (ValueError, AttributeError):
        log.warning("Unparseable RATE_LIMIT=%r; MCP limit defaulting to 60/minute", limit)
        return 60


class _McpRateLimitMiddleware:
    """Per-IP sliding-window rate limiter for the mounted MCP sub-app (H-5).

    SlowAPI's default_limits cannot see through a Starlette Mount (a Mount
    has no ``endpoint`` attribute, so SlowAPI's middleware exempts it),
    which left /mcp/* completely unthrottled. This pure-ASGI wrapper applies
    the same per-minute budget around the MCP app, covering both the /mcp/*
    mount and the bare-/mcp route.
    """

    def __init__(self, app, per_minute: int, key_func) -> None:  # noqa: ANN001, ANN204
        self._app = app
        self._per_minute = per_minute
        self._key_func = key_func
        self._hits: dict[str, collections.deque[float]] = {}
        self._lock = threading.Lock()

    async def __call__(self, scope, receive, send) -> None:  # noqa: ANN001, ANN202
        if scope.get("type") == "http":
            key = self._key_func(scope)
            now = time.monotonic()
            cutoff = now - 60.0
            with self._lock:
                dq = self._hits.get(key)
                if dq is None:
                    dq = self._hits[key] = collections.deque()
                while dq and dq[0] <= cutoff:
                    dq.popleft()
                over = len(dq) >= self._per_minute
                if not over:
                    dq.append(now)
                if len(self._hits) > 20000:  # memory hygiene
                    self._hits = {k: v for k, v in self._hits.items() if v}
            if over:
                resp = JSONResponse(
                    status_code=429,
                    content={
                        "error": "rate_limited",
                        "message": "Too many requests, slow down.",
                    },
                )
                await resp(scope, receive, send)
                return
        await self._app(scope, receive, send)


class _UploadSizeLimitMiddleware:
    """Reject oversized request bodies before the app buffers them (H-4).

    FastAPI's UploadFile spools to memory/disk per request; a 10GB declared
    Content-Length on /convert/* would tie up workers for minutes. This
    pure-ASGI middleware 413s any /convert/* POST whose declared
    Content-Length exceeds MAX_UPLOAD_BYTES. Chunked uploads with no
    Content-Length are caught by _read_upload_capped's running total.
    """

    def __init__(self, app) -> None:  # noqa: ANN001, ANN204
        self._app = app

    async def __call__(self, scope, receive, send) -> None:  # noqa: ANN001, ANN202
        if scope.get("type") == "http" and scope.get("method") == "POST":
            path = scope.get("path", "")
            if path.startswith("/convert/"):
                headers = {
                    k.decode("latin-1").lower(): v.decode("latin-1")
                    for k, v in scope.get("headers", [])
                }
                try:
                    declared = int(headers.get("content-length", "0"))
                except ValueError:
                    declared = 0
                if declared > MAX_UPLOAD_BYTES:
                    resp = JSONResponse(
                        status_code=413,
                        content={
                            "error": "upload_too_large",
                            "message": f"Upload exceeds the {MAX_UPLOAD_BYTES} byte limit.",
                        },
                    )
                    await resp(scope, receive, send)
                    return
        await self._app(scope, receive, send)


async def _read_upload_capped(file: UploadFile, max_bytes: int = MAX_UPLOAD_BYTES) -> bytes:
    """Read an UploadFile in chunks with a running size cap (H-4).

    Starlette's UploadFile.spool_max_size only spills to disk — it does not
    cap total size. A single `await file.read()` on a chunked (no
    Content-Length) upload would buffer an unbounded body into RAM.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ConversionError(f"upload: {total} bytes exceeds {max_bytes} byte limit")
        chunks.append(chunk)
    return b"".join(chunks)


class UrlRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


class _BareMcpAsgi:
    """Serve the MCP ASGI app on the bare /mcp path (no trailing slash).

    Starlette's Mount only matches /mcp/*, so the router 307-redirects the
    bare /mcp to /mcp/ — and many MCP clients don't follow redirects. This
    endpoint serves the same ASGI app directly, mirroring the child scope a
    Mount would build (path "/" with root_path extended by "/mcp").
    """

    def __init__(self, mcp_asgi):  # noqa: ANN001, ANN204
        self.mcp_asgi = mcp_asgi
        # SlowAPI's middleware builds a route name from endpoint.__name__;
        # plain instances don't have one, so provide it.
        self.__name__ = "mcp_bare_path"
        self.__module__ = __name__

    async def __call__(self, scope, receive, send):  # noqa: ANN001, ANN202
        bare = dict(scope)
        bare["path"] = "/"
        bare["root_path"] = scope.get("root_path", "") + "/mcp"
        await self.mcp_asgi(bare, receive, send)


def create_app(rate_limit: str | None = None) -> FastAPI:
    # MCP sub-app first: its lifespan must be handed to the parent FastAPI app,
    # otherwise FastMCP's session task group never initializes and every
    # request 500s ("Task group is not initialized"). path="/" serves the MCP
    # endpoint at the mount root, i.e. POST /mcp (the http_app default path
    # would double it to /mcp/mcp).
    mcp_asgi = mcp.http_app(path="/", transport="streamable-http", stateless_http=True)
    mcp_lifespan = mcp_asgi.lifespan  # capture BEFORE wrapping (wrapper has none)
    limit = rate_limit or DEFAULT_RATE_LIMIT
    # H-5: the MCP surface gets its own per-IP rate limiter — SlowAPI's
    # default_limits cannot cover a Starlette Mount (see _McpRateLimitMiddleware).
    mcp_asgi = _McpRateLimitMiddleware(mcp_asgi, _parse_per_minute(limit), _mcp_scope_key)
    app = FastAPI(
        title="doc-convert-mcp",
        version=__version__,
        description="Document conversion API: PDF to Markdown, OCR, spreadsheets, URL to text.",
        lifespan=mcp_lifespan,
    )

    # x402 metering (env-gated, OFF by default) runs outermost.
    warn_if_payments_misconfigured()
    app.add_middleware(X402PaymentMiddleware)

    # H-4: reject oversized uploads before the app buffers them.
    app.add_middleware(_UploadSizeLimitMiddleware)

    # M-3: proxy-aware key func — one bucket per real client IP, not one
    # shared bucket keyed on Render's load balancer.
    limiter = Limiter(key_func=_rate_limit_key)

    @app.exception_handler(RateLimitExceeded)
    async def _rate_limit_handler(request, exc):  # noqa: ANN001, ANN202
        return JSONResponse(
            status_code=429,
            content={"error": "rate_limited", "message": "Too many requests, slow down."},
        )

    @app.exception_handler(ConversionError)
    async def _conversion_error_handler(request, exc):  # noqa: ANN001, ANN202
        return JSONResponse(
            status_code=422, content={"error": "conversion_failed", "message": str(exc)}
        )

    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)

    @app.get("/health")
    async def health():
        return {
            "status": "ok",
            "version": __version__,
            "x402": "enabled" if x402_effective_enabled() else "disabled",
            "stripe": "enabled" if stripe_effective_enabled() else "disabled",
        }

    # --- x402 discovery manifest: public, always free -----------------------
    # Served at BOTH well-known paths (some registries read the bare path,
    # others the .json form). No @limiter.limit: discovery must never 429,
    # and the "/.well-known" prefix in EXEMPT_PREFIXES keeps the x402
    # middleware from ever 402-challenging it. Built at request time from
    # build_discovery_manifest() so prices always reflect the live single
    # source of truth (TOOL_PRICES_USDC + X402_PRICE_*_USDC env overrides).
    @app.get("/.well-known/x402", include_in_schema=False)
    @app.get("/.well-known/x402.json", include_in_schema=False)
    async def x402_discovery_manifest():
        return build_discovery_manifest()

    # --- Glama connector ownership claim: public, always free ----------------
    # HTTP challenge for glama.ai/mcp/connectors/dev.ioconnex/doc-convert-mcp.
    # Served verbatim; the "/.well-known" prefix in EXEMPT_PREFIXES keeps x402
    # from 402-challenging it.
    @app.get("/.well-known/glama.json", include_in_schema=False)
    async def glama_claim():
        return {
            "$schema": "https://glama.ai/mcp/schemas/connector.json",
            "claim": "glama_claim_rZE1zWvHzco25hY6XxC-qESh-btji64O",
        }

    # --- Legal documents: public, always free (Stripe onboarding URLs) -------
    # No @limiter.limit on these: informational endpoints should never 429 or
    # 402. EXEMPT_PREFIXES in x402.py covers the whole /legal prefix.
    @app.get("/legal/terms", include_in_schema=False)
    async def legal_terms():
        return Response(content=TERMS_OF_SERVICE, media_type="text/markdown; charset=utf-8")

    @app.get("/legal/privacy", include_in_schema=False)
    async def legal_privacy():
        return Response(content=PRIVACY_POLICY, media_type="text/markdown; charset=utf-8")

    @app.get("/legal/refunds", include_in_schema=False)
    async def legal_refunds():
        return Response(content=REFUND_POLICY, media_type="text/markdown; charset=utf-8")

    # --- Public support page (directory listings' supportURL target) --------
    # Always free: "/support" is in EXEMPT_PREFIXES in x402.py.
    @app.get("/support", include_in_schema=False)
    async def support_page():
        return Response(content=SUPPORT_PAGE, media_type="text/html; charset=utf-8")

    # --- OpenAI ChatGPT apps domain verification ----------------------------
    # The portal verifies control of this host by fetching the bare token as
    # plain text. The token is issued per plugin draft and supplied via the
    # OPENAI_APPS_CHALLENGE_TOKEN env var (set in Render once the draft
    # exists); 404 until then. The "/.well-known" prefix in EXEMPT_PREFIXES
    # keeps x402 from 402-challenging it.
    @app.get("/.well-known/openai-apps-challenge", include_in_schema=False)
    async def openai_apps_challenge():
        token = os.environ.get("OPENAI_APPS_CHALLENGE_TOKEN", "").strip()
        if not token:
            return Response(status_code=404, content="not found", media_type="text/plain")
        return Response(content=token, media_type="text/plain; charset=utf-8")

    # --- ChatGPT app review demo walkthrough video ---------------------------
    # Public, always free ("/demo-walkthrough.mp4" is in EXEMPT_PREFIXES in
    # x402.py): OpenAI reviewers fetch this URL (the plugin manifest's
    # review.demo_recording_url) during app review. The file ships inside
    # the image at /app/demo-walkthrough.mp4 (DEMO_VIDEO_PATH overrides);
    # 404 when absent so local/dev runs don't need it.
    @app.get("/demo-walkthrough.mp4", include_in_schema=False)
    async def demo_walkthrough():
        video_path = os.environ.get("DEMO_VIDEO_PATH", "/app/demo-walkthrough.mp4")
        if not os.path.isfile(video_path):
            return Response(status_code=404, content="not found", media_type="text/plain")
        return FileResponse(video_path, media_type="video/mp4", filename="demo-walkthrough.mp4")

    # Always-paid alias (2026-10-24): same handler as /convert/pdf, but
    # the middleware never free-tiers /paid/* — unpaid callers get the 402.
    @app.post("/paid/convert/pdf")
    @app.post("/convert/pdf")
    @limiter.limit(limit)
    async def convert_pdf(request: Request, file: UploadFile = File(...)):  # noqa: ANN001, ANN202, B008
        # H-4: chunked read with running cap — a single await file.read()
        # buffers an unbounded body into RAM when Content-Length is absent.
        data = await _read_upload_capped(file)
        return {"markdown": pdf_to_markdown(data)}

    @app.post("/convert/ocr")
    @limiter.limit(limit)
    async def convert_ocr(request: Request, file: UploadFile = File(...)):  # noqa: ANN001, ANN202, B008
        data = await _read_upload_capped(file)
        return {"text": ocr_image(data)}

    @app.post("/convert/spreadsheet")
    @limiter.limit(limit)
    async def convert_spreadsheet(request: Request, file: UploadFile = File(...)):  # noqa: ANN001, ANN202, B008
        data = await _read_upload_capped(file)
        return {"markdown": parse_spreadsheet(data, file.filename or "upload.csv")}

    @app.post("/convert/url")
    @limiter.limit(limit)
    async def convert_url(request: Request, body: UrlRequest):  # noqa: ANN001, ANN202
        # H-8: the SSRF-guarded fetch is blocking — off the event loop.
        return {"text": await asyncio.to_thread(_url_to_clean_text, body.url)}

    # --- Stripe billing (env-gated, OFF by default; exempt from x402) --------
    @app.post("/billing/checkout")
    @limiter.limit(limit)
    async def billing_checkout(request: Request):  # noqa: ANN001, ANN202
        if not stripe_effective_enabled():
            return JSONResponse(status_code=404, content={"error": "not_found"})
        if (
            not os.environ.get("STRIPE_SUCCESS_URL", "").strip()
            or not os.environ.get("STRIPE_CANCEL_URL", "").strip()
        ):
            log.error("STRIPE_SUCCESS_URL/CANCEL_URL not configured — checkout unavailable.")
            return JSONResponse(
                status_code=503,
                content={"error": "billing_not_configured"},
            )
        try:
            url = create_checkout_session()
        except Exception:  # noqa: BLE001 — Stripe API failure fails closed
            log.exception("Stripe checkout session creation failed")
            return JSONResponse(status_code=503, content={"error": "billing_unavailable"})
        return {"checkout_url": url}

    @app.post("/billing/stripe-webhook")
    async def stripe_webhook(request: Request):  # noqa: ANN001, ANN202
        if not stripe_effective_enabled():
            return JSONResponse(status_code=404, content={"error": "not_found"})
        # H-4-adjacent: Stripe events are a few KB; refuse absurd bodies
        # before buffering them.
        try:
            declared = int(request.headers.get("content-length", "0"))
        except ValueError:
            declared = 0
        if declared > 1024 * 1024:
            return JSONResponse(status_code=413, content={"error": "payload_too_large"})
        payload = await request.body()
        try:
            result = handle_stripe_webhook(payload, request.headers.get("stripe-signature"))
        except Exception:  # noqa: BLE001 — bad signature or malformed event
            return JSONResponse(status_code=400, content={"error": "invalid_signature"})
        return result

    @app.get("/billing/key")
    @limiter.limit(limit)
    async def billing_key(request: Request, session_id: str = ""):  # noqa: ANN001, ANN202
        if not stripe_effective_enabled():
            return JSONResponse(status_code=404, content={"error": "not_found"})
        if not session_id:
            return JSONResponse(status_code=400, content={"error": "missing_session_id"})
        try:
            key = issue_key_for_session(session_id)
        except LookupError as exc:
            return JSONResponse(
                status_code=404, content={"error": "session_not_found", "message": str(exc)}
            )
        except Exception:  # noqa: BLE001 — Stripe API failure fails closed
            log.exception("Subscriber key issuance failed")
            return JSONResponse(status_code=503, content={"error": "billing_unavailable"})
        return {"subscriber_key": key}

    @app.get("/billing/usage")
    async def billing_usage(request: Request):  # noqa: ANN001, ANN202
        """Current month's fair-use credit usage for a Pro subscriber.

        Authed by X-Subscriber-Key. FREE by design: /billing/* is exempt from
        the x402 middleware, and the middleware's subscriber-cap gate only runs
        on paid paths, so this endpoint is never 402'd and never 429-gated by
        the cap itself — reading usage never consumes credits.
        """
        raw_key = (request.headers.get("x-subscriber-key") or "").strip()
        if not subscriber_key_valid(raw_key):
            return JSONResponse(status_code=401, content={"error": "invalid_subscriber_key"})
        return get_subscriber_credit_usage(raw_key)

    @app.get("/billing/status")
    async def billing_status():
        return {
            "stripe_enabled": stripe_effective_enabled(),
            "x402_enabled": x402_effective_enabled(),
        }

    # MCP over streamable HTTP, mounted at /mcp (stateless: safe to mount).
    app.mount("/mcp", mcp_asgi)

    # Bare /mcp must not 307-redirect: serve the MCP app directly (see
    # _BareMcpAsgi). Appended after the mount; the mount's regex can't match
    # the bare path, so this route handles exactly "/mcp".
    app.router.routes.append(
        Route(
            "/mcp",
            _BareMcpAsgi(mcp_asgi),
            methods=["GET", "POST", "DELETE"],
            include_in_schema=False,
        )
    )

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "doc_convert_mcp.rest_app:app",
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8000")),
    )
