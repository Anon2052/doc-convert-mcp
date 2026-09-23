"""Combined ASGI app: REST API + FastMCP (streamable HTTP) + /health.

Run with:  uvicorn doc_convert_mcp.rest_app:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
import os
import secrets

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.responses import Response
from starlette.routing import Route

from . import __version__
from .billing import (
    create_checkout_session,
    get_subscriber_credit_usage,
    get_usage_stats,
    handle_stripe_webhook,
    issue_key_for_session,
    stripe_effective_enabled,
    subscriber_key_valid,
)
from .converters import ConversionError, ocr_image, parse_spreadsheet, pdf_to_markdown
from .converters import url_to_clean_text as _url_to_clean_text
from .legal_docs import PRIVACY_POLICY, REFUND_POLICY, TERMS_OF_SERVICE
from .mcp_server import mcp
from .x402 import X402PaymentMiddleware, warn_if_payments_misconfigured, x402_effective_enabled

log = logging.getLogger("doc_convert_mcp")

DEFAULT_RATE_LIMIT = os.environ.get("RATE_LIMIT", "60/minute")


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
    app = FastAPI(
        title="doc-convert-mcp",
        version=__version__,
        description="Document conversion API: PDF to Markdown, OCR, spreadsheets, URL to text.",
        lifespan=mcp_asgi.lifespan,
    )

    # x402 metering (env-gated, OFF by default) runs outermost.
    warn_if_payments_misconfigured()
    app.add_middleware(X402PaymentMiddleware)

    limiter = Limiter(key_func=get_remote_address)

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

    limit = rate_limit or DEFAULT_RATE_LIMIT

    @app.get("/health")
    async def health():
        return {
            "status": "ok",
            "version": __version__,
            "x402": "enabled" if x402_effective_enabled() else "disabled",
            "stripe": "enabled" if stripe_effective_enabled() else "disabled",
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

    @app.post("/convert/pdf")
    @limiter.limit(limit)
    async def convert_pdf(request: Request, file: UploadFile = File(...)):  # noqa: ANN001, ANN202, B008
        data = await file.read()
        return {"markdown": pdf_to_markdown(data)}

    @app.post("/convert/ocr")
    @limiter.limit(limit)
    async def convert_ocr(request: Request, file: UploadFile = File(...)):  # noqa: ANN001, ANN202, B008
        data = await file.read()
        return {"text": ocr_image(data)}

    @app.post("/convert/spreadsheet")
    @limiter.limit(limit)
    async def convert_spreadsheet(request: Request, file: UploadFile = File(...)):  # noqa: ANN001, ANN202, B008
        data = await file.read()
        return {"markdown": parse_spreadsheet(data, file.filename or "upload.csv")}

    @app.post("/convert/url")
    @limiter.limit(limit)
    async def convert_url(request: Request, body: UrlRequest):  # noqa: ANN001, ANN202
        return {"text": _url_to_clean_text(body.url)}

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

    # --- Usage analytics (admin only) --------------------------------------
    @app.get("/billing/stats")
    async def billing_stats(request: Request, days: int = 30):  # noqa: ANN001, ANN202
        """Per-day usage aggregates + totals for the last ``days`` UTC days.

        Authed by the ``ADMIN_KEY`` shared secret (``X-Admin-Key`` header or
        ``?admin_key=`` query param). Always free: ``/billing/*`` is exempt
        from the x402 middleware and this route has no rate limiter, so
        reading stats never consumes quota. 401 when the key is missing or
        mismatched — and also when ``ADMIN_KEY`` isn't configured at all
        (fail closed).
        """
        expected = os.environ.get("ADMIN_KEY", "")
        provided = request.headers.get("x-admin-key") or request.query_params.get("admin_key") or ""
        if not expected or not secrets.compare_digest(provided, expected):
            return JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "message": "Valid X-Admin-Key header or admin_key query param required.",
                },
            )
        clamped = max(1, min(days, 365))
        return get_usage_stats(clamped)

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
