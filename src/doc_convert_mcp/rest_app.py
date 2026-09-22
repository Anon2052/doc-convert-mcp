"""Combined ASGI app: REST API + FastMCP (streamable HTTP) + /health.

Run with:  uvicorn doc_convert_mcp.rest_app:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from . import __version__
from .converters import ConversionError, ocr_image, parse_spreadsheet, pdf_to_markdown
from .converters import url_to_clean_text as _url_to_clean_text
from .mcp_server import mcp
from .x402 import X402PaymentMiddleware, warn_if_stub_enabled

log = logging.getLogger("doc_convert_mcp")

DEFAULT_RATE_LIMIT = os.environ.get("RATE_LIMIT", "60/minute")


class UrlRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


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
    warn_if_stub_enabled()
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
            "x402": os.environ.get("X402_ENABLED", "false"),
        }

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

    # MCP over streamable HTTP, mounted at /mcp (stateless: safe to mount).
    app.mount("/mcp", mcp_asgi)

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "doc_convert_mcp.rest_app:app",
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8000")),
    )
