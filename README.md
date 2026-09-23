# doc-convert-mcp

Document conversion as an MCP server (streamable HTTP) plus a thin REST API.
Built for AI agents — and Muse in particular — that need to turn messy files
into clean text: PDFs to Markdown, images to text (OCR), spreadsheets to
Markdown tables, and web pages to clean text.

Monetization hook: per-request metering via **x402 USDC micropayments on Base**
(env-gated, off by default).

## Tools

| Tool | Input | Output |
|---|---|---|
| `pdf_to_markdown` | PDF bytes (base64), `max_pages` | Markdown, one `## Page N` section per page |
| `ocr_image` | Image bytes (base64), `lang` | Recognized text (Tesseract) |
| `parse_spreadsheet` | CSV/XLSX bytes (base64), `filename` | Markdown tables, one section per sheet |
| `url_to_clean_text` | Public `http(s)` URL | Main text content, markup stripped |

Limits: 25 MB per input file, 100 PDF pages, 5000 spreadsheet rows.
`url_to_clean_text` rejects private/loopback/link-local IPs (SSRF guard).

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# OCR needs the tesseract binary:  sudo apt install tesseract-ocr
uvicorn doc_convert_mcp.rest_app:app --host 0.0.0.0 --port 8000
```

- REST: `POST http://localhost:8000/convert/pdf` (multipart `file`)
- MCP (streamable HTTP): `POST http://localhost:8000/mcp/`
- Health: `GET http://localhost:8000/health`

## Connecting from Muse

Point Muse at the hosted MCP endpoint (`https://<your-domain>/mcp/`).
Muse builds the integration on its VM and stores your credentials in its
Secure Credentials Store. Example tool call once connected:

```json
{
  "tool": "pdf_to_markdown",
  "arguments": {
    "pdf_base64": "<base64 of the PDF>",
    "max_pages": 20
  }
}
```

```json
{
  "tool": "ocr_image",
  "arguments": { "image_base64": "<base64 of the PNG/JPG>", "lang": "eng" }
}
```

```json
{
  "tool": "parse_spreadsheet",
  "arguments": { "file_base64": "<base64 of .csv/.xlsx>", "filename": "q3.xlsx" }
}
```

```json
{
  "tool": "url_to_clean_text",
  "arguments": { "url": "https://example.com/article" }
}
```

## REST API

```bash
# PDF -> Markdown
curl -X POST http://localhost:8000/convert/pdf \
  -F "file=@report.pdf" | jq .markdown

# OCR
curl -X POST http://localhost:8000/convert/ocr \
  -F "file=@scan.png" | jq .text

# Spreadsheet -> Markdown tables
curl -X POST http://localhost:8000/convert/spreadsheet \
  -F "file=@data.xlsx" | jq .markdown

# URL -> clean text
curl -X POST http://localhost:8000/convert/url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com/article"}' | jq .text
```

Rate limiting: 60 requests/minute per IP on conversion endpoints
(override with `RATE_LIMIT`, e.g. `RATE_LIMIT="600/hour"`).
`/health` is never rate-limited.

## x402 metering (USDC on Base) — real verification

Disabled by default. When enabled, paid paths (`/convert/*`, `POST /mcp`
tool calls) require an `X-Payment` header carrying a base64-encoded x402 v1
payment payload with a signed EIP-3009 USDC authorization on Base. The server
verifies with an x402 facilitator (`/verify`), serves the request, then
settles (`/settle`). Missing/invalid payment gets a `402` with a
`paymentRequirements` object (asset = Circle's canonical Base USDC
`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA38bD`). `/health`, docs, `/billing/*`,
and MCP discovery (`GET /mcp`, `initialize`, `tools/list`, `ping`) stay free.

```bash
export X402_ENABLED=true
export X402_PAY_TO="0xYourAddress"          # receives the USDC
# X402_FACILITATOR_URL defaults to https://x402.org/facilitator
#   (Base Sepolia TESTNET only — not mainnet)
```

Facilitator auth: set `X402_FACILITATOR_API_KEY` (sent as `X-API-Key`), or
`CDP_API_KEY_ID` + `CDP_API_KEY_SECRET` for the Coinbase CDP mainnet
facilitator (`https://api.cdp.coinbase.com/platform/v2/x402`), which mints a
CDP EdDSA JWT per request. Neither set = unauthenticated (works for the
x402.org testnet facilitator).

### Per-tool pricing (USDC)

| Tool | Default price | Env override |
|---|---|---|
| `pdf_to_markdown` | $0.03 | `X402_PRICE_PDF_TO_MARKDOWN_USDC` |
| `ocr_image` | $0.02 | `X402_PRICE_OCR_IMAGE_USDC` |
| `parse_spreadsheet` | $0.02 | `X402_PRICE_PARSE_SPREADSHEET_USDC` |
| `url_to_clean_text` | $0.01 | `X402_PRICE_URL_TO_CLEAN_TEXT_USDC` |
| anything else | $0.015 | `X402_PRICE_USDC` |

> **Pricing is a business decision — adjust before enabling.** Invalid or
> non-positive price values fall back to the default (never zero).

### Stripe monthly plans (subscriber bypass)

Also off by default. A Stripe subscription issues a subscriber key that
bypasses per-call x402 charges (send as `X-Subscriber-Key` header). Only the
SHA-256 hash of each key is stored (SQLite, `BILLING_DB_PATH`, default
`/var/lib/doc-convert-mcp/billing.db` — the Render persistent disk mount; set
`BILLING_DB_PATH=./data/subscribers.db` for local dev).

```bash
export STRIPE_ENABLED=true
export STRIPE_SECRET_KEY="sk_live_..."        # from Stripe dashboard (server-side only)
export STRIPE_WEBHOOK_SECRET="whsec_..."      # webhook signing secret
export STRIPE_PRICE_ID="price_..."            # monthly plan price you create
export STRIPE_SUCCESS_URL="https://your.app/billing/success"
export STRIPE_CANCEL_URL="https://your.app/billing/cancel"
```

Endpoints: `POST /billing/checkout` → `{"checkout_url": ...}`;
`POST /billing/stripe-webhook` (Stripe calls this);
`GET /billing/key?session_id=...` → `{"subscriber_key": ...}` (shown once);
`GET /billing/status` → `{"stripe_enabled": bool, "x402_enabled": bool}`.

**Fair-use cap (Pro).** Subscriber-key auth is capped at
`SUBSCRIBER_MONTHLY_CREDIT_LIMIT` credits per UTC calendar month (default
`1000` — i.e. **$10 of API calls included with the $9/mo plan**; Scott's
call). 1 credit = $0.01 of x402 list price, so an expensive tool costs more
credits than a cheap one. The counter is per subscriber-key hash in the same
SQLite DB and resets automatically at the month boundary. Over the cap,
subscriber-key requests get **HTTP 429** with the cap, current credit usage, the
period, the reset date (first of next month UTC), and a note that per-call
x402 payment still works (resend without `X-Subscriber-Key` + an `X-Payment`
header). The cap applies to subscriber-key auth only — plain x402 payers are
never capped. `GET /billing/usage` (authed by `X-Subscriber-Key`) reports
current credit usage and is always free — it's exempt from both x402 charges
and the cap.

Safety rails: both systems require their full config or they stay **disabled**
(fail closed) with an ERROR at startup. If x402 is live the server logs a
warning naming real USDC charges. No secrets ever appear in code, logs, or
error responses.

> **Before enabling on mainnet:** form the AZ LLC, point
> `X402_FACILITATOR_URL` at the CDP facilitator with CDP keys, and smoke-test
> the CDP JWT claim set against the live facilitator.

## Development

```bash
pip install -r requirements-dev.txt
ruff check src tests && ruff format --check src tests
python -m pytest -q
pip-audit -r requirements.txt
```

CI (GitHub Actions) runs secrets scan → ruff → pytest → pip-audit on every PR.

## Security model

- All dependencies pinned with hashes (`requirements.txt` via pip-tools);
  installed from wheels only (no `setup.py` execution).
- `pip-audit` gate: zero critical/high CVEs.
- Branch protection: PR review required, no force pushes, secret scanning +
  push protection, Dependabot alerts/updates.
- URL fetcher has an SSRF guard (no private/loopback/metadata IPs).
- Never commit secrets — push protection is the backstop, not the plan.
