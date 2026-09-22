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

## x402 metering (USDC on Base)

Disabled by default. To enable:

```bash
export X402_ENABLED=true
export X402_PRICE_USDC="0.01"     # per-request price
export X402_PAY_TO="0xYourAddress"
```

Paid paths (`/convert/*`, `POST /mcp/`) then require an `X-Payment` header
with a signed payment payload; missing/invalid payment gets a `402` with
payment instructions. `/health` and docs stay free.

> **Stub warning:** the bundled verifier checks payload structure only —
> it does **not** verify payments on-chain. Replace `verify_payment_stub`
> with facilitator-backed EIP-3009 verification before production use.
> The server logs a warning at startup while the stub is active.

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
