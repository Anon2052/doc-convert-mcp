# Deploying doc-convert-mcp

The service is a single stateless container: FastAPI REST + FastMCP (streamable HTTP at `/mcp`) + `/health`. Any host that runs a Dockerfile works.

## Recommendation: Render

**One-liner:** $7/mo flat for an always-on 512 MB container with Dockerfile support, free custom domain + automatic TLS, and GitHub auto-deploys — the cheapest predictable option for this workload.

## Comparison (verified Sept 2026)

| | Railway | Render | Fly.io |
|---|---|---|---|
| Always-on cost (1 small svc) | ~$10–15/mo: Hobby $5 minimum + metered compute (~$20/vCPU-mo, ~$10/GB RAM-mo, $0.05/GB egress) | **$7/mo** Starter (0.5 CPU / 512 MB), flat, prorated per second | ~$7–8/mo (shared-cpu-1x, 1 GB, billed per second) |
| Free tier | Trial: $5 credit for 30 days, then $1/mo credit — not prod-viable | $0 (512 MB, spins down after inactivity — fine for staging) | New accounts get a small credit; check current terms |
| Dockerfile support | Yes | Yes (BuildKit, zero-downtime deploys) | Yes (`fly deploy`) |
| Custom domain + TLS | Yes | Yes, free, automatic | Yes |
| Deploy friction | Lowest (dashboard / `git push`) | Low (dashboard or `render.yaml` blueprint — included in repo) | Medium (CLI-driven) |
| Watch out | Metered billing has no ceiling until you set replica limits | 512 MB is tight if OCR jobs spike; next tier is $25/mo (1 CPU / 2 GB) | Per-second billing; volumes cost extra if you add disk |

Runner-up: **Fly.io** if you later want multi-region (35+ regions) or finer cost control; **Railway** if you want the absolute lowest-friction dashboard and don't mind metered billing.

## Environment variables

| Var | Default | Notes |
|---|---|---|
| `PORT` | `8000` | Injected automatically by Railway/Render/Fly — do not set manually |
| `HOST` | `0.0.0.0` | |
| `X402_ENABLED` | `false` | **Leave off.** On-chain payment verification is a structural stub, not prod-ready |
| `RATE_LIMIT` | `60/minute` | e.g. `600/hour` |
| `X402_PRICE_USDC` / `X402_PAY_TO` | unset | Only relevant when x402 verification is real |

No secrets are required to run the service. Nothing is hardcoded in the image.

## Deploy steps

### Render (recommended)
1. Sign in at render.com → **New → Web Service**.
2. Connect the `Anon2052/doc-convert-mcp` repo.
3. Runtime: **Docker**. Dockerfile path: `./Dockerfile` (auto-detected). Health check path: `/health`.
4. Pick the **Starter** ($7/mo) instance. Leave `X402_ENABLED` unset/false.
5. **Create Web Service** — deploys on every push to `main`.
6. Custom domain: **Settings → Custom Domains** (free, TLS automatic).

Or one-click via blueprint: `render.yaml` is in the repo root — **New → Blueprint** and point at the repo.

### Railway
1. railway.app → **New Project → Deploy from GitHub** → select the repo.
2. Railway auto-detects the Dockerfile. It injects `PORT` itself — the container reads it.
3. **Settings → Networking → Generate Domain** (or add a custom domain).
4. Hobby plan ($5/mo minimum + usage) required for always-on.

### Fly.io
```bash
fly launch          # Dockerfile auto-detected; accept the defaults
fly deploy          # builds and ships the image
fly secrets set X402_ENABLED=false   # optional; default is already false
```
`fly.toml` is generated for you. Custom domain: `fly certs add <yourdomain>`.

## Local verification

```bash
docker build -t doc-convert-mcp:prod .
docker run --rm -p 8000:8000 doc-convert-mcp:prod
curl localhost:8000/health   # -> {"status":"ok", ...}
```
