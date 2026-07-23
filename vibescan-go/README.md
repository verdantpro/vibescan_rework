# vibescan-go

A Go reimplementation of the VibeScan backend, ported incrementally from the
Python app in `../vibescan_v2`. It reuses the existing MongoDB / object-storage
data so Go and Python services can run side-by-side against the same store
during migration.

The production binary serves **ingest + v2 read APIs + the embedded React UI**
from one process (same origin in prod — no CORS required).

## Status

| Component | State |
|-----------|-------|
| **Collector** (ingest API) | implemented |
| **v2 read APIs** (gallery, search, stats, detail, media) | implemented |
| **Embedded UI + deploy packaging** (Docker/Caddy, indexes, ECR) | implemented |
| **Agent** (nmap + Chromium capture, `cmd/agent`) | implemented (RDAP ownership + web ports) |
| Interactions (votes, tags, favorites, auth) | next |
| Workers (rollups, network/world map, SSE live) | later |

## Architecture

```
┌─────────────┐  v1 signed envelope   ┌──────────────────────────┐
│  Go agent   │ ────────────────────▶ │  collector (cmd)         │
│  nmap+CDP   │  ◀── blacklist ────── │  + v2 JSON APIs          │
└─────────────┘                       │  + embedded vibescan-ui  │
                                      └───────────┬──────────────┘
                              ┌───────────────────┼───────────────────┐
                              ▼                   ▼                   ▼
                           MongoDB            S3 / R2              GeoLite2
                           (results)         (captures)            (optional)
```

Wire protocol for agents is the **legacy v1** envelope (HMAC-SHA256 + gzip +
base64), so existing Python agents keep working while the Go agent is primary.

## Deploy

Target stack: **AWS EC2 t3.micro** (image pulled from **ECR**) + **MongoDB Atlas
M0** + **S3/CloudFront**, behind **Caddy**, with the **Go agent** on a separate
scanner host.

**Full step-by-step runbook: [`deploy/DEPLOY.md`](deploy/DEPLOY.md).**

Two web-host modes live under `deploy/`:

- **Build elsewhere, pull on the server** (small hosts like the EC2 t3.micro) —
  `docker-compose.registry.yml` + `build-push.sh` (cross-builds `linux/amd64`
  and pushes to Amazon ECR). This is the path documented end-to-end in the
  runbook.
- **Build on the server** (≥2 GB RAM) — `docker-compose.yml`:

  ```bash
  cd deploy
  cp .env.example .env          # fill Mongo / S3 / domain / shared key
  docker compose build
  docker compose run --rm --entrypoint migrate app   # indexes first
  docker compose up -d
  ```

The multi-stage `Dockerfile` builds the UI, embeds it into the binary, and
produces a small Alpine image (~60 MB) containing:

| Binary | Role |
|--------|------|
| `vibescan` | default entrypoint — collector + APIs + UI |
| `migrate` | one-shot indexes + CIDR blacklist seed |

`internal/web/dist/` is **generated** by the UI build (`vibescan-ui`,
`VITE_API_BASE=""`); a placeholder ships so the module always builds. Indexes
are created on startup and via `cmd/migrate` (`internal/store/indexes.go`).

The plan is a **strangler** migration: the Go collector speaks the exact legacy
v1 wire protocol, so agents keep submitting unchanged while components cut over
one at a time.

## Collector

`cmd/collector` is a drop-in replacement for `vibescan_v2/server.py`. It serves:

| Route | Purpose |
|-------|---------|
| `POST /api/v1/results` | signed, gzip+base64 submission envelope (legacy v1) |
| `GET  /api/v1/blacklist` | enabled CIDR blacklist (agents cache ~hourly) |
| `GET  /api/health`, `GET /api/healthz` | health probes |
| `GET  /api/v2/*` | read APIs (below) |
| `/*` | embedded SPA (client-side routes fall back to `index.html`) |

### Wire & data compatibility

Verified byte-for-byte against the Python implementation via golden tests
(`internal/transport`, `internal/media`):

- HMAC-SHA256 signing, gzip, base64 envelope (`common/transport.py`)
- Capture hash/ext, DOM-structure hash, pHash chunking
- Deterministic `_id = ObjectId(md5("ip:port")[:24])`, so upserts collide
  correctly with documents written by the Python collector
- Per-service document schema, GeoIP enrichment, `landing_image`, object-storage
  `r2:<key>` references, and disk buffering when MongoDB is unavailable

### Intentional deviations from `server.py`

- **No artificial sleep** before each bulk write.
- **Disk buffer uses BSON files** (not JSON) to preserve BSON date types exactly.
- Object-storage uploads for a submission are finalized in one bounded-concurrency
  pass before persistence (slightly higher orphaned-object risk on a mid-submission
  crash; functionally equivalent otherwise).
- **`no_report` / `anon` redacts `submitted_by`** to `0.0.0.0` at ingest (and the
  public detail API re-redacts if `anon` is set). Python still stores the real
  client IP under `submitted_by` even when anonymized.

### Run locally

```bash
# Config via environment or a .env file (same variables as vibescan_v2 / deploy/.env.example).
export MONGO_URI="mongodb://localhost:27017"
export VIBESCAN_SHARED_KEY="dev-key"
export GEOLITE2_CITY_MMDB=../vibescan_v2/GeoLite2-City.mmdb   # optional
go run ./cmd/collector    # listens on :8000 (override with PORT)
```

MongoDB is optional at startup: if it’s unreachable the collector still serves
and spools accepted submissions to `cache/server_buffer/`, flushing once the
database recovers. Object storage accepts **`S3_*` (AWS) or `R2_*` (Cloudflare)**
env names interchangeably.

### Test

```bash
go test ./...
go build ./...
```

## v2 read APIs

Clean JSON endpoints for the UI (all under `/api/v2`, CORS `*`, same process as
the collector). Keyed by `ip/port` rather than Mongo `_id`.

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v2/gallery?limit=&offset=&with_screenshots_only=` | Recent captured services as tiles |
| `GET /api/v2/search?q=&port=&status=&secured=&product=&limit=&offset=` | Filtered / free-text search |
| `GET /api/v2/services/{ip}/{port}` | Single service detail (incl. `fulltext`) |
| `GET /api/v2/stats?time_range=<hours>` | Windowed aggregate snapshot (one `$facet` pass, 60s cached) |
| `GET /api/v2/random-capture` | One random landing-page tile (`$sample`) |
| `GET /api/v2/image/{ip}/{port}` | Serves base64 captures; 302-redirects to object storage for `r2:` refs |

A gallery/search **tile** carries `ip, port, banner, product, http_status,
secured, whois, image_url, capture_hash/ext, has_fulltext, screenshot_phash,
dom_hash, cert_cn, updated_at, geo`. `image_url` resolves to the object-storage
public URL (S3/CloudFront or R2) when configured, otherwise `/api/v2/image/...`.

### Deferred (intentionally) in the read layer

- **Stats are computed live** over the requested window (bounded `$facet` +
  `maxTimeMS` + 60s cache), not from Redis/hourly rollups.
- **Search is Mongo regex + filters**, not Atlas Search / Online Archive.
- Votes, tags, favorites, auth, and live SSE streams are not in this layer yet.

## Agent

`cmd/agent` is the Go port of `vibescan_v2/client_agent.py`: random IPv4 batches
→ nmap → optional Chromium capture → signed submit.

```bash
export VIBESCAN_SERVER_URL=http://127.0.0.1:8000
export VIBESCAN_SHARED_KEY=dev-key
export VIBESCAN_PORTS=80,443,8000,8080,8443
go run ./cmd/agent
```

Production packaging: `Dockerfile.agent` + `deploy/docker-compose.agent.yml` +
`deploy/agent.env.example`. See **§7 of [`deploy/DEPLOY.md`](deploy/DEPLOY.md)**.

| Env | Default | Notes |
|-----|---------|--------|
| `VIBESCAN_SERVER_URL` | _(required)_ | Collector base URL, no path |
| `VIBESCAN_SHARED_KEY` | `vibescan-default-key` | Must match collector |
| `VIBESCAN_PORTS` | `80,443,8000,8080,8443` | CSV web ports |
| `VIBESCAN_NMAP_OPTIONS` | `-n -T3` | Prefer `-T2` in production examples |
| `VIBESCAN_SCAN_THREADS` | `2` | Concurrent host record builds |
| `VIBESCAN_BATCH_SIZE` | `10` | Random IPs per nmap batch |
| `VIBESCAN_BROWSER_CONCURRENCY` | `2` | Concurrent Chromium captures |
| `VIBESCAN_CAPTURE_HTTP` | `1` | `0` = discover-only |
| `VIBESCAN_NO_REPORT` | off | Redact `submitted_by` (→ `0.0.0.0`) + set `anon` |
| `VIBESCAN_RDAP` | `1` | RDAP ownership lookup (cached /24) |
## Layout

```
cmd/collector        entrypoint (ingest + v2 APIs + embedded UI)
cmd/agent            scanner: nmap discovery + Chromium capture + submit
cmd/migrate          one-shot: create MongoDB indexes + seed blacklist
internal/config      env / .env loading (S3_* and R2_* aliases)
internal/transport   v1 signed-envelope encode/decode (+ golden tests)
internal/media       capture / DOM / pHash hashing (+ golden tests)
internal/geo         IPv4 normalization, GeoIP lookup
internal/store       MongoDB upserts/reads/indexes, object storage, disk buffer, blacklist
internal/collector   ingest pipeline + blacklist cache
internal/scanner     agent loop, nmap, Chromium, collector client
internal/httpapi     HTTP routing/handlers (API + SPA)
internal/web         embedded UI (dist/ generated by vibescan-ui)
Dockerfile           multi-stage build (UI → embed → Go → slim runtime)
Dockerfile.agent     agent image (nmap + Chromium + agent binary)
deploy/              compose (build / registry / agent), Caddyfile,
                     .env.example, agent.env.example, build-push.sh, DEPLOY.md
```

## Related trees

| Path | Role |
|------|------|
| `../vibescan-ui` | React/Vite frontend (embedded into the Go image in production) |
| `../vibescan_v2` | Legacy Python stack (reference + dual-run) |
