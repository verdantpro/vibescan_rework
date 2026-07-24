# VibeScan · Live Cleartext HTTP Acquisition

A distributed internet-observation platform built with **Go** and **React**:
authenticated scanner agents, HTTP capture, threat-intelligence enrichment,
search, telemetry, and ethical opt-out controls.

**Live demo:** https://vibescan.verdantprotocol.com &nbsp;·&nbsp;
**Ethics & opt-out:** https://vibescan.verdantprotocol.com/about

> *"VibeScan" is an operational internet-measurement instrument — distinct from the
> AI-code-scanning tools of the same name.*

<!-- Add a hero screenshot at docs/screenshot.png, then uncomment:
![VibeScan console](docs/screenshot.png)
-->

## The problem

What does the ordinary, reachable web look like when you stop searching for known
domains and sample public IPv4 space instead? Answering that responsibly takes more
than running nmap. VibeScan is a continuously operating census of randomly discovered
public web services: it limits itself to common web ports, captures what an anonymous
browser can see, stores point-in-time records, enriches them with public security data,
and provides a human opt-out and takedown process.

This repository is the **Go reimplementation** of an earlier Python prototype, migrated
via a **strangler** strategy — the Go collector speaks the exact legacy v1 wire protocol,
so existing agents keep submitting unchanged while components cut over one at a time.

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

Scanner agent → HMAC-SHA256 signed + gzipped envelope → collector → MongoDB /
object storage → concurrent threat-intel enrichment → embedded React UI.

## Key technical decisions

- **Strangler migration** — the Go collector is byte-for-byte wire-compatible with the
  Python stack (verified by golden tests), so old and new agents coexist on one datastore.
- **One binary, same origin in prod** — ingest + v2 read APIs + the React UI are served
  from a single process; the UI is embedded via `go:embed` in a multi-stage image (~60 MB).
- **Designed for failure** — disk buffering (BSON) when MongoDB is unavailable, deterministic
  `_id` so upserts collide correctly, bounded-concurrency enrichment, per-client rate limits.
- **Rendering hostile pages safely** — captures run in a containerized headless Chromium on a
  separate scanner host, isolated from the collector.
- **Enrichment without leaking keys** — server-side fan-out across InternetDB/Shodan and
  threat feeds (VirusTotal, AbuseIPDB, GreyNoise, OTX, ThreatFox, …); API keys never reach
  the browser, results are cached and throttled.
- **Deploy without inbound SSH** — image → ECR → EC2 rolled via AWS SSM.

## Security & ethics

VibeScan only observes what an anonymous visitor could already see. It does **not** sign in,
submit credentials, exploit/fuzz, probe non-web services, or scan ports exhaustively. Scanning
runs continuously at a deliberately slow rate, every agent honors a CIDR exclusion list, and the
agent's own source IP is anonymized in each record. Third-party reputation/threat verdicts are
the vendors' and may be wrong. A human monitors the abuse address for opt-out, takedown, and
abuse reports. Full policy: [`/about`](https://vibescan.verdantprotocol.com/about).

## Repository layout

| Path | Role |
|------|------|
| [`vibescan-go/`](vibescan-go/) | Collector, v2 APIs, scanner agent, migrate, Docker/Caddy deploy — [README](vibescan-go/README.md) |
| [`vibescan-ui/`](vibescan-ui/) | React/Vite console (embedded into the Go image in prod) — [README](vibescan-ui/README.md) |

The legacy Python app (`vibescan_v2`) is a separate Git remote kept for dual-run / reference
and is **not** part of this repo.

## Local development

```bash
# Backend collector (listens on :8000)
cd vibescan-go
export MONGO_URI="mongodb://localhost:27017"
export VIBESCAN_SHARED_KEY="dev-key"
go run ./cmd/collector

# Frontend (dev server, proxies to the collector)
cd vibescan-ui
npm install
npm run dev
```

MongoDB is optional at startup — the collector spools accepted submissions to disk and flushes
once the database recovers. See [`vibescan-go/README.md`](vibescan-go/README.md) for the agent,
enrichment, and full v2 API reference.

## Test & deploy

```bash
# Backend
cd vibescan-go && go vet ./... && go test ./...

# Frontend
cd vibescan-ui && npm run lint && npm run build
```

**Deploy:** push to `main` runs [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml)
(build → ECR → **SSM** roll EC2, no open SSH). Full runbook:
[`vibescan-go/deploy/DEPLOY.md`](vibescan-go/deploy/DEPLOY.md).

## Known limitations

- Stats are computed live per request (bounded `$facet` + 60s cache), not from rollups.
- Search uses a MongoDB `$text` index, not Atlas Search.
- Threat/reputation verdicts come from third-party feeds and can be inaccurate.
- Interactions (votes, tags, favorites, auth) and live SSE streaming are not yet in this layer.

## License

Source-available for evaluation and portfolio review only — **not** open source and **not**
licensed for reuse. See [`LICENSE`](LICENSE).

---

<!-- Maintainer checklist (GitHub UI — not versioned):
  • Set repo Description: "A distributed internet-observation platform built with Go and React:
    authenticated scanner agents, HTTP capture, threat-intelligence enrichment, search, telemetry
    and ethical opt-out controls."
  • Add Topics: golang, react, cybersecurity, internet-scanner, threat-intelligence, mongodb, aws,
    data-visualization
  • Add docs/screenshot.png and uncomment the hero image above.
  • Add a 1200×630 social preview at vibescan-ui/public/og.png (referenced by the
    Open Graph / Twitter tags in index.html and src/lib/meta.ts).
-->
