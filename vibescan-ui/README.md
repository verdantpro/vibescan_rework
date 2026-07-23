# vibescan-ui

**vibescan** frontend — recon console for HTTP/HTTPS discovery. React + TypeScript
(Vite), talking to the Go v2 read APIs.

In production the built `dist/` is **embedded** into the `vibescan-go` collector
binary (see `vibescan-go/Dockerfile` and `vibescan-go/internal/web`) and served
same-origin with the API.

## Concept

**"Field Record"** — an OSINT/evidence-board treatment of the census: each host
is presented like a case file. Palette is the Verdant Protocol green (`#2f6f4f`
family, lifted for the dark ground) on a warm slate, with red reserved as a
semantic signal for cleartext/no-TLS. Type pairs an editorial serif for
statements (Iowan Old Style / Palatino / Georgia stack) with JetBrains Mono for
all telemetry/data, and Sora for running body copy. The signature is the
**capture-as-exhibit** treatment (screenshot pinned with registration ticks +
mono field notes) and the **live acquisition viewport** paired with a **world
map** of GeoIP origins. `HTTPS` reads green (secured), `HTTP` red (cleartext).

Design tokens live on `:root` in `src/theme.css`.

## Routes

| Path | Screen |
|------|--------|
| `/` | **Live** — acquisition viewport + latest/recent rails + world map + headline |
| `/feed` | **Feed** — captured services, `ranked` (curated) or `latest` (recency) |
| `/search` | **Search** — query + port/status/protocol filters, `$text`-backed |
| `/stats` | **Stats** — telemetry dashboard (ports, status, servers, over-time) |
| `/signal/:ip/:port` | **Signal** — the case file: exhibit + field notes + banner + page source |
| `/about` | **About** — how it works, scope, and the opt-out / takedown / abuse posture |

A global footer (About & ethics · opt-out contact) is present on every page.

## Run

Needs the Go collector serving the v2 API. The collector defaults to
**`http://127.0.0.1:8000`** (`PORT` env). Point the UI at it with `VITE_API_BASE`
(see `.env.example`).

```bash
# Terminal 1 — from vibescan-go/
go run ./cmd/collector          # :8000

# Terminal 2 — from vibescan-ui/
npm install
cp .env.example .env            # VITE_API_BASE=http://127.0.0.1:8000 recommended
npm run dev                     # http://localhost:5173
npm run build                   # typecheck + production bundle → dist/
```

The Go API sends `Access-Control-Allow-Origin: *`, so the Vite dev server on a
different port works out of the box. `VITE_API_BASE` defaults to
`http://127.0.0.1:8000` in dev and `""` (same-origin) in a production build, so
the embedded app uses relative URLs even without an env file.

## Notes

- `src/api.ts` is the single typed client; relative `image_url`s are resolved
  against `VITE_API_BASE`. Failed calls throw a typed `ApiError` with an
  `offline` flag (honoring the collector's `503 {offline:true}`), so pages show a
  retryable "couldn't reach the collector" state (`components/ErrorState`) rather
  than a false "no results".
- The world map projects `public/world-110m.json` (from `world-atlas`) with
  `d3-geo`; points come from recent gallery entries' GeoIP (collector needs
  `GeoLite2-City.mmdb` for coordinates).
- Charts are hand-rolled to match the theme (single-hue for magnitude, reserved
  status colors for response codes).
- The `/about` page states the moderation / opt-out / takedown posture and points
  to the abuse contact; keep it in sync with what the collector actually enforces
  (e.g. the agent CIDR blacklist).
- Deploy of the combined stack: **[`../vibescan-go/deploy/DEPLOY.md`](../vibescan-go/deploy/DEPLOY.md)**.
