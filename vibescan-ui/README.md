# vibescan-ui

**vibescan** frontend — recon console for HTTP/HTTPS discovery. React + TypeScript
(Vite), talking to the Go v2 read APIs.

In production the built `dist/` is **embedded** into the `vibescan-go` collector
binary (see `vibescan-go/Dockerfile` and `vibescan-go/internal/web`) and served
same-origin with the API.

## Concept

An ops-deck that "acquires" random exposed machines and maps where signals
originate. Palette is CRT-free plasma: cyan (live) + violet + red (insecure) on a
blue-black void. Type: Chakra Petch (display) · Sora (body) · JetBrains Mono
(telemetry). The signature is the **acquisition viewport** (scanning HUD +
telemetry readout) paired with a **world map** of live GeoIP origins.

## Routes

| Path | Screen |
|------|--------|
| `/` | **Live** — acquisition viewport + world map + headline |
| `/feed` | **Feed** — recent captured services (gallery) |
| `/search` | **Search** — query + port/status/protocol filters |
| `/stats` | **Stats** — telemetry dashboard (ports, status, servers, over-time) |
| `/signal/:ip/:port` | **Signal** — full capture + record + banner + page source |

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
different port works out of the box. Production builds set `VITE_API_BASE=""` so
the browser uses same-origin relative URLs inside the embedded app.

## Notes

- `src/api.ts` is the single typed client; relative `image_url`s are resolved
  against `VITE_API_BASE`.
- The world map projects `public/world-110m.json` (from `world-atlas`) with
  `d3-geo`; points come from recent gallery entries' GeoIP (collector needs
  `GeoLite2-City.mmdb` for coordinates).
- Thumbs up/down on the viewport are stubbed until the votes API lands.
- Charts are hand-rolled to match the theme (single-hue for magnitude, reserved
  status colors for response codes).
- Deploy of the combined stack: **[`../vibescan-go/deploy/DEPLOY.md`](../vibescan-go/deploy/DEPLOY.md)**.
