# vibescan (monorepo)

Go reimplementation of VibeScan: collector + embedded UI, plus a scanner agent.
Replaces the Python stack incrementally while sharing Mongo / object storage.

| Path | Role |
|------|------|
| [`vibescan-go/`](vibescan-go/) | Collector, v2 APIs, agent, migrate, Docker/Caddy deploy |
| [`vibescan-ui/`](vibescan-ui/) | React recon console (embedded into the Go image in prod) |

**Deploy runbook:** [`vibescan-go/deploy/DEPLOY.md`](vibescan-go/deploy/DEPLOY.md)

The legacy Python app (`vibescan_v2`) is **not** part of this repo — it remains a
separate Git remote for dual-run / reference.
