# shadow-meridian

Source for the TPN Observer Cloudflare Workers, recovered on 17 October 2026 from the scripts deployed on Cloudflare. The original source folder was lost with the Claude session that deployed it.

## What is here

| Folder | Deployed worker | What it does |
| --- | --- | --- |
| `workers/observer-desk` | `observer-desk` | publish.tpnintel.com: prepares the Malta Observer candidate on a schedule (`observer_editions`, `observer_candidates`), shows the desk page and records Jes's approval (`observer_approvals`) |
| `workers/meridian-shadow` | `meridian-shadow` | Meridian comparison copy; it also bundles the observer-feed source (`../observer-feed/src/index.js`) |
| `workers/tpn-evidence-shadow` | `tpn-evidence-shadow` | The evidence engine collector (cron + queue) that fills the D1 database |

Each folder holds `deployed-bundle.js`, exactly as Cloudflare runs it today, and `MODULES.txt`, which lists the original source modules inside the bundle (each starts with a `// src/...` comment).

## Not recovered

- `wrangler.toml` files: bindings (D1 `EVIDENCE_DB`, R2, queues), cron schedules, routes and vars. Copy these from the Cloudflare dashboard before the first redeploy.
- Static assets served through `ASSETS` (where a worker uses them).
- Secrets. Never commit them.
- `tpn-observer-feed` and `dispatch-shadow` as standalone folders; to be added.

## Rule

Nothing in this repo deploys by itself. Cloudflare keeps running what is deployed until someone runs `wrangler deploy` on purpose.
