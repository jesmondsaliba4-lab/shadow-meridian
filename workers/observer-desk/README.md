# observer-desk

publish.tpnintel.com, behind Cloudflare Access. Two tabs, one structure: a job prepares a candidate, Jes presses Publish, the site reads only the latest approval.

| Tab | Candidate from | Tables | Schedule |
| --- | --- | --- | --- |
| Malta Observer (`/`) | Meridian and Dispatch repositories on GitHub | `observer_editions`, `observer_candidates`, `observer_approvals` | the existing Observer cron |
| AI & Skills Watch (`/watch`) | TPN evidence engine (`EVIDENCE_DB`) | `watch_editions`, `watch_candidates`, `watch_approvals` | `0 18 * * SUN` (Sunday 19:00 CET / 20:00 CEST) |

## Source

`src/` was recovered from `deployed-bundle.js` on 17 October 2026. Bundling `src/index.js` with esbuild 0.24.2 (`npm run bundle`) reproduced the deployed bundle exactly, apart from one path comment, before the Watch was added. `deployed-bundle.js` is kept as the record of what Cloudflare ran at recovery.

## AI & Skills Watch

Design note: <https://claude.ai/code/artifact/9036599b-c0c9-43f7-abb1-eb85d6e10f1b>

- `src/watch/select.js`: the selection rules (pure functions). An edition covers items the engine first saw in the 7 days before it is prepared, published in the last 14 days; the headline must pair AI with skills, schools, jobs, workers, training, literacy or labour; dropped topics are excluded; one link per story, original publisher first; at most 12 items (5 research, 7 news), grouped by chapter with Malta first. Each item carries only headline, publisher, date, link and chapter.
- `src/watch/store.js`: reads the engine and writes the three `watch_*` tables.
- `src/watch/page.js`, `src/watch/routes.js`: the Watch tab. `GET /watch`, `POST /watch/refresh`, `POST /watch/publish`.
- Drops: Jes ticks Drop on single items and presses Publish. The edition body never changes; `watch_approvals.dropped` lists the dropped item ids (a JSON array), and the site shows the approved edition without them.

## Before the first deploy with the Watch

Nothing here deploys by itself. When the Watch is reviewed:

1. Apply `migrations/0001_watch_tables.sql` to `tpn-evidence` (EU) with `wrangler d1 execute tpn-evidence --remote --file migrations/0001_watch_tables.sql`.
2. Add `"0 18 * * SUN"` to `[triggers] crons` in the desk's `wrangler.toml` (copied from the dashboard; not in this repo), next to the Observer's existing cron. The worker routes on the exact cron string, so any other cron still prepares the Observer.
3. Deploy the desk with `wrangler deploy`.

## Tests

```bash
npm test
```

Runs on Node 22.5 or later. The tests use `node:sqlite` in place of D1 and a throwaway signing key in place of Cloudflare Access; nothing touches Cloudflare.
