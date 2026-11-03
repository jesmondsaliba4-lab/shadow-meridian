# tpn-news-search

A small, separate, read-only Worker that lets cde.news **Enquire** search the TPN evidence engine (the news behind meridian.tpnintel.com). Answers that use it carry the credit *"Further research supported by ThinkPeople Nexus Insights & Research · Meridian"*.

It does not touch the Meridian Worker, the Observer desk or the collector, and it never writes to the database.

## What it returns

`GET /search?q=<words>&limit=<1-8>` with `Authorization: Bearer <NEWS_SEARCH_KEY>`:

```json
{"items":[{"title":"…","date":"2026-11-02T10:00:00Z","source":"Reuters","url":"https://…","summary":"…","country":"…"}]}
```

- Only dated articles from the last 120 days, matched on the headline.
- One article per story (engine clusters), the original publisher's link.
- `summary` only where the engine keeps the feed's own text (`summary_policy = 'feed-text'`); empty where a publisher's rules exclude it.
- cde.news's own Malta-24 briefing is never cited back to cde.news.
- No index scores, rankings, Meridian analysis or reader data.
- Without the `NEWS_SEARCH_KEY` secret, every request gets 401.

## Deploy from the Cloudflare dashboard (no command line)

1. **Workers & Pages › Create › Create Worker**, name it `tpn-news-search`, press **Deploy**.
2. **Edit code**: replace everything with `src/index.js` from this folder, press **Deploy**.
3. **Settings › Bindings › Add binding › D1 database**: variable name `EVIDENCE_DB`, database `tpn-evidence`.
4. **Settings › Variables and Secrets › Add**: type **Secret**, name `NEWS_SEARCH_KEY`, a long random value (e.g. `openssl rand -hex 32`).
5. The address is `https://tpn-news-search.<your-workers-subdomain>.workers.dev/search` (shown on the Worker's overview page).
6. In WordPress: **Customize › cde.news › Meridian research (Enquire)** — paste the address and the same key; leave the Cloudflare token fields empty.

Or with Wrangler: put the `tpn-evidence` database ID in `wrangler.toml`, then `wrangler secret put NEWS_SEARCH_KEY` and `wrangler deploy`.

## Tests

```bash
npm test
```

Node 22.5 or later; uses `node:sqlite` in place of D1.
