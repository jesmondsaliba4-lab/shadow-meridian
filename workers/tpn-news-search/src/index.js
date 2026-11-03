// tpn-news-search: read-only news search over the TPN evidence engine (D1 `tpn-evidence`),
// for cde.news "Enquire". Answers that use it carry the credit
// "Further research supported by ThinkPeople Nexus Insights & Research · Meridian".
//
//   GET /search?q=<words>&limit=<1-8>
//   Authorization: Bearer <NEWS_SEARCH_KEY>
//
// Returns {"items":[{"title","date","source","url","summary","country"}]}.
// Only news-level fields leave the engine: headline, the publisher's own date, the
// publisher's name, its original link, the feed's own text where the engine keeps it
// (summary_policy = 'feed-text'), and the routed country. Nothing is written.
// Without NEWS_SEARCH_KEY (a Worker secret) the endpoint stays closed.

const MAX_TERMS = 6;
const WINDOW_DAYS = 120;
const CANDIDATES = 300;
const SELF_CHANNELS = new Set(["malta:cde-malta24"]); // cde.news's own briefing: never cite cde.news back to itself
const STOP = new Set(
  "a an and are as at be by for from has have how in into is it its of on or that the their this to was were what when where which who why will with about latest news today week this year".split(" ")
);
const SECURITY = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "x-robots-tag": "noindex",
};

export function searchTerms(query) {
  const words = String(query || "")
    .toLowerCase()
    .normalize("NFKC")
    .split(/[^\p{L}\p{N}]+/u)
    .filter((w) => w && !STOP.has(w) && (w.length >= 3 || /^\p{N}+$/u.test(w) || ["eu", "uk", "us", "un"].includes(w)));
  return [...new Set(words)].slice(0, MAX_TERMS);
}

const escapeLike = (s) => s.replace(/[\\%_]/g, (ch) => `\\${ch}`);

function json(status, body) {
  return new Response(JSON.stringify(body), { status, headers: SECURITY });
}

function sameKey(given, expected) {
  const a = new TextEncoder().encode(given);
  const b = new TextEncoder().encode(expected);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function authorised(request, env) {
  const key = String(env.NEWS_SEARCH_KEY || "");
  if (key.length < 16) return false;
  const header = request.headers.get("authorization") || "";
  return header.startsWith("Bearer ") && sameKey(header.slice(7).trim(), key);
}

export async function searchNews(db, query, { limit = 4, nowMs = Date.now() } = {}) {
  const terms = searchTerms(query);
  if (!terms.length) return [];
  const since = new Date(nowMs - WINDOW_DAYS * 864e5).toISOString();
  const like = terms.map(() => "i.headline LIKE ? ESCAPE '\\'").join(" OR ");
  const { results } = await db
    .prepare(
      `SELECT i.item_id, i.headline, i.canonical_url, i.publisher_domain, i.published_at, i.cluster_id,
              CASE WHEN i.summary_policy = 'feed-text' THEN i.summary ELSE NULL END AS summary,
              (SELECT c.name FROM item_channels ic JOIN channels c ON c.channel_id = ic.channel_id
                WHERE ic.item_id = i.item_id ORDER BY ic.first_seen_at LIMIT 1) AS publisher,
              (SELECT GROUP_CONCAT(ic.channel_id) FROM item_channels ic WHERE ic.item_id = i.item_id) AS channel_ids,
              (SELECT r.value FROM item_routes r
                WHERE r.item_id = i.item_id AND r.kind = 'country' AND r.confidence IN ('high','medium')
                ORDER BY CASE r.confidence WHEN 'high' THEN 0 ELSE 1 END, r.value LIMIT 1) AS country
         FROM items i
        WHERE i.date_status = 'dated' AND i.published_at >= ? AND (${like})
        ORDER BY i.published_at DESC, i.item_id
        LIMIT ${CANDIDATES}`
    )
    .bind(since, ...terms.map((t) => `%${escapeLike(t)}%`))
    .all();

  const scored = [];
  const clusters = new Set();
  for (const r of results) {
    const channels = String(r.channel_ids || "").split(",").filter(Boolean);
    if (channels.length && channels.every((c) => SELF_CHANNELS.has(c))) continue;
    if (!/^https?:\/\//i.test(String(r.canonical_url || ""))) continue;
    const head = String(r.headline || "").toLowerCase();
    const body = String(r.summary || "").toLowerCase();
    let hits = 0;
    let score = 0;
    for (const t of terms) {
      const inHead = head.includes(t);
      if (inHead) score += 3;
      if (body.includes(t)) score += 1;
      if (inHead) hits += 1;
    }
    if (!hits) continue;
    score += hits * 2;
    const t = Date.parse(r.published_at);
    if (Number.isFinite(t)) score += Math.max(0, 1 - (nowMs - t) / (WINDOW_DAYS * 864e5)) * 2;
    scored.push({ score, r });
  }
  scored.sort((a, b) => b.score - a.score);

  const out = [];
  for (const { r } of scored) {
    if (r.cluster_id) {
      if (clusters.has(r.cluster_id)) continue; // one item per story
      clusters.add(r.cluster_id);
    }
    out.push({
      title: String(r.headline).slice(0, 200),
      date: r.published_at || "",
      source: String(r.publisher || r.publisher_domain || "").slice(0, 80),
      url: r.canonical_url,
      summary: r.summary ? String(r.summary).slice(0, 900) : "",
      country: r.country || "",
    });
    if (out.length >= limit) break;
  }
  return out;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/search") return json(404, { error: "not_found" });
    if (request.method !== "GET") return json(405, { error: "method_not_allowed" });
    if (!authorised(request, env)) return json(401, { error: "unauthorised" });
    if (!env.EVIDENCE_DB) return json(503, { error: "engine_not_connected" });
    const q = (url.searchParams.get("q") || "").slice(0, 300);
    const limit = Math.max(1, Math.min(8, parseInt(url.searchParams.get("limit") || "4", 10) || 4));
    try {
      const items = await searchNews(env.EVIDENCE_DB, q, { limit });
      return json(200, { items, attribution: "ThinkPeople Nexus Insights & Research · Meridian" });
    } catch {
      return json(503, { error: "search_failed" });
    }
  },
};
