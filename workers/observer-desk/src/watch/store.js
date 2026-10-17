import { buildWatchEdition, watchEditionIsValid, WINDOW_DAYS, MAX_AGE_DAYS } from "./select.js";

const DAY_MS = 24 * 60 * 60 * 1e3;

// Items the evidence engine first saw in the window, with a publisher date and an AI term in the headline.
// The SQL filter is deliberately loose (GLOB is case-sensitive, so 'AI' does not match 'said');
// the rules in select.js decide what qualifies.
export const WATCH_SOURCE_SQL = `
SELECT i.item_id, i.headline, i.canonical_url, i.publisher_domain, i.published_at, i.cluster_id,
       (SELECT GROUP_CONCAT(DISTINCT c.register_id) FROM item_channels ic JOIN channels c ON c.channel_id = ic.channel_id
         WHERE ic.item_id = i.item_id) AS registers,
       (SELECT c.name FROM item_channels ic JOIN channels c ON c.channel_id = ic.channel_id
         WHERE ic.item_id = i.item_id AND c.register_id = 'research-publishers' ORDER BY c.channel_id LIMIT 1) AS research_channel,
       EXISTS (SELECT 1 FROM item_routes r WHERE r.item_id = i.item_id AND r.kind = 'country' AND r.value = 'malta'
                AND (r.confidence IS NULL OR r.confidence != 'low')) AS malta,
       (SELECT GROUP_CONCAT(r.value) FROM item_routes r WHERE r.item_id = i.item_id AND r.kind = 'country'
         AND (r.confidence IS NULL OR r.confidence != 'low')) AS countries
  FROM items i
 WHERE i.first_seen_at >= ?1 AND i.first_seen_at < ?2
   AND i.date_status = 'dated' AND i.published_at >= ?3
   AND (i.headline GLOB '*AI*' OR i.headline GLOB '*A.I.*' OR i.headline GLOB '*LLM*'
        OR i.headline LIKE '%artificial intelligence%' OR i.headline LIKE '%chatgpt%' OR i.headline LIKE '%genai%')
 ORDER BY i.published_at DESC, i.item_id
 LIMIT 2000`;

export function watchWindow(nowMs) {
  return {
    start: new Date(nowMs - WINDOW_DAYS * DAY_MS).toISOString(),
    end: new Date(nowMs).toISOString(),
    oldestPublished: new Date(nowMs - MAX_AGE_DAYS * DAY_MS).toISOString()
  };
}

export async function sha256Hex(text) {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function buildWatchCandidate(db, { nowMs = Date.now() } = {}) {
  const w = watchWindow(nowMs);
  const { results } = await db.prepare(WATCH_SOURCE_SQL).bind(w.start, w.end, w.oldestPublished).all();
  const edition = buildWatchEdition(results || [], { nowMs });
  const body = JSON.stringify(edition);
  return {
    edition_id: await sha256Hex(body),
    body,
    window_start: edition.window.start,
    window_end: edition.window.end,
    valid: watchEditionIsValid(edition, { nowMs }),
    items: edition.items.length
  };
}

export async function storeWatchCandidate(db, candidate, { nowMs = Date.now() } = {}) {
  const at = new Date(nowMs).toISOString();
  await db.batch([
    db.prepare(
      "INSERT OR IGNORE INTO watch_editions (edition_id, body, prepared_at, window_start, window_end, valid) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(candidate.edition_id, candidate.body, at, candidate.window_start, candidate.window_end, candidate.valid ? 1 : 0),
    db.prepare("INSERT INTO watch_candidates (edition_id, prepared_at) VALUES (?, ?)").bind(candidate.edition_id, at)
  ]);
  return candidate.edition_id;
}

export async function latestWatchCandidate(db) {
  return db.prepare(
    `SELECT e.edition_id, e.body, c.prepared_at, e.window_start, e.window_end, e.valid
       FROM watch_candidates c JOIN watch_editions e ON e.edition_id = c.edition_id
      ORDER BY c.candidate_id DESC LIMIT 1`
  ).first();
}

export async function publishedWatch(db) {
  return db.prepare(
    `SELECT e.edition_id, e.body, e.prepared_at, a.approved_at, a.approved_by, a.dropped
       FROM watch_approvals a JOIN watch_editions e ON e.edition_id = a.edition_id
      ORDER BY a.approval_id DESC LIMIT 1`
  ).first();
}

export async function approveWatch(db, editionId, approvedBy, dropped, { nowMs = Date.now() } = {}) {
  await db.prepare("INSERT INTO watch_approvals (edition_id, approved_at, approved_by, dropped) VALUES (?, ?, ?, ?)")
    .bind(editionId, new Date(nowMs).toISOString(), approvedBy, JSON.stringify(dropped)).run();
}

export async function prepareWatch(env, { nowMs = Date.now() } = {}) {
  const candidate = await buildWatchCandidate(env.EVIDENCE_DB, { nowMs });
  const before = await latestWatchCandidate(env.EVIDENCE_DB);
  await storeWatchCandidate(env.EVIDENCE_DB, candidate, { nowMs });
  // The window moves with every run, so compare the items rather than the edition id.
  return { edition_id: candidate.edition_id, valid: candidate.valid, items: candidate.items, changed: itemsOf(before?.body) !== itemsOf(candidate.body) };
}

function itemsOf(body) {
  try {
    return body ? JSON.stringify(JSON.parse(body).items) : null;
  } catch {
    return null;
  }
}
