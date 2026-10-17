// Local stand-ins for the Cloudflare pieces the desk uses: a D1-shaped wrapper over
// node:sqlite, and a Cloudflare Access token signed with a throwaway key.
import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";

const MIGRATION = new URL("../migrations/0001_watch_tables.sql", import.meta.url);

// The evidence-engine tables the Watch reads, as they are in tpn-evidence (columns the job does not use are left out).
const EVIDENCE_SCHEMA = `
CREATE TABLE channels (channel_id TEXT PRIMARY KEY, name TEXT NOT NULL, register_id TEXT);
CREATE TABLE items (
  item_id TEXT PRIMARY KEY, canonical_url TEXT NOT NULL, publisher_domain TEXT NOT NULL, headline TEXT NOT NULL,
  published_at TEXT, date_status TEXT NOT NULL, first_seen_at TEXT NOT NULL, cluster_id TEXT);
CREATE TABLE item_channels (item_id TEXT NOT NULL, channel_id TEXT NOT NULL, first_seen_at TEXT NOT NULL, PRIMARY KEY (item_id, channel_id));
CREATE TABLE item_routes (item_id TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, method TEXT NOT NULL, field TEXT, matched TEXT, confidence TEXT, PRIMARY KEY (item_id, kind, value));
CREATE TABLE observer_editions (edition_id TEXT PRIMARY KEY, body TEXT NOT NULL, prepared_at TEXT NOT NULL, meridian_commit TEXT, dispatch_commit TEXT, valid INTEGER NOT NULL CHECK (valid IN (0, 1)));
CREATE TABLE observer_candidates (candidate_id INTEGER PRIMARY KEY AUTOINCREMENT, edition_id TEXT NOT NULL, prepared_at TEXT NOT NULL);
CREATE TABLE observer_approvals (approval_id INTEGER PRIMARY KEY AUTOINCREMENT, edition_id TEXT NOT NULL, approved_at TEXT NOT NULL, approved_by TEXT NOT NULL);
`;

class Statement {
  constructor(db, sql, params = []) {
    this.db = db;
    this.sql = sql;
    this.params = params;
  }
  bind(...params) {
    return new Statement(this.db, this.sql, params);
  }
  async first() {
    return this.db.prepare(this.sql).get(...this.params) ?? null;
  }
  async all() {
    return { results: this.db.prepare(this.sql).all(...this.params).map((r) => ({ ...r })) };
  }
  async run() {
    const r = this.db.prepare(this.sql).run(...this.params);
    return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid) } };
  }
}

export function localD1() {
  const db = new DatabaseSync(":memory:");
  db.exec(EVIDENCE_SCHEMA);
  db.exec(fs.readFileSync(MIGRATION, "utf8"));
  return {
    raw: db,
    prepare: (sql) => new Statement(db, sql),
    async batch(statements) {
      db.exec("BEGIN");
      try {
        const out = [];
        for (const s of statements) out.push(await s.run());
        db.exec("COMMIT");
        return out;
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
    }
  };
}

const CHANNELS = [
  ["research:cedefop-news", "Cedefop · news", "research-publishers"],
  ["research:jrc-publications", "JRC Publications Repository (European Commission)", "research-publishers"],
  ["research:eurofound-news", "Eurofound · current news", "research-publishers"],
  ["malta:business-now", "Business Now", "malta"],
  ["eu:cyprus-mail", "Cyprus Mail", "eu-affairs"],
  ["corporate:fortune", "Fortune", "corporate"],
  ["insights:mckinsey", "McKinsey Insights / Quarterly", "insights"]
];

// rows: { id, headline, domain, channel, published, seen?, cluster?, countries? }
export function seedEvidence(d1, rows) {
  const db = d1.raw;
  const ch = db.prepare("INSERT OR IGNORE INTO channels (channel_id, name, register_id) VALUES (?, ?, ?)");
  for (const c of CHANNELS) ch.run(...c);
  const item = db.prepare("INSERT INTO items (item_id, canonical_url, publisher_domain, headline, published_at, date_status, first_seen_at, cluster_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
  const link = db.prepare("INSERT INTO item_channels (item_id, channel_id, first_seen_at) VALUES (?, ?, ?)");
  const route = db.prepare("INSERT INTO item_routes (item_id, kind, value, method, confidence) VALUES (?, 'country', ?, 'test', ?)");
  for (const r of rows) {
    const seen = r.seen || r.published;
    item.run(r.id, r.url || `https://${r.domain}/${r.id}`, r.domain, r.headline, r.published, r.published ? "dated" : "undated", seen, r.cluster || null);
    link.run(r.id, r.channel, seen);
    for (const c of r.countries || []) route.run(r.id, c, "high");
  }
}

// Cloudflare Access: a signed RS256 token plus a fetch that serves the matching certs.
export async function accessFixture({ email = "jes@example.org", team = "https://tpn.cloudflareaccess.com", aud = "desk-aud", nowMs = Date.now() } = {}) {
  const pair = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const jwk = { ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), kid: "test-key" };
  const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
  const now = Math.floor(nowMs / 1e3);
  const unsigned = `${b64({ alg: "RS256", kid: "test-key" })}.${b64({ aud: [aud], iss: team, email, exp: now + 3600 })}`;
  const sig = Buffer.from(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, new TextEncoder().encode(unsigned))).toString("base64url");
  return {
    token: `${unsigned}.${sig}`,
    env: { ACCESS_TEAM_DOMAIN: team, ACCESS_AUD: aud, EVIDENCE_READERS: email },
    fetchImpl: async () => new Response(JSON.stringify({ keys: [jwk] }), { headers: { "content-type": "application/json" } })
  };
}

export function deskRequest(path, { token, method = "GET", form, origin = "https://publish.tpnintel.com", site = "same-origin" } = {}) {
  const headers = { "cf-access-jwt-assertion": token };
  if (method === "POST") Object.assign(headers, { origin, "sec-fetch-site": site });
  let body;
  if (form) {
    body = new URLSearchParams();
    for (const [k, v] of form) body.append(k, v);
  }
  return new Request(`https://publish.tpnintel.com${path}`, { method, headers, body });
}
