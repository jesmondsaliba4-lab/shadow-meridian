import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import worker, { searchNews, searchTerms } from "../src/index.js";

function d1() {
  const db = new DatabaseSync(":memory:");
  db.exec(`
CREATE TABLE channels (channel_id TEXT PRIMARY KEY, name TEXT NOT NULL, register_id TEXT);
CREATE TABLE items (item_id TEXT PRIMARY KEY, canonical_url TEXT NOT NULL, publisher_domain TEXT NOT NULL, headline TEXT NOT NULL,
  summary TEXT, summary_policy TEXT, published_at TEXT, date_status TEXT NOT NULL, first_seen_at TEXT NOT NULL, cluster_id TEXT);
CREATE TABLE item_channels (item_id TEXT NOT NULL, channel_id TEXT NOT NULL, first_seen_at TEXT NOT NULL, PRIMARY KEY (item_id, channel_id));
CREATE TABLE item_routes (item_id TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, method TEXT NOT NULL, field TEXT, matched TEXT, confidence TEXT, PRIMARY KEY (item_id, kind, value));`);
  const stmt = (sql, params = []) => ({
    bind: (...p) => stmt(sql, p),
    all: async () => ({ results: db.prepare(sql).all(...params).map((r) => ({ ...r })) }),
  });
  return { raw: db, prepare: (sql) => stmt(sql) };
}

const NOW = Date.parse("2026-11-03T09:00:00Z");
function seed(db) {
  const ins = db.raw.prepare("INSERT INTO items VALUES (?,?,?,?,?,?,?,?,?,?)");
  ins.run("a", "https://www.reuters.com/a", "reuters.com", "Brent crude climbs as Gulf shipping risks persist", "Oil rose for a third day.", "feed-text", "2026-11-02T10:00:00Z", "dated", "2026-11-02T10:05:00Z", "k1");
  ins.run("b", "https://www.ft.com/b", "ft.com", "Gulf shipping risks lift crude prices", "Paywalled text", "omitted-by-rule", "2026-11-02T09:00:00Z", "dated", "2026-11-02T09:05:00Z", "k1");
  ins.run("c", "https://cde.news/c", "cde.news", "Malta briefing: crude prices and fuel", null, null, "2026-11-02T08:00:00Z", "dated", "2026-11-02T08:05:00Z", null);
  ins.run("d", "https://x.example/d", "x.example", "Undated crude story", null, null, null, "undated", "2026-11-02T08:05:00Z", null);
  ins.run("e", "https://old.example/e", "old.example", "Crude prices in 2025", null, null, "2025-01-02T08:00:00Z", "dated", "2025-01-02T08:05:00Z", null);
  ins.run("f", "https://apnews.com/f", "apnews.com", "Fuel subsidies extended", "AP text", "feed-text", "2026-11-01T08:00:00Z", "dated", "2026-11-01T08:05:00Z", null);
  db.raw.exec(`INSERT INTO channels VALUES ('world:reuters','Reuters','world'),('world:ft','Financial Times','world'),('malta:cde-malta24','CDE Malta-24','malta'),('world:ap','AP News','world');
    INSERT INTO item_channels VALUES ('a','world:reuters','2026-11-02T10:05:00Z'),('b','world:ft','2026-11-02T09:05:00Z'),('c','malta:cde-malta24','2026-11-02T08:05:00Z'),('f','world:ap','2026-11-01T08:05:00Z');
    INSERT INTO item_routes VALUES ('a','country','united-arab-emirates','text',NULL,NULL,'high');`);
}

test("search words drop filler", () => {
  assert.deepEqual(searchTerms("What is the latest on crude prices?"), ["crude", "prices"]);
});

test("returns dated, recent, one-per-story items with publisher names and links", async () => {
  const db = d1(); seed(db);
  const items = await searchNews(db, "brent crude", { limit: 8, nowMs: NOW });
  const urls = items.map((i) => i.url);
  assert.ok(urls.includes("https://www.reuters.com/a"));
  const both = await searchNews(db, "crude prices gulf", { limit: 8, nowMs: NOW });
  assert.equal(both.filter((i) => /reuters|ft\.com/.test(i.url)).length, 1, "same story (cluster) is listed once");
  const crude = (await searchNews(db, "crude", { limit: 8, nowMs: NOW })).map((i) => i.url);
  assert.ok(!crude.includes("https://cde.news/c"), "cde.news's own briefing is not cited back");
  assert.ok(!crude.includes("https://x.example/d"), "undated items are left out");
  assert.ok(!crude.includes("https://old.example/e"), "old items are left out");
  const a = items.find((i) => i.url === "https://www.reuters.com/a");
  assert.deepEqual(Object.keys(a).sort(), ["country", "date", "source", "summary", "title", "url"]);
  assert.equal(a.source, "Reuters");
  assert.equal(a.country, "united-arab-emirates");
});

test("text the publisher's rules exclude is never returned", async () => {
  const db = d1(); seed(db);
  db.raw.exec("UPDATE items SET cluster_id = NULL WHERE item_id = 'b'");
  const items = await searchNews(db, "gulf shipping", { limit: 8, nowMs: NOW });
  const b = items.find((i) => i.url === "https://www.ft.com/b");
  assert.equal(b.summary, "");
});

test("the endpoint is closed without the key and open with it", async () => {
  const db = d1(); seed(db);
  const env = { EVIDENCE_DB: db, NEWS_SEARCH_KEY: "0123456789abcdef0123" };
  const ask = (auth) => worker.fetch(new Request("https://s.example/search?q=fuel", { headers: auth ? { authorization: auth } : {} }), env);
  assert.equal((await ask("")).status, 401);
  assert.equal((await ask("Bearer wrong-key-wrong-key")).status, 401);
  const ok = await ask("Bearer 0123456789abcdef0123");
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).items[0].source, "AP News");
  assert.equal((await worker.fetch(new Request("https://s.example/search?q=fuel"), { EVIDENCE_DB: db })).status, 401, "no key configured: closed");
  assert.equal((await worker.fetch(new Request("https://s.example/other"), env)).status, 404);
});
