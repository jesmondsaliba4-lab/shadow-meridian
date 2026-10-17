import test from "node:test";
import assert from "node:assert/strict";
import worker, { handleRequest } from "../src/index.js";
import { WATCH_CRON } from "../src/watch/routes.js";
import { accessFixture, deskRequest, localD1, seedEvidence } from "./helpers.js";

const SUNDAY = Date.parse("2026-10-18T18:00:00Z");
const daysAgo = (n) => new Date(SUNDAY - n * 864e5).toISOString();

function evidence(d1) {
  seedEvidence(d1, [
    { id: "it_mt", headline: "MCAST turns to AI to tackle Malta's skills gap", domain: "businessnow.mt", channel: "malta:business-now", published: daysAgo(5), countries: ["malta"] },
    { id: "it_jrc", headline: "AI and Skills", domain: "publications.jrc.ec.europa.eu", channel: "research:jrc-publications", published: daysAgo(3) },
    { id: "it_cy", headline: "Cyprus businesses invited to subsidised AI training programme", domain: "cyprus-mail.com", channel: "eu:cyprus-mail", published: daysAgo(4), countries: ["cyprus"] },
    { id: "it_rogue", headline: "AI agents are going rogue, and training choices are why", domain: "fortune.com", channel: "corporate:fortune", published: daysAgo(2) },
    { id: "it_old", headline: "Is AI putting graduates out of work already?", domain: "fortune.com", channel: "corporate:fortune", published: daysAgo(160), seen: daysAgo(1) },
    { id: "it_prev", headline: "AI skills week for workers", domain: "cyprus-mail.com", channel: "eu:cyprus-mail", published: daysAgo(9), seen: daysAgo(9) }
  ]);
}

// One key for the whole file: access.js caches the team's certs for ten minutes.
const access = await accessFixture({ nowMs: SUNDAY });

async function desk() {
  const d1 = localD1();
  evidence(d1);
  const env = { ...access.env, EVIDENCE_DB: d1 };
  const call = (path, options) => handleRequest(deskRequest(path, { token: access.token, ...options }), env, { fetchImpl: access.fetchImpl, nowMs: SUNDAY });
  return { d1, env, call };
}

function cronEvent(cron) {
  const waits = [];
  return { controller: { cron, scheduledTime: SUNDAY }, ctx: { waitUntil: (p) => waits.push(p) }, done: () => Promise.all(waits) };
}

test("the Sunday cron prepares a Watch candidate from the evidence engine", async () => {
  const { d1, env } = await desk();
  const e = cronEvent(WATCH_CRON);
  await worker.scheduled(e.controller, env, e.ctx);
  await e.done();
  const candidates = d1.raw.prepare("SELECT * FROM watch_candidates").all();
  assert.equal(candidates.length, 1);
  const edition = d1.raw.prepare("SELECT * FROM watch_editions").get();
  assert.equal(edition.valid, 1);
  assert.equal(edition.window_start, "2026-10-11T18:00:00.000Z");
  const body = JSON.parse(edition.body);
  assert.deepEqual(body.items.map((i) => i.id), ["it_mt", "it_jrc", "it_cy"], "Malta first; rogue, too old and outside the window are out");
  assert.equal(d1.raw.prepare("SELECT COUNT(*) AS n FROM observer_candidates").get().n, 0, "the Observer is not touched");
});

test("other crons still run the Observer job, not the Watch", async () => {
  const { d1, env } = await desk();
  const errors = [];
  const original = console.error;
  console.error = (line) => errors.push(line);
  try {
    const e = cronEvent("*/30 * * * *");
    await worker.scheduled(e.controller, env, e.ctx);
    await e.done();
  } finally {
    console.error = original;
  }
  assert.match(errors.join("\n"), /observer_candidate_failed/, "the Observer job ran (and failed here: no GitHub key in tests)");
  assert.equal(d1.raw.prepare("SELECT COUNT(*) AS n FROM watch_candidates").get().n, 0);
});

test("the Watch tab lists the candidate with a Drop box per item", async () => {
  const { call } = await desk();
  await call("/watch/refresh", { method: "POST" });
  const page = await (await call("/watch")).text();
  assert.match(page, /AI &amp; Skills Watch/);
  assert.equal((page.match(/name="drop"/g) || []).length, 3);
  assert.match(page, /MCAST turns to AI/);
  assert.doesNotMatch(page, /going rogue/);
  assert.doesNotMatch(page, /<script/i, "no scripts: the desk's CSP forbids them");
  const observer = await (await call("/")).text();
  assert.match(observer, /href="\/watch"/, "the Observer page links to the Watch tab");
});

test("Publish records the approval with the dropped items", async () => {
  const { d1, call } = await desk();
  await call("/watch/refresh", { method: "POST" });
  const { edition_id } = d1.raw.prepare("SELECT edition_id FROM watch_candidates ORDER BY candidate_id DESC").get();
  const res = await call("/watch/publish", { method: "POST", form: [["edition_id", edition_id], ["drop", "it_cy"]] });
  assert.equal(res.status, 303);
  assert.equal(res.headers.get("location"), "/watch?m=published");
  const approval = d1.raw.prepare("SELECT * FROM watch_approvals").get();
  assert.equal(approval.edition_id, edition_id);
  assert.equal(approval.approved_by, "jes@example.org");
  assert.deepEqual(JSON.parse(approval.dropped), ["it_cy"]);
  const page = await (await call("/watch")).text();
  assert.match(page, /1 dropped/);
});

test("Publish refuses stale editions, unknown items, dropping everything and cross-site posts", async () => {
  const { d1, call } = await desk();
  await call("/watch/refresh", { method: "POST" });
  const { edition_id } = d1.raw.prepare("SELECT edition_id FROM watch_candidates").get();
  const publish = (form, options) => call("/watch/publish", { method: "POST", form, ...options });
  assert.equal((await publish([["edition_id", "0".repeat(64)]])).headers.get("location"), "/watch?m=invalid");
  assert.equal((await publish([["edition_id", edition_id], ["drop", "it_other"]])).headers.get("location"), "/watch?m=invalid");
  assert.equal((await publish([["edition_id", edition_id], ["drop", "it_mt"], ["drop", "it_jrc"], ["drop", "it_cy"]])).headers.get("location"), "/watch?m=all_dropped");
  assert.equal((await publish([["edition_id", edition_id]], { origin: "https://evil.example", site: "cross-site" })).status, 403);
  assert.equal(d1.raw.prepare("SELECT COUNT(*) AS n FROM watch_approvals").get().n, 0);
});

test("the Watch needs a signed-in reader like the rest of the desk", async () => {
  const { env } = await desk();
  const res = await handleRequest(new Request("https://publish.tpnintel.com/watch"), env);
  assert.equal(res.status, 401);
});
