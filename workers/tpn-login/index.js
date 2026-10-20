var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// ../src/access.js
var certCache = /* @__PURE__ */ new Map();
var CERT_TTL_MS = 10 * 60 * 1e3;
var b64urlToBytes = /* @__PURE__ */ __name((s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=")), (c) => c.charCodeAt(0)), "b64urlToBytes");
var b64urlToJson = /* @__PURE__ */ __name((s) => JSON.parse(new TextDecoder().decode(b64urlToBytes(s))), "b64urlToJson");
async function keysFor(teamDomain, fetchImpl, nowMs) {
  const cached = certCache.get(teamDomain);
  if (cached && nowMs - cached.fetchedAt < CERT_TTL_MS) return cached.keys;
  const response = await fetchImpl(`${teamDomain}/cdn-cgi/access/certs`);
  if (!response.ok) throw new Error("certs unavailable");
  const { keys } = await response.json();
  certCache.set(teamDomain, { keys, fetchedAt: nowMs });
  return keys;
}
__name(keysFor, "keysFor");
async function verifyAccess(request, env, { fetchImpl = fetch, nowMs = Date.now(), requireReader = true } = {}) {
  const team = env.ACCESS_TEAM_DOMAIN;
  const aud = env.ACCESS_AUD;
  if (!team || !aud || !/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(team)) return { ok: false, status: 503, reason: "access-not-configured" };
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) return { ok: false, status: 401, reason: "missing-token" };
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false, status: 401, reason: "malformed-token" };
  let header, payload;
  try {
    header = b64urlToJson(parts[0]);
    payload = b64urlToJson(parts[1]);
  } catch {
    return { ok: false, status: 401, reason: "malformed-token" };
  }
  if (header.alg !== "RS256") return { ok: false, status: 401, reason: "bad-algorithm" };
  let keys;
  try {
    keys = await keysFor(team, fetchImpl, nowMs);
  } catch {
    return { ok: false, status: 503, reason: "certs-unavailable" };
  }
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) return { ok: false, status: 401, reason: "unknown-key" };
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64urlToBytes(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!valid) return { ok: false, status: 401, reason: "bad-signature" };
  const nowS = Math.floor(nowMs / 1e3);
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audiences.includes(aud)) return { ok: false, status: 401, reason: "wrong-audience" };
  if (payload.iss !== team) return { ok: false, status: 401, reason: "wrong-issuer" };
  if (typeof payload.exp !== "number" || payload.exp < nowS) return { ok: false, status: 401, reason: "expired" };
  if (typeof payload.nbf === "number" && payload.nbf > nowS + 60) return { ok: false, status: 401, reason: "not-yet-valid" };
  const email = String(payload.email || "").toLowerCase();
  if (!email) return { ok: false, status: 401, reason: "no-identity" };
  const readers = String(env.EVIDENCE_READERS || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (!readers.length) return { ok: false, status: 503, reason: "readers-not-configured" };
  const isReader = readers.includes(email);
  if (!isReader && requireReader) return { ok: false, status: 403, reason: "not-a-reader" };
  return { ok: true, email, isReader };
}
__name(verifyAccess, "verifyAccess");

// src/index.js
var SECURITY = {
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "x-frame-options": "DENY",
  "referrer-policy": "same-origin",
  "x-content-type-options": "nosniff",
  "x-robots-tag": "noindex, nofollow",
  "cache-control": "no-store, private"
};
var esc = /* @__PURE__ */ __name((v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]), "esc");
var SECTIONS = [
  {
    title: "Publish",
    note: "What the public sees, and where it is approved.",
    items: [
      { name: "Publication desk", url: "https://publish.tpnintel.com/", text: "Review the prepared Malta Observer edition and press Publish." },
      { name: "Malta Observer", url: "https://www.maltaobserver.com/", text: "The public showcase. Headlines update on their own; everything else after Publish.", public: true },
      { name: "The News Dispatch", url: "https://www.maltaobserver.com/news-dispatch.html", text: "Dispatch stories in full, other headlines as a dated list.", public: true }
    ]
  },
  {
    title: "Intelligence",
    note: "Behind this sign-in, for Jes and Charmaine.",
    items: [
      { name: "Evidence engine", url: "https://engine.tpnintel.com/", text: "Everything collected from monitored publishers, with each publisher\u2019s own date." },
      { name: "Dispatch", url: "https://dispatch.tpnintel.com/", text: "The newsroom and industry research view on the engine." },
      { name: "Meridian", url: "https://meridian.tpnintel.com/", text: "Geopolitical intelligence and analysis on the engine." },
      { name: "Official statistics", url: "https://stats.tpnintel.com/", text: "NSO Malta: IRIS datasets and the Selected Indicators files." },
      { name: "Skills Workbench", url: "https://skills.tpnintel.com/", text: "The Malta Skills Workbench, private copy." },
      { name: "SHaiPING Malta", url: "https://shaipingmalta.tpnintel.com/", text: "The National Workplace Index platform: Review & Release, HR intelligence and the Malta news monitor." },
      { name: "Research connector", url: "https://research.tpnintel.com/mcp", text: "Add this address to Claude or another AI assistant as a connector; it is not a web page.", connector: true }
    ]
  },
  {
    title: "Wellbeing (separate sign-in)",
    note: "The WBGI keeps its own access list.",
    items: [
      { name: "WBGI observatory", url: "https://wellbeing.yourfuturelink.pro/", text: "The wellbeing index." },
      { name: "Who gets access", url: "https://wellbeing-access.yourfuturelink.pro/", text: "Approve or remove WBGI viewers." }
    ]
  },
  {
    title: "Also public",
    note: "",
    items: [
      { name: "SHaiPING Malta (public site)", url: "https://shaipingmalta.eu/", text: "The public SHaiPING website.", public: true },
      { name: "ThinkPeople Nexus", url: "https://thinkpeople.eu/", text: "The company website.", public: true }
    ]
  },
  {
    title: "Old services",
    note: "Since 17 Oct 2026 the old meridian, dispatch and intelligence.yourfuturelink.pro addresses forward to the rooms above. The old services keep running behind the forward, unchanged, until they are exported, checked and paused after the Election Watch dates (25 Oct, 27 Oct, 3 Nov).",
    items: [
      { name: "Dispatch PRO (old)", url: "https://dispatch.nexus-tp.com/", text: "Previous Dispatch briefing archive." }
    ]
  }
];
var MARK = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Ccircle cx='32' cy='32' r='31' fill='%23091425' stroke='%23d49a5a' stroke-width='2'/%3E%3Ccircle cx='32' cy='32' r='19' fill='none' stroke='%2336c5f0' stroke-opacity='.55' stroke-width='1.5'/%3E%3Cpath d='M20 22h24M32 22v22' stroke='%23f2efe8' stroke-width='5' stroke-linecap='round'/%3E%3Ccircle cx='44' cy='43' r='3.2' fill='%23d49a5a'/%3E%3C/svg%3E";
var ISO = /* @__PURE__ */ __name((ms) => new Date(ms).toISOString(), "ISO");
async function todayView(db, nowMs = Date.now()) {
  const safe = /* @__PURE__ */ __name(async (fn) => {
    try {
      return await fn();
    } catch {
      return null;
    }
  }, "safe");
  const dayAgo = ISO(nowMs - 24 * 60 * 60 * 1e3);
  const [published, candidate, collected, lastRun, nso] = await Promise.all([
    safe(() => db.prepare("SELECT edition_id, approved_at FROM observer_approvals ORDER BY approval_id DESC LIMIT 1").first()),
    safe(() => db.prepare(
      `SELECT c.edition_id, c.prepared_at, e.valid FROM observer_candidates c JOIN observer_editions e ON e.edition_id = c.edition_id
        ORDER BY c.candidate_id DESC LIMIT 1`
    ).first()),
    safe(() => db.prepare("SELECT COUNT(*) AS n, COUNT(DISTINCT publisher_domain) AS publishers FROM items WHERE first_seen_at >= ?").bind(dayAgo).first()),
    safe(() => db.prepare("SELECT started_at FROM runs ORDER BY started_at DESC LIMIT 1").first()),
    safe(() => db.prepare("SELECT fetched_at FROM stat_fetches WHERE ok = 1 ORDER BY fetched_at DESC LIMIT 1").first())
  ]);
  let observer;
  if (!candidate && !published) observer = { state: "unknown" };
  else if (candidate && candidate.valid === 1 && candidate.edition_id !== published?.edition_id && (!published || candidate.prepared_at > published.approved_at)) {
    observer = { state: "waiting", prepared_at: candidate.prepared_at, published_at: published?.approved_at || null };
  } else observer = { state: "current", published_at: published?.approved_at || null };
  return {
    observer,
    engine: collected ? { items_24h: Number(collected.n) || 0, publishers_24h: Number(collected.publishers) || 0, last_run: lastRun?.started_at || null } : null,
    nso: nso ? { last_reading: nso.fetched_at } : null
  };
}
__name(todayView, "todayView");
var SHAIPING_POINTER = "https://shaipingmalta.tpnintel.com/data/index-current.json";
async function shaipingRelease(env, fetchImpl = fetch) {
  if (!env.SHAIPING_CLIENT_ID || !env.SHAIPING_CLIENT_SECRET) return null;
  try {
    const r = await fetchImpl(SHAIPING_POINTER, {
      headers: { "CF-Access-Client-Id": env.SHAIPING_CLIENT_ID, "CF-Access-Client-Secret": env.SHAIPING_CLIENT_SECRET, accept: "application/json" },
      redirect: "manual",
      signal: AbortSignal.timeout(4e3)
    });
    if (!r.ok) return null;
    const j = await r.json();
    if (!j || typeof j.current_release_id !== "string") return null;
    return { release_id: j.current_release_id, status: j.approval_status || null, promoted_at: j.promoted_at || j.calculation_date || null, cutoff: j.evidence_cutoff || null };
  } catch {
    return null;
  }
}
__name(shaipingRelease, "shaipingRelease");
function day(iso) {
  if (!iso) return "date not recorded";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "date not recorded";
  return new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Malta", day: "numeric", month: "short", year: "numeric" }).format(d);
}
__name(day, "day");
function when(iso) {
  if (!iso) return "not recorded";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "not recorded";
  return new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Malta", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }).format(d);
}
__name(when, "when");
function page({ viewer, today }) {
  const o = today.observer;
  const observerCard = o.state === "waiting" ? `<a class="stat stat--act" href="https://publish.tpnintel.com/"><span>Malta Observer</span><b>An edition is waiting for Publish</b><small>Prepared ${esc(when(o.prepared_at))}${o.published_at ? ` \xB7 last published ${esc(when(o.published_at))}` : ""}</small></a>` : o.state === "current" ? `<div class="stat"><span>Malta Observer</span><b>Up to date</b><small>${o.published_at ? `Published ${esc(when(o.published_at))}` : "Nothing published yet"}</small></div>` : `<div class="stat"><span>Malta Observer</span><b>Status unavailable</b><small>Open the publication desk to check.</small></div>`;
  const engineCard = today.engine ? `<div class="stat"><span>Evidence engine</span><b>${esc(today.engine.items_24h.toLocaleString("en-GB"))} articles in 24 hours</b><small>From ${esc(today.engine.publishers_24h)} publishers \xB7 last run ${esc(when(today.engine.last_run))}</small></div>` : `<div class="stat"><span>Evidence engine</span><b>Status unavailable</b><small>Open the engine to check.</small></div>`;
  const nsoCard = today.nso ? `<div class="stat"><span>Official statistics</span><b>Last NSO reading</b><small>${esc(when(today.nso.last_reading))}</small></div>` : `<div class="stat"><span>Official statistics</span><b>No reading yet</b><small>Open the statistics page to check.</small></div>`;
  const sh = today.shaiping;
  const shaipingCard = sh ? `<a class="stat" href="https://shaipingmalta.tpnintel.com/"><span>National Workplace Index</span><b>Release ${esc(sh.release_id)}</b><small>${sh.status ? `${esc(sh.status)} ` : ""}${esc(day(sh.promoted_at))}${sh.cutoff ? ` \xB7 evidence to ${esc(day(sh.cutoff))}` : ""}</small></a>` : `<a class="stat" href="https://shaipingmalta.tpnintel.com/"><span>National Workplace Index</span><b>Release information unavailable</b><small>Open SHaiPING Malta to check.</small></a>`;
  const sections = SECTIONS.map((s) => `<section><header><h2>${esc(s.title)}</h2>${s.note ? `<p>${esc(s.note)}</p>` : ""}</header><div class="grid">${s.items.map((i) => {
    const host = new URL(i.url).host + (new URL(i.url).pathname.length > 1 ? new URL(i.url).pathname : "");
    const tag = i.connector ? "<i>Connector</i>" : i.public ? "<i>Public</i>" : "";
    return i.connector ? `<div class="tile"><h3>${esc(i.name)} ${tag}</h3><p>${esc(i.text)}</p><code>${esc(i.url)}</code></div>` : `<a class="tile" href="${esc(i.url)}"${i.public ? ' target="_blank" rel="noopener noreferrer"' : ""}><h3>${esc(i.name)} ${tag}</h3><p>${esc(i.text)}</p><code>${esc(host)}</code></a>`;
  }).join("")}</div></section>`).join("");
  return `<!doctype html><html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>TPN Intel \u2014 Reserved access</title><link rel="icon" href="${MARK}"><style>
:root{--navy:#091425;--paper:#f2efe8;--ink:#16191d;--muted:#646b71;--bronze:#d49a5a;--bronze-deep:#9b6431;--cyan:#36c5f0;--line:#d7d0c6;--act:#b4531f}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
.top{position:sticky;top:0;z-index:5;height:72px;padding:0 clamp(16px,4vw,70px);display:flex;align-items:center;gap:20px;background:rgba(9,20,37,.97);color:#f7f4ee;border-bottom:1px solid rgba(212,154,90,.25)}
.brand{display:flex;align-items:center;gap:12px;text-decoration:none;color:#b9c4cf;letter-spacing:.12em;font-size:13px;white-space:nowrap}.brand img{width:38px;height:38px}.brand b{color:#fff}
.top p{margin:0 0 0 auto;color:#b9c4cf;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.top a.public{padding:8px 12px;border:1px solid rgba(212,154,90,.6);border-radius:999px;color:#f4d3ad;text-decoration:none;font-size:11px;font-weight:700;white-space:nowrap}
.hero{background:var(--navy);color:#fff;padding:42px clamp(16px,5vw,76px) 46px;border-bottom:5px solid var(--bronze)}
.hero div{max-width:1370px;margin:0 auto}.kicker{margin:0 0 10px;font-size:12px;letter-spacing:.22em;font-weight:800;color:var(--bronze)}
.hero h1{margin:0;font-size:clamp(40px,6vw,76px);line-height:.92;letter-spacing:-.055em}.hero h1 span{color:transparent;-webkit-text-stroke:1.5px rgba(255,255,255,.9)}
main{max-width:1500px;margin:0 auto;padding:30px clamp(16px,5vw,76px) 60px}
.today{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:34px}
.stat{display:grid;gap:3px;background:#fff;border:1px solid #dcd5cb;border-top:4px solid var(--bronze);padding:18px 20px;color:inherit;text-decoration:none;min-width:0}
.stat span{font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;color:#7b8388}.stat b{font-size:19px;letter-spacing:-.01em}.stat small{color:var(--muted)}
.stat--act{border-top-color:var(--act);background:#fff7f0}.stat--act b{color:var(--act)}
main section{margin-top:34px}main section header{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 16px;margin-bottom:14px}
h2{margin:0;font-size:12px;letter-spacing:.22em;font-weight:800;text-transform:uppercase;color:var(--bronze-deep)}section header p{margin:0;color:var(--muted);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
.tile{display:flex;flex-direction:column;gap:8px;background:#fff;border:1px solid #dcd5cb;padding:22px;color:inherit;text-decoration:none;min-width:0}
a.tile:hover{border-color:var(--bronze)}.tile h3{margin:0;font-size:22px;line-height:1.1;letter-spacing:-.025em}
.tile h3 i{font-style:normal;font-size:10px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:#7b8388;border:1px solid #d7d0c6;padding:1px 6px;vertical-align:4px}
.tile p{margin:0;color:#4f585d;flex:1}.tile code{font:12px ui-monospace,Menlo,monospace;color:var(--bronze-deep);overflow-wrap:anywhere}
@media (max-width:1100px){.today{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:860px){.today,.grid{grid-template-columns:1fr}.top p{display:none}.top a.public{margin-left:auto}}
</style></head><body><header class="top"><a class="brand" href="/"><img src="${MARK}" alt=""><span><b>TPN</b> INTEL</span></a><p>Signed in as ${esc(viewer)}</p><a class="public" href="https://tpnintel.com/">Public site</a></header>
<section class="hero"><div><p class="kicker">RESERVED ACCESS</p><h1>Your intelligence, <span>in one place.</span></h1></div></section><main>
<div class="today">${observerCard}${engineCard}${nsoCard}${shaipingCard}</div>
${sections}
</main></body></html>`;
}
__name(page, "page");
async function handleRequest(request, env, deps = {}) {
  const access = await verifyAccess(request, env, deps);
  if (!access.ok) {
    return new Response(`Not available (${access.reason}). Sign in through tpnintel.com with a reader account.`, {
      status: access.status,
      headers: { ...SECURITY, "content-type": "text/plain; charset=utf-8" }
    });
  }
  if (!["GET", "HEAD"].includes(request.method)) return new Response("Not allowed.", { status: 405, headers: { ...SECURITY, allow: "GET, HEAD" } });
  const url = new URL(request.url);
  if (url.pathname !== "/") return new Response("Not found.", { status: 404, headers: { ...SECURITY, "content-type": "text/plain; charset=utf-8" } });
  const [today, shaiping] = await Promise.all([todayView(env.EVIDENCE_DB, deps.nowMs ?? Date.now()), shaipingRelease(env, deps.fetchImpl ?? fetch)]);
  today.shaiping = shaiping;
  return new Response(page({ viewer: access.email, today }), { headers: { ...SECURITY, "content-type": "text/html; charset=utf-8" } });
}
__name(handleRequest, "handleRequest");
var index_default = { fetch: /* @__PURE__ */ __name((request, env) => handleRequest(request, env), "fetch") };
export {
  SECTIONS,
  index_default as default,
  handleRequest,
  page,
  todayView
};
