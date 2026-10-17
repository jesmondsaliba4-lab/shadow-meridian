import { deskTabs, TAB_STYLE } from "./watch/page.js";

var esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
var fmt = new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Malta", day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
var when = (iso) => {
  const t = Date.parse(iso || "");
  return Number.isNaN(t) ? "\u2014" : fmt.format(t);
};
var safeUrl = (u) => /^https?:\/\//i.test(String(u || "")) ? String(u) : null;
var parse = (row) => {
  try {
    return row ? JSON.parse(row.body) : null;
  } catch {
    return null;
  }
};
var short = (id) => String(id || "").slice(0, 12);
function headlines(edition) {
  return new Set([
    edition?.dispatch?.lead?.title,
    ...(edition?.dispatch?.items || []).map((i) => i.headline),
    ...(edition?.meridian?.items || []).map((i) => i.headline)
  ].filter(Boolean));
}
function items(list, previous) {
  if (!list?.length) return `<p class="note">None.</p>`;
  return `<ol class="list">${list.map((i) => {
    const url = safeUrl(i.source_url);
    const isNew = previous && !previous.has(i.headline);
    return `<li>${isNew ? '<span class="new">new</span> ' : ""}<b>${esc(i.headline)}</b>${i.summary ? `<span class="sum">${esc(i.summary)}</span>` : ""}<span class="meta">${esc(i.theme || "")}${i.source_name ? ` \xB7 ${url ? `<a href="${esc(url)}" rel="noopener noreferrer" target="_blank">${esc(i.source_name)}</a>` : esc(i.source_name)}` : ""}${i.period ? ` \xB7 ${esc(i.period)}` : ""}</span></li>`;
  }).join("")}</ol>`;
}
function editionView(edition, previous) {
  if (!edition) return `<p class="note">Nothing here yet.</p>`;
  const lead = edition.dispatch?.lead || {};
  const lens = edition.meridian?.lens || {};
  const score = (v) => v === null || v === void 0 || Number.isNaN(Number(v)) ? "\u2014" : String(Math.round(Number(v) * 10) / 10);
  return `
  <h4>Dispatch \xB7 lead</h4>
  <div class="lead"><span class="meta">${esc(lead.kicker || "")}${lead.period ? ` \xB7 ${esc(lead.period)}` : ""}</span>${lead.context ? `<span class="ctx">Context: ${esc(lead.context)}</span>` : ""}<b>${esc(lead.title || "\u2014")}</b><span class="sum">${esc(lead.summary || "")}</span></div>
  <h4>Dispatch \xB7 items</h4>${items(edition.dispatch?.items, previous)}
  <h4>Meridian \xB7 ${esc(edition.meridian?.title || "context")}</h4>${items(edition.meridian?.items, previous)}
  <h4>Meridian \xB7 indices</h4>
  <table><tbody>
    <tr><td>Sovereign index</td><td class="num">${score(lens.index?.score)}</td></tr>
    <tr><td>Business attraction</td><td class="num">${score(lens.business?.score)}</td></tr>
    <tr><td>Conflict exposure / absorption</td><td class="num">${score(lens.conflict_resilience?.exposure_score)} / ${score(lens.conflict_resilience?.absorption_capacity)}</td></tr>
  </tbody></table>
  <p class="note">Sources as of ${esc(when(edition.as_of))} \xB7 Dispatch ${esc(short(edition.dispatch?.commit))} \xB7 Meridian ${esc(short(edition.meridian?.commit))}</p>`;
}
function renderDesk({ candidate, published, viewer, message }) {
  const cand = parse(candidate);
  const pub = parse(published);
  const same = candidate && published && candidate.edition_id === published.edition_id;
  const canPublish = candidate && candidate.valid === 1 && !same;
  const previous = pub ? headlines(pub) : null;
  return `<!doctype html>
<html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex, nofollow">
<title>Publish to Observer</title>
<style>
:root{--navy:#0a1226;--gold:#c89244;--paper:#f6f1e6;--ink:#1d2433;--muted:#5b6272;--line:#ddd3bf;--card:#fffdf8;--ok:#2f6b3a;--bad:#9b2c2c}
@media (prefers-color-scheme:dark){:root{--paper:#0d1424;--ink:#ebe5d8;--muted:#a3a9b7;--line:#2a3550;--card:#131c31;--ok:#7ccf8a;--bad:#f08a8a}}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header{background:var(--navy);color:#efe7d4;padding:16px 16px 0;border-bottom:3px solid var(--gold)}header h1{margin:0;font-size:20px}header p{margin:4px 0 0;color:#c9c2b2;font-size:13px}
${TAB_STYLE}
main{max-width:1200px;margin:0 auto;padding:16px}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
h2{margin:0 0 4px;font-size:18px}h4{margin:16px 0 6px;font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.list{margin:0;padding-left:20px}.list li{margin:0 0 10px}.lead b,.list b{display:block}.sum{display:block;font-size:13px}.meta{display:block;font-size:12px;color:var(--muted)}.ctx{display:block;font-size:12px;font-style:italic;color:var(--muted);margin:2px 0 4px}
.new{display:inline-block;background:var(--gold);color:#1d1406;font-size:10px;font-weight:700;text-transform:uppercase;padding:0 6px;border-radius:4px;margin-right:4px}
table{border-collapse:collapse;width:100%}td{padding:4px 6px;border-bottom:1px solid var(--line)}.num{text-align:right;font-variant-numeric:tabular-nums}
.note{color:var(--muted);font-size:13px}.ok{color:var(--ok)}.bad{color:var(--bad)}
.bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:0 0 16px}
button{font:inherit;font-weight:700;padding:10px 18px;border-radius:8px;border:0;background:var(--gold);color:#1d1406;cursor:pointer}button.secondary{background:transparent;border:1px solid var(--line);color:var(--ink)}
.msg{padding:10px 12px;border-radius:8px;border:1px solid var(--line);background:var(--card);margin:0 0 16px}
a{color:var(--gold)}
</style></head><body>
<header><h1>Publish to Observer</h1><p>Malta Observer publication desk \xB7 signed in as ${esc(viewer)} \xB7 nothing reaches maltaobserver.com until you press Publish</p>${deskTabs("observer")}</header>
<main>
${message ? `<p class="msg">${esc(message)}</p>` : ""}
<div class="bar">
  ${canPublish ? `<form method="post" action="/publish"><input type="hidden" name="edition_id" value="${esc(candidate.edition_id)}"><button type="submit">Publish this candidate to the Observer</button></form>` : ""}
  <form method="post" action="/refresh"><button class="secondary" type="submit">Prepare a fresh candidate now</button></form>
  <span class="note">${!candidate ? "No candidate prepared yet." : same ? "The candidate is what is already published." : candidate.valid === 1 ? `<span class="ok">The candidate passes the Observer's own checks.</span>` : `<span class="bad">The candidate fails the Observer's own checks and cannot be published.</span>`}</span>
</div>
<div class="cols">
  <section class="card"><h2>Candidate</h2><p class="note">Prepared ${esc(when(candidate?.prepared_at))} \xB7 ${esc(short(candidate?.edition_id))}</p>${editionView(cand, previous)}</section>
  <section class="card"><h2>Published now</h2><p class="note">${published ? `Approved ${esc(when(published.approved_at))} by ${esc(published.approved_by)} \xB7 ${esc(short(published.edition_id))}` : "Nothing published from this desk yet. The Observer still reads its old sources until it is switched to this desk."}</p>${editionView(pub, null)}</section>
</div>
<p class="note">The Dispatch lead's headline and text are taken from the same Dispatch item; a different key message from the brief is shown above it as context. The Malta ticker is not part of an edition; it updates on its own from the engine.</p>
</main></body></html>`;
}

export { renderDesk };
