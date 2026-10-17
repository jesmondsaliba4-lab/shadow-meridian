import { CHAPTERS } from "./select.js";

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const fmt = new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Malta", day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
const day = new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Malta", day: "numeric", month: "short" });
const when = (iso) => {
  const t = Date.parse(iso || "");
  return Number.isNaN(t) ? "—" : fmt.format(t);
};
const onDay = (iso) => {
  const t = Date.parse(iso || "");
  return Number.isNaN(t) ? "—" : day.format(t);
};
const safeUrl = (u) => /^https:\/\//i.test(String(u || "")) ? String(u) : null;
const short = (id) => String(id || "").slice(0, 12);

export function parseBody(row) {
  try {
    return row ? JSON.parse(row.body) : null;
  } catch {
    return null;
  }
}

export function parseDropped(row) {
  try {
    const value = JSON.parse(row?.dropped || "[]");
    return Array.isArray(value) ? value.map(String) : [];
  } catch {
    return [];
  }
}

// Tabs shared by both desk pages.
export function deskTabs(active) {
  const tab = (href, label, key) => `<a href="${href}"${active === key ? ' aria-current="page"' : ""}>${label}</a>`;
  return `<nav class="tabs">${tab("/", "Malta Observer", "observer")}${tab("/watch", "AI &amp; Skills Watch", "watch")}</nav>`;
}

export const TAB_STYLE = `.tabs{display:flex;gap:4px;margin:12px 0 -16px}.tabs a{color:#c9c2b2;text-decoration:none;padding:6px 12px;border-radius:6px 6px 0 0;font-size:14px}.tabs a[aria-current]{background:var(--paper);color:var(--ink);font-weight:700}`;

function itemLine(item, { form, dropped }) {
  const url = safeUrl(item.url);
  const headline = url ? `<a href="${esc(url)}" rel="noopener noreferrer" target="_blank">${esc(item.headline)}</a>` : esc(item.headline);
  const isDropped = dropped?.has(item.id);
  const control = form
    ? `<label class="drop"><input type="checkbox" name="drop" value="${esc(item.id)}"> Drop</label>`
    : isDropped ? '<span class="tag">dropped</span>' : "";
  return `<li class="${isDropped ? "gone" : ""}"><div class="row"><div><b>${headline}</b><span class="meta">${esc(item.chapter)} · ${esc(item.publisher)} · ${esc(onDay(item.published_at))} · ${esc(item.kind)}</span></div>${control}</div></li>`;
}

function editionList(edition, options = {}) {
  const items = Array.isArray(edition?.items) ? edition.items : [];
  if (!items.length) return `<p class="note">Nothing here yet.</p>`;
  return CHAPTERS.map((chapter) => {
    const inChapter = items.filter((i) => i.chapter === chapter);
    return inChapter.length ? `<h4>${esc(chapter)}</h4><ol class="list">${inChapter.map((i) => itemLine(i, options)).join("")}</ol>` : "";
  }).join("");
}

export function renderWatch({ candidate, published, viewer, message }) {
  const cand = parseBody(candidate);
  const pub = parseBody(published);
  const pubDropped = new Set(parseDropped(published));
  const canPublish = candidate && candidate.valid === 1 && cand?.items?.length;
  const research = (cand?.items || []).filter((i) => i.kind === "research").length;
  const news = (cand?.items || []).length - research;
  return `<!doctype html>
<html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex, nofollow">
<title>AI &amp; Skills Watch · Publish</title>
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
.list{margin:0;padding-left:20px}.list li{margin:0 0 10px}.list b{display:block;font-weight:600}.meta{display:block;font-size:12px;color:var(--muted)}
.row{display:flex;gap:12px;justify-content:space-between;align-items:flex-start}
.drop{flex:none;font-size:13px;color:var(--muted);white-space:nowrap;cursor:pointer;padding:2px 0}
li:has(input:checked) b,li.gone b{text-decoration:line-through;opacity:.55}
.tag{flex:none;font-size:10px;font-weight:700;text-transform:uppercase;border:1px solid var(--line);border-radius:4px;padding:0 6px;color:var(--muted)}
.note{color:var(--muted);font-size:13px}.ok{color:var(--ok)}.bad{color:var(--bad)}
.bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:0 0 16px}
button{font:inherit;font-weight:700;padding:10px 18px;border-radius:8px;border:0;background:var(--gold);color:#1d1406;cursor:pointer}button.secondary{background:transparent;border:1px solid var(--line);color:var(--ink)}
.msg{padding:10px 12px;border-radius:8px;border:1px solid var(--line);background:var(--card);margin:0 0 16px}
a{color:var(--gold)}.list a{color:inherit}
</style></head><body>
<header><h1>AI &amp; Skills Watch</h1><p>Weekly source list · signed in as ${esc(viewer)} · nothing goes live until you press Publish</p>${deskTabs("watch")}</header>
<main>
${message ? `<p class="msg">${esc(message)}</p>` : ""}
<div class="bar">
  <form method="post" action="/watch/refresh"><button class="secondary" type="submit">Prepare a fresh candidate now</button></form>
  <span class="note">${!candidate ? "No candidate prepared yet. One is prepared every Sunday evening." : candidate.valid === 1 ? `<span class="ok">The candidate passes the Watch's checks.</span>` : `<span class="bad">The candidate fails the Watch's checks and cannot be published.</span>`}</span>
</div>
<div class="cols">
  <section class="card"><h2>Candidate</h2>
    <p class="note">Prepared ${esc(when(candidate?.prepared_at))} · covers ${esc(onDay(cand?.window?.start))}–${esc(onDay(cand?.window?.end))} · ${research} research, ${news} news${cand ? ` · ${esc(cand.left_out)} of ${esc(cand.considered)} AI headlines left out by the rules` : ""} · ${esc(short(candidate?.edition_id))}</p>
    ${canPublish ? `<form method="post" action="/watch/publish"><input type="hidden" name="edition_id" value="${esc(candidate.edition_id)}">
      ${editionList(cand, { form: true })}
      <p class="note">Tick Drop on anything that should not go live. Everything else is published.</p>
      <button type="submit">Publish to the AI &amp; Skills Watch</button></form>` : editionList(cand)}
  </section>
  <section class="card"><h2>Published now</h2><p class="note">${published ? `Approved ${esc(when(published.approved_at))} by ${esc(published.approved_by)} · ${pubDropped.size} dropped · ${esc(short(published.edition_id))}` : "Nothing published yet."}</p>${editionList(pub, { dropped: pubDropped })}</section>
</div>
<p class="note">Each line is the publisher's own headline, name, date and link, labelled “source signal”. The Watch points readers to sources; it is not PFRI evidence and never changes an Index score.</p>
</main></body></html>`;
}
