import { verifyAccess } from "./access.js";
import { approve, buildCandidate, latestCandidate, publishedEdition, storeCandidate } from "./build.js";
import { renderDesk } from "./page.js";

var SECURITY = {
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  "x-frame-options": "DENY",
  "referrer-policy": "same-origin",
  "x-content-type-options": "nosniff",
  "x-robots-tag": "noindex, nofollow",
  "cache-control": "no-store, private"
};
var MESSAGES = {
  published: "Published. maltaobserver.com shows this edition within about five minutes.",
  prepared: "A fresh candidate has been prepared.",
  unchanged: "The sources have not changed since the last candidate.",
  failed: "The candidate could not be prepared. The sources may be unreachable; the published edition is unchanged.",
  invalid: "That edition cannot be published: it is not the current candidate or it fails the Observer's checks."
};
var REASONS = {
  no_key: "No GitHub read key is set for the desk.",
  http_401: "GitHub did not accept the read key: it may be mistyped, expired or revoked. Set it again.",
  http_403: "GitHub refused the request: the key may lack access, or GitHub is limiting requests for a while.",
  http_404: "GitHub could not find a repository, branch or file the desk needs.",
  timeout: "GitHub took too long to answer. Try again in a few minutes.",
  database: "The EU database did not accept the candidate.",
  no_brief: "The Dispatch repository has no current intelligence brief."
};
function failureCode(error) {
  const code = String(error?.code || "");
  if (/^http_\d{3}$/.test(code) || /^[a-z_]{1,32}$/.test(code)) return code;
  const m = String(error?.message || "");
  if (/No GitHub read key/.test(m)) return "no_key";
  if (/no current intelligence brief/.test(m)) return "no_brief";
  if (error?.name === "TimeoutError" || error?.name === "AbortError" || /timed? ?out/i.test(m)) return "timeout";
  if (/D1|SQLITE|database/i.test(m)) return "database";
  return "other";
}
function messageFor(params) {
  const m = params.get("m");
  if (m !== "failed") return MESSAGES[m] || null;
  const why = String(params.get("why") || "");
  const reason = REASONS[why] || (/^[a-z0-9_]{1,32}$/.test(why) ? `Error code: ${why}.` : "");
  return `${MESSAGES.failed}${reason ? ` Reason: ${reason}` : ""}`;
}
var text = (status, body) => new Response(body, { status, headers: { ...SECURITY, "content-type": "text/plain; charset=utf-8" } });
var html = (body) => new Response(body, { status: 200, headers: { ...SECURITY, "content-type": "text/html; charset=utf-8" } });
var back = (code, why) => new Response(null, { status: 303, headers: { ...SECURITY, location: `/?m=${code}${why ? `&why=${encodeURIComponent(why)}` : ""}` } });
async function prepare(env, { nowMs = Date.now() } = {}) {
  const candidate = await buildCandidate({ token: env.GITHUB_READ_TOKEN, meridianBranch: env.GITHUB_MERIDIAN_BRANCH || "main", dispatchBranch: env.GITHUB_DISPATCH_BRANCH || "master", nowMs });
  const before = await latestCandidate(env.EVIDENCE_DB);
  await storeCandidate(env.EVIDENCE_DB, candidate, { nowMs });
  return { edition_id: candidate.edition_id, valid: candidate.valid, changed: before?.edition_id !== candidate.edition_id };
}
function sameSite(request, url) {
  const origin = request.headers.get("origin");
  const site = request.headers.get("sec-fetch-site");
  if (site) return site === "same-origin" && (origin === url.origin || origin === "null" || origin === null);
  return origin === url.origin;
}
async function handleRequest(request, env, deps = {}) {
  const url = new URL(request.url);
  const access = await verifyAccess(request, env, deps);
  if (!access.ok) return text(access.status, `Not available (${access.reason}). Sign in through tpnintel.com with a reader account.`);
  const db = env.EVIDENCE_DB;
  if (request.method === "GET" && url.pathname === "/") {
    const [candidate2, published] = await Promise.all([latestCandidate(db), publishedEdition(db)]);
    return html(renderDesk({ candidate: candidate2, published, viewer: access.email, message: messageFor(url.searchParams) }));
  }
  if (request.method !== "POST" || !["/publish", "/refresh"].includes(url.pathname)) return text(404, "Not found.");
  if (!sameSite(request, url)) return text(403, "Refused: this action must come from the publication desk page.");
  if (url.pathname === "/refresh") {
    try {
      const r = await prepare(env, deps);
      return back(r.changed ? "prepared" : "unchanged");
    } catch (error) {
      const why = failureCode(error);
      console.error(JSON.stringify({ event: "observer_candidate_failed", why, message: error instanceof Error ? error.message : String(error) }));
      return back("failed", why);
    }
  }
  const form = await request.formData().catch(() => null);
  const editionId = String(form?.get("edition_id") || "");
  const candidate = await latestCandidate(db);
  if (!candidate || candidate.edition_id !== editionId || candidate.valid !== 1) return back("invalid");
  await approve(db, editionId, access.email, deps);
  console.log(JSON.stringify({ event: "observer_edition_published", edition_id: editionId, by: access.email }));
  return back("published");
}
var index_default = {
  fetch: (request, env) => handleRequest(request, env),
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(prepare(env, { nowMs: controller.scheduledTime }).then(
      (r) => console.log(JSON.stringify({ event: "observer_candidate_prepared", ...r })),
      (e) => console.error(JSON.stringify({ event: "observer_candidate_failed", message: e instanceof Error ? e.message : String(e) }))
    ));
  }
};
export {
  index_default as default,
  failureCode,
  handleRequest,
  prepare
};

