import { approveWatch, latestWatchCandidate, prepareWatch, publishedWatch } from "./store.js";
import { parseBody, renderWatch } from "./page.js";

// Sunday evening in Malta (Cloudflare crons run in UTC: 19:00 CET, 20:00 CEST).
// The same string must be listed under [triggers] crons in wrangler.toml.
export const WATCH_CRON = "0 18 * * SUN";

const MESSAGES = {
  published: "Published. This is now the approved edition of the AI & Skills Watch.",
  prepared: "A fresh candidate has been prepared.",
  unchanged: "No new items since the last candidate.",
  failed: "The candidate could not be prepared. The published edition is unchanged.",
  invalid: "That edition cannot be published: it is not the current candidate or it fails the Watch's checks.",
  all_dropped: "Nothing was published: every item was dropped."
};

const back = (security, code) => new Response(null, { status: 303, headers: { ...security, location: `/watch?m=${code}` } });

// Returns a Response for /watch routes, or null for anything else.
export async function handleWatch(request, env, { url, access, html, text, sameSite, security, deps = {} }) {
  if (url.pathname !== "/watch" && !url.pathname.startsWith("/watch/")) return null;
  const db = env.EVIDENCE_DB;
  if (request.method === "GET" && url.pathname === "/watch") {
    const [candidate, published] = await Promise.all([latestWatchCandidate(db), publishedWatch(db)]);
    return html(renderWatch({ candidate, published, viewer: access.email, message: MESSAGES[url.searchParams.get("m")] || null }));
  }
  if (request.method !== "POST" || !["/watch/publish", "/watch/refresh"].includes(url.pathname)) return text(404, "Not found.");
  if (!sameSite(request, url)) return text(403, "Refused: this action must come from the publication desk page.");
  if (url.pathname === "/watch/refresh") {
    try {
      const r = await prepareWatch(env, deps);
      return back(security, r.changed ? "prepared" : "unchanged");
    } catch (error) {
      console.error(JSON.stringify({ event: "watch_candidate_failed", message: error instanceof Error ? error.message : String(error) }));
      return back(security, "failed");
    }
  }
  const form = await request.formData().catch(() => null);
  const editionId = String(form?.get("edition_id") || "");
  const candidate = await latestWatchCandidate(db);
  if (!candidate || candidate.edition_id !== editionId || candidate.valid !== 1) return back(security, "invalid");
  const ids = new Set((parseBody(candidate)?.items || []).map((i) => String(i.id)));
  const dropped = [...new Set((form?.getAll("drop") || []).map(String))];
  if (dropped.some((id) => !ids.has(id))) return back(security, "invalid");
  if (dropped.length >= ids.size) return back(security, "all_dropped");
  await approveWatch(db, editionId, access.email, dropped.sort(), deps);
  console.log(JSON.stringify({ event: "watch_edition_published", edition_id: editionId, dropped: dropped.length, by: access.email }));
  return back(security, "published");
}
