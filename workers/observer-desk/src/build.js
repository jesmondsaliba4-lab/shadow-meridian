import { githubJsonWithMeta, githubResolveCommit, githubTreeWithMeta } from "./vendor/github.js";
import { alignDispatchLead } from "./dispatch-lead.js";
import { latestDispatchPaths, projectDispatch, projectMeridian, sourceUpdateIsValid } from "./vendor/observer-edition.js";

var MERIDIAN_REPOSITORY = "jesmondsaliba4-lab/meridian-index";
var DISPATCH_REPOSITORY = "jesmondsaliba4-lab/dispatch-pro";
var CONTRACT = "observer-source-update-v1.3";
async function sha256Hex(text) {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function buildCandidate({ token, meridianBranch = "main", dispatchBranch = "master", nowMs = Date.now() }) {
  if (!token) throw new Error("No GitHub read key is configured for the publication desk.");
  const [meridianHead, dispatchHead] = await Promise.all([
    githubResolveCommit(MERIDIAN_REPOSITORY, meridianBranch, { token }),
    githubResolveCommit(DISPATCH_REPOSITORY, dispatchBranch, { token })
  ]);
  const read = (repo, path, ref, maxBytes) => githubJsonWithMeta(repo, path, { token, ref, maxBytes });
  const [dataset, liveStatus, sovereign, business, resilience, vision2050, dispatchTree] = await Promise.all([
    read(MERIDIAN_REPOSITORY, "data/data.json", meridianHead.commit, 2 * 1024 * 1024),
    read(MERIDIAN_REPOSITORY, "data/live-status.json", meridianHead.commit, 256 * 1024),
    read(MERIDIAN_REPOSITORY, "data/sovereign.json", meridianHead.commit, 2 * 1024 * 1024),
    read(MERIDIAN_REPOSITORY, "data/business.json", meridianHead.commit, 2 * 1024 * 1024),
    read(MERIDIAN_REPOSITORY, "data/resilience.json", meridianHead.commit, 3 * 1024 * 1024),
    read(MERIDIAN_REPOSITORY, "data/vision2050.json", meridianHead.commit, 512 * 1024),
    githubTreeWithMeta(DISPATCH_REPOSITORY, dispatchHead.commit, { token })
  ]);
  const paths = latestDispatchPaths(dispatchTree.data);
  if (!paths.intelligence?.path || !paths.pipeline) throw new Error("The Dispatch repository has no current intelligence brief.");
  const [intelligence, pipeline] = await Promise.all([
    read(DISPATCH_REPOSITORY, paths.intelligence.path, dispatchHead.commit, 512 * 1024),
    read(DISPATCH_REPOSITORY, paths.pipeline, dispatchHead.commit, 2 * 1024 * 1024)
  ]);
  const dispatch = alignDispatchLead(projectDispatch({ intelligence: intelligence.data, pipeline: pipeline.data, commit: dispatchHead.commit }));
  const meridian = projectMeridian({
    dataset: dataset.data,
    liveStatus: liveStatus.data,
    sovereign: sovereign.data,
    business: business.data,
    resilience: resilience.data,
    vision2050: vision2050.data,
    commit: meridianHead.commit,
    now: nowMs
  });
  delete meridian.news_ticker;
  const times = [dispatch.source_updated_at, meridian.source_updated_at].map((v) => Date.parse(v || "")).filter(Number.isFinite);
  const edition = {
    contract_version: CONTRACT,
    as_of: times.length === 2 ? new Date(Math.max(...times)).toISOString() : null,
    geography: "Malta and Gozo",
    dispatch,
    meridian
  };
  const valid = Boolean(edition.as_of) && sourceUpdateIsValid({ ...edition, assembled_at: new Date(nowMs).toISOString() });
  const body = JSON.stringify(edition);
  return { edition_id: await sha256Hex(body), body, valid, meridian_commit: meridianHead.commit, dispatch_commit: dispatchHead.commit };
}
async function storeCandidate(db, candidate, { nowMs = Date.now() } = {}) {
  const at = new Date(nowMs).toISOString();
  await db.prepare(
    "INSERT INTO observer_editions (edition_id, body, prepared_at, meridian_commit, dispatch_commit, valid) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(candidate.edition_id, candidate.body, at, candidate.meridian_commit, candidate.dispatch_commit, candidate.valid ? 1 : 0).run();
  await db.prepare("INSERT INTO observer_candidates (edition_id, prepared_at) VALUES (?, ?)").bind(candidate.edition_id, at).run();
  return candidate.edition_id;
}
async function latestCandidate(db) {
  return db.prepare(
    `SELECT e.edition_id, e.body, c.prepared_at, e.meridian_commit, e.dispatch_commit, e.valid
       FROM observer_candidates c JOIN observer_editions e ON e.edition_id = c.edition_id
      ORDER BY c.candidate_id DESC LIMIT 1`
  ).first();
}
async function publishedEdition(db) {
  return db.prepare(
    `SELECT e.edition_id, e.body, e.prepared_at, a.approved_at, a.approved_by
       FROM observer_approvals a JOIN observer_editions e ON e.edition_id = a.edition_id
      ORDER BY a.approval_id DESC LIMIT 1`
  ).first();
}
async function approve(db, editionId, approvedBy, { nowMs = Date.now() } = {}) {
  await db.prepare("INSERT INTO observer_approvals (edition_id, approved_at, approved_by) VALUES (?, ?, ?)").bind(editionId, new Date(nowMs).toISOString(), approvedBy).run();
}

export { approve, buildCandidate, latestCandidate, publishedEdition, storeCandidate };
