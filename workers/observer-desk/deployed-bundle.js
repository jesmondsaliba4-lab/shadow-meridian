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

// src/vendor/github.js
import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
var API = "https://api.github.com";
var DEFAULT_TIMEOUT_MS = 8e3;
var DEFAULT_MAX_JSON_BYTES = 2 * 1024 * 1024;
var COMMIT_SHA = /^[a-f0-9]{40}$/i;
var REPOSITORY = /^[a-z0-9_.-]+\/[a-z0-9_.-]+$/i;
var REF_NAME = /^[a-z0-9._/-]{1,200}$/i;
var RESERVED_ADDRESSES = new BlockList();
[
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4]
].forEach(([address, prefix]) => RESERVED_ADDRESSES.addSubnet(address, prefix, "ipv4"));
[
  ["::", 128],
  ["::1", 128],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
  ["2001:db8::", 32]
].forEach(([address, prefix]) => RESERVED_ADDRESSES.addSubnet(address, prefix, "ipv6"));
var ConnectorFetchError = class extends Error {
  static {
    __name(this, "ConnectorFetchError");
  }
  constructor(code, message) {
    super(message);
    this.name = "ConnectorFetchError";
    this.code = code;
  }
};
function timeoutSignal(timeoutMs = DEFAULT_TIMEOUT_MS) {
  return AbortSignal.timeout(Math.max(250, Number(timeoutMs) || DEFAULT_TIMEOUT_MS));
}
__name(timeoutSignal, "timeoutSignal");
function responseMeta(response, provider) {
  return {
    provider,
    status: response.status,
    etag: response.headers.get("etag"),
    last_modified: response.headers.get("last-modified"),
    content_type: response.headers.get("content-type")
  };
}
__name(responseMeta, "responseMeta");
async function boundedJson(response, maxBytes = DEFAULT_MAX_JSON_BYTES) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new ConnectorFetchError("payload_too_large", "Connector payload exceeds the permitted size");
  }
  const body = await response.text();
  if (Buffer.byteLength(body, "utf8") > maxBytes) {
    throw new ConnectorFetchError("payload_too_large", "Connector payload exceeds the permitted size");
  }
  try {
    return JSON.parse(body);
  } catch {
    throw new ConnectorFetchError("invalid_payload", "Connector response is not valid JSON");
  }
}
__name(boundedJson, "boundedJson");
async function githubJsonWithMeta(repo, path, options = {}) {
  const token = options.token || process.env.GITHUB_READ_TOKEN || "";
  const ref = String(options.ref || "").trim();
  const repository = String(repo || "");
  const repositoryParts = repository.split("/");
  if (!REPOSITORY.test(repository) || repositoryParts.some((segment) => segment === "." || segment === "..")) {
    throw new ConnectorFetchError("invalid_endpoint", "GitHub repository is invalid");
  }
  if (!path || !/^[a-z0-9._/-]+$/i.test(String(path)) || String(path).startsWith("/") || String(path).split("/").some((segment) => !segment || segment === "." || segment === "..")) {
    throw new ConnectorFetchError("invalid_endpoint", "GitHub content path is invalid");
  }
  if (!COMMIT_SHA.test(ref)) throw new ConnectorFetchError("invalid_ref", "GitHub reads require a 40-character commit SHA");
  const url = new URL(`${API}/repos/${repo}/contents/${path}`);
  url.searchParams.set("ref", ref.toLowerCase());
  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "malta-observer/1.3"
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(url, { headers, cache: "no-store", redirect: "manual", signal: timeoutSignal(options.timeoutMs) });
  if (!response.ok) throw new ConnectorFetchError(`http_${response.status}`, `GitHub HTTP ${response.status}`);
  const payload = await boundedJson(response, options.maxBytes);
  if (!payload?.content) throw new ConnectorFetchError("invalid_payload", "GitHub payload has no content");
  let data;
  try {
    const text3 = Buffer.from(payload.content, payload.encoding || "base64").toString("utf8");
    data = JSON.parse(text3);
  } catch {
    throw new ConnectorFetchError("invalid_payload", "GitHub payload is not valid JSON");
  }
  return {
    data,
    meta: {
      ...responseMeta(response, "github"),
      repository: repo,
      path,
      ref: ref.toLowerCase(),
      content_sha: payload.sha || null
    }
  };
}
__name(githubJsonWithMeta, "githubJsonWithMeta");
function validRepository(repository) {
  const value = String(repository || "");
  const parts = value.split("/");
  return REPOSITORY.test(value) && !parts.some((segment) => segment === "." || segment === "..");
}
__name(validRepository, "validRepository");
function githubHeaders(token = "") {
  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "malta-observer/1.3"
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}
__name(githubHeaders, "githubHeaders");
async function githubResolveCommit(repo, ref, options = {}) {
  const repository = String(repo || "");
  const requestedRef = String(ref || "").trim();
  if (!validRepository(repository)) {
    throw new ConnectorFetchError("invalid_endpoint", "GitHub repository is invalid");
  }
  if (!REF_NAME.test(requestedRef) || requestedRef.startsWith("/") || requestedRef.endsWith("/") || requestedRef.split("/").some((segment) => !segment || segment === "." || segment === "..")) {
    throw new ConnectorFetchError("invalid_ref", "GitHub branch or tag is invalid");
  }
  const token = options.token || process.env.GITHUB_READ_TOKEN || "";
  const url = new URL(`${API}/repos/${repository}/commits/${encodeURIComponent(requestedRef)}`);
  const response = await fetch(url, {
    headers: githubHeaders(token),
    cache: "no-store",
    redirect: "manual",
    signal: timeoutSignal(options.timeoutMs)
  });
  if (!response.ok) throw new ConnectorFetchError(`http_${response.status}`, `GitHub HTTP ${response.status}`);
  const payload = await boundedJson(response, options.maxBytes || 512 * 1024);
  const commit = String(payload?.sha || "").toLowerCase();
  if (!COMMIT_SHA.test(commit)) throw new ConnectorFetchError("invalid_payload", "GitHub commit response has no immutable SHA");
  return {
    commit,
    requested_ref: requestedRef,
    committed_at: payload?.commit?.committer?.date || payload?.commit?.author?.date || null,
    meta: { ...responseMeta(response, "github"), repository, ref: requestedRef }
  };
}
__name(githubResolveCommit, "githubResolveCommit");
async function githubTreeWithMeta(repo, commit, options = {}) {
  const repository = String(repo || "");
  const immutableCommit = String(commit || "").trim().toLowerCase();
  if (!validRepository(repository)) {
    throw new ConnectorFetchError("invalid_endpoint", "GitHub repository is invalid");
  }
  if (!COMMIT_SHA.test(immutableCommit)) {
    throw new ConnectorFetchError("invalid_ref", "GitHub tree reads require a 40-character commit SHA");
  }
  const token = options.token || process.env.GITHUB_READ_TOKEN || "";
  const url = new URL(`${API}/repos/${repository}/git/trees/${immutableCommit}`);
  url.searchParams.set("recursive", "1");
  const response = await fetch(url, {
    headers: githubHeaders(token),
    cache: "no-store",
    redirect: "manual",
    signal: timeoutSignal(options.timeoutMs)
  });
  if (!response.ok) throw new ConnectorFetchError(`http_${response.status}`, `GitHub HTTP ${response.status}`);
  const data = await boundedJson(response, options.maxBytes || 3 * 1024 * 1024);
  if (!Array.isArray(data?.tree)) throw new ConnectorFetchError("invalid_payload", "GitHub tree response is invalid");
  return {
    data,
    meta: { ...responseMeta(response, "github"), repository, ref: immutableCommit }
  };
}
__name(githubTreeWithMeta, "githubTreeWithMeta");

// src/dispatch-lead.js
function alignDispatchLead(dispatch) {
  if (!dispatch || typeof dispatch !== "object" || !dispatch.lead) return dispatch;
  const first = Array.isArray(dispatch.items) ? dispatch.items.find((item) => item?.headline && item?.summary) : null;
  if (!first) return dispatch;
  const keyMessage = String(dispatch.lead.title || "").trim();
  const lead = { ...dispatch.lead, title: first.headline, summary: first.summary, lead_item_id: first.id || null };
  if (keyMessage && keyMessage !== first.headline) lead.context = keyMessage;
  else delete lead.context;
  return { ...dispatch, lead };
}
__name(alignDispatchLead, "alignDispatchLead");

// src/vendor/observer-edition.js
var DISPATCH_INTELLIGENCE = /^scripts\/render\/content\/intelligence_(\d{4}-\d{2}-\d{2})\.json$/;
var DISPATCH_DAILY = /^scripts\/render\/content\/daily_(\d{4}-\d{2}-\d{2})\.json$/;
function text(value = "") {
  return String(value).replace(/<br\s*\/?>/gi, " ").replace(/<[^>]+>/g, " ").replace(/&nbsp;/gi, " ").replace(/&amp;/gi, "&").replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'").replace(/\s+/g, " ").trim();
}
__name(text, "text");
function array(value) {
  return Array.isArray(value) ? value : [];
}
__name(array, "array");
function bounded(value, maximum = 1200) {
  const output = text(value);
  return output.length <= maximum ? output : `${output.slice(0, maximum - 1).trimEnd()}\u2026`;
}
__name(bounded, "bounded");
function headlineFromParagraph(paragraph) {
  const match = String(paragraph || "").match(/<strong>([\s\S]*?)<\/strong>/i);
  return bounded(match?.[1] || paragraph, 180).replace(/[.:;]+$/, "");
}
__name(headlineFromParagraph, "headlineFromParagraph");
function paragraphBody(paragraph) {
  return bounded(String(paragraph || "").replace(/<strong>[\s\S]*?<\/strong>/i, ""), 900);
}
__name(paragraphBody, "paragraphBody");
function sourceTags(paragraph) {
  return [...String(paragraph || "").matchAll(/\[([^\]]+)\]/g)].map((match) => text(match[1])).filter(Boolean);
}
__name(sourceTags, "sourceTags");
function datedPath(tree, pattern) {
  return array(tree?.tree).filter((entry) => entry?.type === "blob" && pattern.test(String(entry.path || ""))).map((entry) => ({ path: entry.path, date: String(entry.path).match(pattern)?.[1] || "" })).sort((a, b) => b.date.localeCompare(a.date))[0] || null;
}
__name(datedPath, "datedPath");
function latestDispatchPaths(tree) {
  return {
    intelligence: datedPath(tree, DISPATCH_INTELLIGENCE),
    daily: datedPath(tree, DISPATCH_DAILY),
    pipeline: array(tree?.tree).some((entry) => entry?.path === "public/data/intelligence-pipeline.json") ? "public/data/intelligence-pipeline.json" : null
  };
}
__name(latestDispatchPaths, "latestDispatchPaths");
function maltaPage(edition) {
  return array(edition?.pages).find((page) => /malta/i.test(String(page?.section_title || ""))) || null;
}
__name(maltaPage, "maltaPage");
function dispatchEditionUrl(date) {
  return `https://dispatch.nexus-tp.com/reports/current/Intelligence_Dispatch_${date}.docx`;
}
__name(dispatchEditionUrl, "dispatchEditionUrl");
function dispatchParagraphItems(intelligence, date) {
  const page = maltaPage(intelligence);
  return array(page?.paragraphs).slice(0, 4).map((paragraph, index) => {
    const tags = sourceTags(paragraph);
    return {
      id: `dispatch-intelligence-${date}-${index + 1}`,
      theme: index === 0 ? "Malta in the world" : "Institutions, economy and society",
      headline: headlineFromParagraph(paragraph),
      summary: paragraphBody(paragraph),
      source_application: "Dispatch PRO",
      source_name: tags.length ? `TPNintel Reports / Current Brief \xB7 ${tags.join(" \xB7 ")}` : "TPNintel Reports / Current Brief",
      source_url: dispatchEditionUrl(date),
      observed_at: date,
      role: "Interpretation",
      limitation: "Editorial interpretation of cited reporting; not an official national assessment."
    };
  });
}
__name(dispatchParagraphItems, "dispatchParagraphItems");
function pipelineMaltaItems(pipeline, limit = 4) {
  const section = array(pipeline?.draft?.sections).find((item) => String(item?.scope || "").toLowerCase() === "malta");
  return array(section?.items).filter((item) => item?.headline && item?.source_url).slice(0, limit).map((item) => ({
    id: String(item.id || `dispatch-signal-${item.date || "undated"}`),
    theme: text(item.category || "Malta source signal"),
    headline: bounded(item.headline, 180),
    summary: bounded(item.summary, 760),
    source_application: "Dispatch PRO",
    source_name: text(item.source_name || "Original publisher"),
    source_url: String(item.source_url),
    observed_at: String(item.date || item.collected_at || pipeline?.generated_at || ""),
    role: "Source signal",
    limitation: "Automatically collected source signal; it has not been independently corroborated by Malta Observer."
  }));
}
__name(pipelineMaltaItems, "pipelineMaltaItems");
function projectDispatch({ intelligence, pipeline, commit }) {
  const date = String(intelligence?.edition_date_label || pipeline?.draft?.period || pipeline?.generated_at || "").match(/\d{4}-\d{2}-\d{2}/)?.[0] || String(pipeline?.draft?.period || "") || null;
  const editorialItems = dispatchParagraphItems(intelligence, date);
  const signalItems = pipelineMaltaItems(pipeline, 4);
  const items2 = [...editorialItems, ...signalItems].filter((item, index, rows) => rows.findIndex((candidate) => candidate.headline === item.headline) === index).slice(0, 6);
  const firstMessage = array(intelligence?.key_messages).find((message) => /Malta|Prime Minister|Robert Abela/i.test(String(message))) || array(intelligence?.key_messages)[0] || items2[0]?.headline || "The current brief contains no Malta-specific item.";
  return {
    commit,
    period: date,
    source_updated_at: pipeline?.generated_at || date,
    lead: {
      kicker: "TPNintel Reports / Current Brief",
      title: bounded(firstMessage, 260),
      summary: items2[0]?.summary || "The current brief is available, but no Malta summary was supplied.",
      period: date,
      source_application: "Dispatch PRO",
      source_state: text(intelligence?.edition_kicker || pipeline?.draft?.editorial_state || "Editorial draft"),
      source_url: dispatchEditionUrl(date),
      role: "Interpretation",
      limitation: "Editorial analysis based on cited reporting; not an official national assessment or proof of policy effect."
    },
    items: items2
  };
}
__name(projectDispatch, "projectDispatch");
function meridianPriority(story) {
  const value = `${story?.headline || ""} ${story?.category || ""}`.toLowerCase();
  if (/electric|energy|grid|interconnector/.test(value)) return 60;
  if (/research|development|innovation/.test(value)) return 55;
  if (/work|employment|skills/.test(value)) return 50;
  if (/econom|trade|governance|institution/.test(value)) return 40;
  if (/sport|feast|entertainment/.test(value)) return 0;
  return 20;
}
__name(meridianPriority, "meridianPriority");
function meridianItems(dataset, limit = 6) {
  const malta = array(dataset?.entities).find((entity) => String(entity?.key || entity?.display_name || "").toLowerCase() === "malta");
  const candidates = [...array(malta?.stories), ...array(malta?.business_roundup?.stories)];
  return candidates.filter((story) => story?.headline && array(story?.sources)[0]?.url).filter((story) => !/work(?:ing)? in (?:their )?free time|right to disconnect/i.test(String(story.headline))).sort((a, b) => meridianPriority(b) - meridianPriority(a)).filter((story, index, rows) => rows.findIndex((candidate) => candidate.headline === story.headline) === index).slice(0, limit).map((story, index) => ({
    id: `meridian-malta-${index + 1}`,
    theme: text(story.category || "Longer-term context"),
    headline: bounded(story.headline, 200),
    summary: bounded(story.summary, 900),
    source_application: "Meridian Index",
    source_name: array(story.sources).map((source) => text(source.name)).filter(Boolean).join(" \xB7 "),
    source_url: String(array(story.sources)[0]?.url || ""),
    period: text(story.period || dataset?.generated_at?.slice?.(0, 10) || "Date unavailable"),
    role: "Context evidence",
    limitation: "This is contextual reporting. Check the cited source for its date and current status."
  }));
}
__name(meridianItems, "meridianItems");
function safeHttpsUrl(value) {
  try {
    const url = new URL(String(value || ""));
    return url.protocol === "https:" ? url.href : "";
  } catch {
    return "";
  }
}
__name(safeHttpsUrl, "safeHttpsUrl");
var LIVE_NEWS_WINDOW_MS = 24 * 60 * 60 * 1e3;
var LIVE_NEWS_FUTURE_TOLERANCE_MS = 5 * 60 * 1e3;
var LIVE_NEWS_MIN_HEARTBEAT_GRACE_MS = 90 * 60 * 1e3;
function meridianNewsTicker(dataset, liveStatus, limit = 8, now = Date.now()) {
  const malta = array(dataset?.entities).find((entity) => String(entity?.key || entity?.display_name || "").toLowerCase() === "malta");
  const monitoring = liveStatus && typeof liveStatus === "object" ? { ...dataset?.live_monitoring || {}, ...liveStatus } : dataset?.live_monitoring || {};
  const nowMs = new Date(now).getTime();
  const checkedAtMs = new Date(monitoring.last_success || 0).getTime();
  const cadenceMinutes = Number(monitoring.cadence_minutes);
  const heartbeatGraceMs = Number.isFinite(cadenceMinutes) && cadenceMinutes > 0 ? Math.max(LIVE_NEWS_MIN_HEARTBEAT_GRACE_MS, cadenceMinutes * 3 * 60 * 1e3) : LIVE_NEWS_MIN_HEARTBEAT_GRACE_MS;
  const heartbeatFresh = Number.isFinite(nowMs) && Number.isFinite(checkedAtMs) && checkedAtMs > 0 && checkedAtMs <= nowMs + LIVE_NEWS_FUTURE_TOLERANCE_MS && nowMs - checkedAtMs <= heartbeatGraceMs;
  const coverageWarnings = Number.isFinite(Number(monitoring.coverage_warning_count)) ? Math.max(0, Number(monitoring.coverage_warning_count)) : array(monitoring.source_status).filter((source) => ["partial", "empty", "unavailable"].includes(source?.state)).length;
  const coverageState = coverageWarnings > 0 || ["partial", "degraded"].includes(monitoring.state) ? "partial" : "complete";
  const items2 = array(malta?.stories).filter((story) => story?.briefing_state === "monitored" && story?.live_monitoring?.automated).map((story) => {
    const source = array(story?.sources).find((item) => safeHttpsUrl(item?.url));
    const observedAt = String(story?.live_monitoring?.seen_at || "");
    const observedAtMs = new Date(observedAt).getTime();
    if (!story?.headline || !source || !observedAt || !Number.isFinite(observedAtMs) || !Number.isFinite(nowMs) || observedAtMs < nowMs - LIVE_NEWS_WINDOW_MS || observedAtMs > nowMs + LIVE_NEWS_FUTURE_TOLERANCE_MS) return null;
    return {
      headline: bounded(story.headline, 180),
      theme: text(story.category || "Malta update"),
      source_name: text(source.name || "Original source"),
      source_url: safeHttpsUrl(source.url),
      observed_at: new Date(observedAt).toISOString(),
      signal_label: story.live_monitoring.status === "cross-source" ? "Cross-source signal" : "Source signal"
    };
  }).filter(Boolean).sort((a, b) => b.observed_at.localeCompare(a.observed_at)).filter((item, index, rows) => rows.findIndex((candidate) => candidate.headline === item.headline) === index).slice(0, limit);
  const checkedAt = String(monitoring.last_success || "");
  const publishedItems = heartbeatFresh ? items2 : [];
  return {
    state: !heartbeatFresh || monitoring.state === "degraded" || coverageState === "partial" && !publishedItems.length ? "unavailable" : publishedItems.length ? "current" : "no-current-signal",
    checked_at: checkedAt && !Number.isNaN(new Date(checkedAt).getTime()) ? new Date(checkedAt).toISOString() : null,
    cadence_minutes: Number.isFinite(cadenceMinutes) ? cadenceMinutes : null,
    coverage_state: coverageState,
    coverage_warning_count: coverageWarnings,
    items: publishedItems,
    boundary: "Monitored headlines are separate from the Observer\u2019s dated analysis. A source signal is not independent verification."
  };
}
__name(meridianNewsTicker, "meridianNewsTicker");
function competitionRank(values, target) {
  const scores = array(values).map(Number).filter(Number.isFinite);
  const score = Number(target);
  if (!Number.isFinite(score) || !scores.length) return null;
  return { rank: 1 + scores.filter((value) => value > score).length, total: scores.length };
}
__name(competitionRank, "competitionRank");
function rankLabel(ranking) {
  return ranking ? `#${ranking.rank} / ${ranking.total}` : "Not ranked";
}
__name(rankLabel, "rankLabel");
var ISO3_TO_ISO2 = Object.freeze({
  ALB: "AL",
  ARE: "AE",
  AUS: "AU",
  AUT: "AT",
  BEL: "BE",
  BGR: "BG",
  BIH: "BA",
  CHE: "CH",
  CHN: "CN",
  CYP: "CY",
  CZE: "CZ",
  DEU: "DE",
  DNK: "DK",
  DZA: "DZ",
  ESP: "ES",
  EST: "EE",
  FIN: "FI",
  FRA: "FR",
  GBR: "GB",
  GRC: "GR",
  HRV: "HR",
  HUN: "HU",
  IRL: "IE",
  ISL: "IS",
  ISR: "IL",
  ITA: "IT",
  JPN: "JP",
  LBN: "LB",
  LBY: "LY",
  LTU: "LT",
  LUX: "LU",
  LVA: "LV",
  MDA: "MD",
  MKD: "MK",
  MLT: "MT",
  MNE: "ME",
  MAR: "MA",
  NLD: "NL",
  NOR: "NO",
  POL: "PL",
  PRT: "PT",
  QAT: "QA",
  ROU: "RO",
  SAU: "SA",
  SRB: "RS",
  SVK: "SK",
  SVN: "SI",
  SWE: "SE",
  SYR: "SY",
  TUN: "TN",
  TUR: "TR",
  UKR: "UA",
  USA: "US",
  XKX: "XK"
});
function countryLeagueRows(registry, dataset, scoreFor, detailsFor = () => ({})) {
  const rows = Object.entries(registry || {}).map(([key, identity]) => {
    const record = dataset?.entities?.[key];
    const score = Number(scoreFor(record));
    const iso3 = text(identity?.iso3).toUpperCase();
    const iso2 = ISO3_TO_ISO2[iso3];
    if (!record || !Number.isFinite(score) || !iso2) return null;
    return {
      key,
      country: text(identity?.display_name || record?.display_name || key),
      iso2,
      iso3,
      score,
      ...detailsFor(record)
    };
  }).filter(Boolean).sort((a, b) => b.score - a.score || a.country.localeCompare(b.country));
  return rows.map((row) => ({
    ...row,
    rank: 1 + rows.filter((candidate) => candidate.score > row.score).length
  }));
}
__name(countryLeagueRows, "countryLeagueRows");
function leagueTable({ key, title, metric, summary, generatedAt, rows, note }) {
  const malta = rows.find((row) => row.key === "malta") || null;
  return {
    key,
    title,
    metric,
    summary,
    direction: "higher_is_better",
    generated_at: generatedAt || null,
    country_count: rows.length,
    ranking_method: "Higher scores first; countries with the same score share the same rank.",
    rows: rows.slice(0, 25),
    malta,
    note
  };
}
__name(leagueTable, "leagueTable");
function scoreText(value) {
  return Number(value).toLocaleString("en-GB", { maximumFractionDigits: 1 });
}
__name(scoreText, "scoreText");
function ordinal(value) {
  const number = Number(value);
  if (!Number.isInteger(number)) return text(value);
  const remainder = number % 100;
  if (remainder >= 11 && remainder <= 13) return `${number}th`;
  const suffix = { 1: "st", 2: "nd", 3: "rd" }[number % 10] || "th";
  return `${number}${suffix}`;
}
__name(ordinal, "ordinal");
function sentenceList(items2) {
  if (items2.length < 2) return items2[0] || "";
  return `${items2.slice(0, -1).join(", ")} and ${items2.at(-1)}`;
}
__name(sentenceList, "sentenceList");
function maltaWorldSummary(tables) {
  const byKey = new Map(tables.map((table) => [table.key, table]));
  const sovereign = byKey.get("sovereign_resilience");
  const business = byKey.get("business_attraction");
  const conflict = byKey.get("conflict_absorption");
  if (!sovereign?.malta || !business?.malta || !conflict?.malta) {
    return "Malta\u2019s position is shown separately for overall resilience, business attraction and its ability to cope with shocks.";
  }
  const exposureProfile = publicConflictProfile(conflict.malta.quadrant);
  return `Malta ranks ${ordinal(sovereign.malta.rank)} of ${sovereign.country_count} countries in the ThinkPeople Nexus Sovereign Index, with a score of ${scoreText(sovereign.malta.score)}, and ${ordinal(business.malta.rank)} for Business Attraction, with ${scoreText(business.malta.score)}. In the separate Conflict Resilience comparison, Malta ranks ${ordinal(conflict.malta.rank)} for its ability to cope with shocks. Its exposure score is ${scoreText(conflict.malta.exposure_score)}, placing it in the ${exposureProfile.toLowerCase()} group used in this comparison.`;
}
__name(maltaWorldSummary, "maltaWorldSummary");
function meridianWorldView(sovereign, business, resilience, commit) {
  const registry = business?.entities || {};
  const sovereignRows = countryLeagueRows(registry, sovereign, (record) => record?.aggregate_index, (record) => ({
    tier: text(record?.tier?.label || record?.tier)
  }));
  const businessRows = countryLeagueRows(registry, business, (record) => record?.business_attraction?.score, (record) => ({
    tier: text(record?.business_attraction?.tier)
  }));
  const conflictRows = countryLeagueRows(registry, resilience, (record) => record?.absorption_capacity, (record) => ({
    exposure_score: Number(record?.exposure_score),
    quadrant: text(record?.quadrant)
  }));
  const tables = [
    leagueTable({
      key: "sovereign_resilience",
      title: "ThinkPeople Nexus Sovereign Index",
      metric: "Overall resilience score",
      summary: "The overall resilience score built from the seven areas shown in the Malta Resilience report.",
      generatedAt: sovereign?.generated_at,
      rows: sovereignRows,
      note: "Regional averages are not included in this country comparison."
    }),
    leagueTable({
      key: "business_attraction",
      title: "Business Attraction",
      metric: "Business attraction score",
      summary: "A separate view of five parts of the business environment: financial capacity, operating conditions, talent, connectivity and innovation.",
      generatedAt: business?.generated_at,
      rows: businessRows,
      note: "This view is separate from the Sovereign Index and is not investment advice."
    }),
    leagueTable({
      key: "conflict_absorption",
      title: "Conflict resilience \u2014 ability to cope with shocks",
      metric: "Ability to cope with shocks",
      summary: "This table compares how well countries may cope with regional shocks. Exposure is shown separately because it measures a different part of risk.",
      generatedAt: resilience?.generated_at,
      rows: conflictRows,
      note: "Countries are ranked only on their ability to cope with shocks. This is not an overall conflict-risk ranking, and no position means that a country is risk-free."
    })
  ];
  return {
    kicker: "MALTA IN THE WORLD",
    title: "Where Malta stands in three country comparisons",
    summary: maltaWorldSummary(tables),
    source_application: "Meridian Index",
    source_state: "Repository observation \xB7 not a separately approved C-Ai.US release",
    repository_commit: commit,
    tables,
    limitation: "Each table compares countries using the date shown. Regional averages are left out, and countries with the same score share the same rank."
  };
}
__name(meridianWorldView, "meridianWorldView");
function sourceList(value) {
  return array(value).slice(0, 4).map((source) => ({
    name: bounded(source?.name || "Original source", 100),
    url: String(source?.url || "")
  })).filter((source) => source.url);
}
__name(sourceList, "sourceList");
function electionFacts(summary) {
  const values = [...String(summary || "").matchAll(/(\d+(?:\.\d+)?)%/g)].map((match) => match[1]);
  const labels = ["PL vote", "PN vote", "Turnout"];
  return values.slice(0, 3).map((value, index) => ({ label: labels[index], value: `${index === 2 ? "\u2248" : ""}${value}%` }));
}
__name(electionFacts, "electionFacts");
var INDEX_COMPONENTS = [
  { key: "credit_rating", label: "Credit ratings", weight: 20, definition: "Independent ratings of Malta\u2019s ability to repay government debt." },
  { key: "economic_stability", label: "Economic stability", weight: 20, definition: "Growth, jobs, prices, government finances and Malta\u2019s balance with the rest of the world." },
  { key: "geopolitical_stability", label: "Geopolitical stability", weight: 20, definition: "Exposure to regional tension, conflict spreading across borders, and dependence on key routes or partners." },
  { key: "political_stability", label: "Political stability", weight: 10, definition: "Stable constitutional government and the absence of serious political violence." },
  { key: "institutional_integrity", label: "Institutional integrity", weight: 10, definition: "Rule of law, public accountability, control of corruption and safeguards around public institutions." },
  { key: "ai_readiness", label: "AI readiness", weight: 10, definition: "Malta\u2019s ability to govern, use and benefit from AI responsibly." },
  { key: "wellbeing", label: "Wellbeing", weight: 10, definition: "Economic security, health and how people rate their lives." }
];
var CREDIT_AGENCIES = {
  sp: "S&P Global Ratings",
  moodys: "Moody\u2019s Ratings",
  fitch: "Fitch Ratings"
};
var CREDIT_SOURCE_IDS = {
  sp: "credit-sp",
  moodys: "credit-moodys",
  fitch: "credit-fitch"
};
var SOURCE_ID_HINTS = {
  economic_stability: ["economic-commission", "economic-fitch-report"],
  geopolitical_stability: ["geopolitical-election", "geopolitical-energy"],
  political_stability: ["political-election", "political-wgi"],
  institutional_integrity: ["institutional-rule-of-law", "institutional-transparency"],
  ai_readiness: ["ai-strategy", "ai-budget", "ai-digital-decade"],
  wellbeing: ["wellbeing-eurostat", "wellbeing-happiness", "geopolitical-election"]
};
function readableDate(value) {
  const match = String(value || "").match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (!match) return text(value || "Date unavailable");
  const date = /* @__PURE__ */ new Date(`${match[1]}-${match[2]}-${match[3]}T00:00:00Z`);
  return new Intl.DateTimeFormat("en-GB", {
    day: "numeric",
    month: "long",
    year: "numeric",
    timeZone: "UTC"
  }).format(date);
}
__name(readableDate, "readableDate");
function weightPercent(value, fallback) {
  const weight = Number(value);
  if (!Number.isFinite(weight)) return fallback;
  return weight <= 1 ? weight * 100 : weight;
}
__name(weightPercent, "weightPercent");
function displayDirection(value) {
  const output = text(value);
  return output ? `${output.charAt(0).toUpperCase()}${output.slice(1)}` : null;
}
__name(displayDirection, "displayDirection");
function publicConflictProfile(value) {
  const key = text(value).toLowerCase().replaceAll(" ", "-");
  const labels = {
    insulated: "Lower exposure",
    "resilient-frontline": "Higher exposure, stronger capacity",
    "fragile-frontline": "Higher exposure, weaker capacity",
    exposed: "Higher exposure"
  };
  return labels[key] || displayDirection(key.replaceAll("-", " ")) || "Not classified";
}
__name(publicConflictProfile, "publicConflictProfile");
function publicReadinessStatus(value) {
  const key = text(value).toLowerCase().replaceAll("_", " ");
  if (key === "provisional") return "Early estimate";
  if (key === "proxy only") return "Related indicator";
  return displayDirection(key);
}
__name(publicReadinessStatus, "publicReadinessStatus");
function sovereignScoreNarrative(entry, components) {
  const ranked = components.filter((component) => Number.isFinite(Number(component.score))).map((component) => ({ ...component, score: Number(component.score) })).sort((a, b) => b.score - a.score);
  if (!ranked.length) return "The current scores for Malta\u2019s seven resilience areas are not available.";
  const leadingCount = Math.max(1, ranked.length - 3);
  const leaders = ranked.slice(0, leadingCount);
  const lower = ranked.slice(leadingCount);
  const headlineScore = Number(entry?.aggregate_index);
  const headline = Number.isFinite(headlineScore) ? `${scoreText(headlineScore)} overall score` : "overall score";
  const describe = /* @__PURE__ */ __name((items2) => sentenceList(items2.map((component) => `${component.label} (${scoreText(component.score)})`)), "describe");
  if (!lower.length) return `Malta\u2019s ${headline} is built from ${describe(leaders)}.`;
  const lowest = lower.at(-1);
  return `Malta\u2019s ${headline} is supported most strongly by ${describe(leaders)}. The lower-scoring areas are ${describe(lower)}, with ${lowest.label.toLowerCase()} the lowest.`;
}
__name(sovereignScoreNarrative, "sovereignScoreNarrative");
function indexInputBasis(entry, sovereign) {
  const sources = [];
  const sourceByIdentity = /* @__PURE__ */ new Map();
  const registerSource = /* @__PURE__ */ __name((source, suggestedId) => {
    const name = bounded(source?.name || "Source", 220);
    const url = String(source?.url || "");
    if (!name && !url) return null;
    const identity = url || name.toLowerCase();
    if (sourceByIdentity.has(identity)) return sourceByIdentity.get(identity);
    const id = suggestedId || `source-${sources.length + 1}`;
    sourceByIdentity.set(identity, id);
    sources.push({ id, name, ...url ? { url } : {} });
    return id;
  }, "registerSource");
  const ratings = Object.entries(entry?.credit_ratings || {});
  const creditObservations = ratings.map(([agency, rating]) => ({
    label: CREDIT_AGENCIES[agency] || text(agency),
    value: text(rating?.rating || "Not rated"),
    detail: [
      Number.isFinite(Number(rating?.score)) ? `Score ${rating.score}` : "",
      rating?.outlook ? `${text(rating.outlook)} outlook` : "",
      rating?.date ? readableDate(rating.date) : ""
    ].filter(Boolean).join(" \xB7 ")
  }));
  const creditSourceIds = ratings.map(([agency, rating]) => registerSource(
    rating?.source,
    CREDIT_SOURCE_IDS[agency] || `credit-${agency}`
  )).filter(Boolean);
  const outlooks = [...new Set(ratings.map(([, rating]) => text(rating?.outlook)).filter(Boolean))];
  const creditDirection = outlooks.length === 1 ? `${displayDirection(outlooks[0])} outlooks` : outlooks.length > 1 ? "Mixed outlooks" : null;
  const creditRationale = creditObservations.length ? `${creditObservations.length} current long-term credit ratings\u2014${creditObservations.map((item) => item.value).join(", ")}\u2014produce an average score of ${entry.credit_average_score}. ${outlooks.length === 1 ? `All ${creditObservations.length} outlooks are ${outlooks[0]}.` : "The outlooks are mixed."}` : "The credit part of the score averages available current long-term foreign-currency sovereign ratings on a 0\u2013100 scale.";
  const weights = sovereign?.methodology?.weights || {};
  const components = INDEX_COMPONENTS.map((definition) => {
    if (definition.key === "credit_rating") {
      return {
        key: definition.key,
        label: definition.label,
        definition: definition.definition,
        score: entry.credit_average_score,
        weight: weightPercent(weights.credit_rating, definition.weight),
        direction: creditDirection,
        rationale: creditRationale,
        observations: creditObservations,
        source_ids: creditSourceIds
      };
    }
    const pillar = entry?.pillars?.[definition.key] || {};
    const sourceIds = array(pillar.sources).map((source, index) => registerSource(
      source,
      SOURCE_ID_HINTS[definition.key]?.[index] || `${definition.key}-${index + 1}`
    )).filter(Boolean);
    return {
      key: definition.key,
      label: definition.label,
      definition: definition.definition,
      score: pillar.score,
      weight: weightPercent(weights[definition.key], definition.weight),
      direction: displayDirection(pillar.direction),
      rationale: bounded(pillar.rationale || `${definition.label} has a score of ${pillar.score} in this dated evidence.`, 1200),
      source_ids: sourceIds
    };
  });
  const evidenceDate = sovereign?.generated_at ? readableDate(sovereign.generated_at) : null;
  return {
    title: "Resilience scoring facts",
    summary: sovereignScoreNarrative(entry, components),
    as_of: evidenceDate ? `Evidence dated ${evidenceDate}` : "Evidence date unavailable",
    components,
    sources,
    note: evidenceDate ? `The evidence was last updated on ${evidenceDate}. ThinkPeople Nexus chooses the indicators and how they are combined. Listing a source does not mean that the source endorses the score.` : "The evidence date was not available. ThinkPeople Nexus chooses the indicators and how they are combined. Listing a source does not mean that the source endorses the score."
  };
}
__name(indexInputBasis, "indexInputBasis");
function meridianIndexLens(dataset, sovereign) {
  const entry = sovereign?.entities?.malta;
  if (!entry) return null;
  const inputBasis = indexInputBasis(entry, sovereign);
  const euKeys = new Set(array(dataset?.entities).filter((entity) => entity?.region === "EU").map((entity) => entity.key));
  const allEntries = Object.values(sovereign?.entities || {}).filter((item) => !item?.is_regional_average);
  const euEntries = Object.entries(sovereign?.entities || {}).filter(([key]) => euKeys.has(key)).map(([, value]) => value);
  const pillars = [
    { label: "Credit", score: entry.credit_average_score },
    { label: "Economic stability", score: entry.pillars?.economic_stability?.score },
    { label: "Geopolitical stability", score: entry.pillars?.geopolitical_stability?.score },
    { label: "Political stability", score: entry.pillars?.political_stability?.score },
    { label: "Institutional integrity", score: entry.pillars?.institutional_integrity?.score },
    { label: "AI readiness", score: entry.pillars?.ai_readiness?.score },
    { label: "Wellbeing", score: entry.pillars?.wellbeing?.score }
  ].filter((pillar) => Number.isFinite(Number(pillar.score)));
  const rankedPillars = [...pillars].sort((a, b) => Number(b.score) - Number(a.score));
  const strongestAreas = sentenceList(rankedPillars.slice(0, 2).map((pillar) => pillar.label.toLowerCase()));
  const weakestArea = rankedPillars.at(-1)?.label.toLowerCase();
  const scoreSummary = strongestAreas && weakestArea ? `Malta scores ${scoreText(entry.aggregate_index)}, placing it in the ${text(entry.tier?.label || "unclassified")} range. ${displayDirection(strongestAreas)} are the strongest areas; ${weakestArea} is the weakest.` : `Malta scores ${scoreText(entry.aggregate_index)}, placing it in the ${text(entry.tier?.label || "unclassified")} range.`;
  return {
    kicker: "SOVEREIGN RESILIENCE INDEX",
    title: "Meridian \u2014 ThinkPeople Nexus Sovereign Index",
    score: entry.aggregate_index,
    tier: text(entry.tier?.label || "Not classified"),
    ranks: [
      { label: "Global", value: rankLabel(competitionRank(allEntries.map((item) => item?.aggregate_index), entry.aggregate_index)) },
      { label: "EU", value: rankLabel(competitionRank(euEntries.map((item) => item?.aggregate_index), entry.aggregate_index)) }
    ],
    summary: scoreSummary,
    pillars,
    methodology: "Credit, economic stability and geopolitical stability each make up 20% of the score. Political stability, institutional integrity, AI readiness and wellbeing each make up 10%. The source list below shows the evidence used.",
    input_basis: inputBasis,
    source_application: "Meridian Index",
    source_name: "Sovereign Resilience Index dataset",
    source_url: "https://meridian.nexus-tp.com",
    observed_at: sovereign.generated_at ? `Evidence dated ${readableDate(sovereign.generated_at)}` : "Evidence date unavailable",
    role: "Overall resilience score built from seven areas",
    source_state: "Repository observation \xB7 not a separately approved C-Ai.US release",
    limitation: `The sources reflect the evidence available for this Malta score. ThinkPeople Nexus chooses the indicators and how they are combined. The score is not an official index from any organisation listed as a source, and listing a source does not mean endorsement. The worldwide comparison covers ${allEntries.filter((item) => Number.isFinite(Number(item?.aggregate_index))).length} countries; Malta\u2019s EU position covers ${euEntries.filter((item) => Number.isFinite(Number(item?.aggregate_index))).length} countries.`
  };
}
__name(meridianIndexLens, "meridianIndexLens");
function meridianElectionLens(dataset) {
  const malta = array(dataset?.entities).find((entity) => entity?.key === "malta");
  const election = malta?.election;
  if (!election) return null;
  const last = election.last_election || {};
  const next = election.next_election || {};
  const polling = election.polling_trend || {};
  const noPostElectionPoll = /no published national voting-intention poll/i.test(String(polling.summary || ""));
  return {
    kicker: "ELECTION WATCH",
    title: "The new mandate, and what comes next",
    last_election: {
      date: text(last.date || "Date unavailable"),
      type: text(last.type || ""),
      headline: bounded(last.headline, 220),
      summary: bounded(last.summary, 850),
      facts: electionFacts(last.summary),
      sources: sourceList(last.sources)
    },
    next_election: {
      date: text(next.date || "No date set"),
      type: text(next.type || ""),
      summary: bounded(next.summary, 650),
      sources: sourceList(next.sources)
    },
    polling_trend: {
      as_of: noPostElectionPoll ? "No post-election poll" : "Latest cited poll",
      summary: bounded(polling.summary, 700),
      sources: sourceList(polling.sources)
    },
    source_application: "Meridian Index",
    source_name: "Election Watch \xB7 Malta record",
    observed_at: dataset?.generated_at ? `Evidence dated ${readableDate(dataset.generated_at)}` : "Evidence date unavailable",
    role: "Dated election overview",
    source_state: "Repository observation \xB7 not a separately approved C-Ai.US release",
    limitation: noPostElectionPoll ? "This summary draws on the election reports cited here. Malta Observer has not independently checked the vote and turnout figures. No post-election poll was available, so this page does not claim to show current party support." : "This summary draws on the election and polling reports cited here. Malta Observer has not independently checked the figures. The cited poll is dated and does not by itself show current party support."
  };
}
__name(meridianElectionLens, "meridianElectionLens");
function meridianStatisticsLens(business) {
  const malta = business?.entities?.malta;
  const pulse = malta?.economic_pulse;
  if (!pulse) return null;
  const oneDecimal = /* @__PURE__ */ __name((value) => Number(value).toLocaleString("en-GB", { minimumFractionDigits: 1, maximumFractionDigits: 1 }), "oneDecimal");
  const integer = /* @__PURE__ */ __name((value) => Number(value).toLocaleString("en-GB", { maximumFractionDigits: 0 }), "integer");
  const conversion = business?.currency_conversion;
  const euroRate = Number(conversion?.eur_usd_rate);
  const hasEuroConversion = Number.isFinite(euroRate) && euroRate > 0 && String(conversion?.source_currency || "").toUpperCase() === "USD" && String(conversion?.default_display_currency || "").toUpperCase() === "EUR";
  const sourceNominalGdp = pulse.gdp_nominal_usd_bn?.value;
  const sourceGdpPerCapita = pulse.gdp_per_capita_usd?.value;
  const euroNominalGdp = hasEuroConversion ? Number(sourceNominalGdp) / euroRate : null;
  const euroGdpPerCapita = hasEuroConversion ? Number(sourceGdpPerCapita) / euroRate : null;
  const conversionDate = conversion?.reference_date ? readableDate(conversion.reference_date) : "date unavailable";
  return {
    kicker: "ECONOMIC PULSE",
    title: "Malta economic pulse",
    summary: hasEuroConversion ? "The latest IMF estimates and forecasts available for Malta, with estimated euro values shown beside the original US-dollar figures." : "The latest available IMF figures for Malta. Estimates and projections remain clearly labelled.",
    items: [
      {
        label: "Nominal GDP",
        value: hasEuroConversion ? `\u20AC${oneDecimal(euroNominalGdp)}bn` : `US$${oneDecimal(sourceNominalGdp)}bn`,
        ...hasEuroConversion ? { secondary_value: `US$${oneDecimal(sourceNominalGdp)}bn` } : {},
        period: pulse.gdp_nominal_usd_bn?.year,
        status: text(pulse.gdp_nominal_usd_bn?.status)
      },
      {
        label: "GDP per capita",
        value: hasEuroConversion ? `\u20AC${integer(euroGdpPerCapita)}` : `US$${integer(sourceGdpPerCapita)}`,
        ...hasEuroConversion ? { secondary_value: `US$${integer(sourceGdpPerCapita)}` } : {},
        period: pulse.gdp_per_capita_usd?.year,
        status: text(pulse.gdp_per_capita_usd?.status)
      },
      { label: "Real GDP growth", value: `${oneDecimal(pulse.real_gdp_growth_pct?.value)}%`, period: pulse.real_gdp_growth_pct?.year, status: text(pulse.real_gdp_growth_pct?.status) },
      { label: "Unemployment", value: `${oneDecimal(pulse.unemployment_pct?.value)}%`, period: pulse.unemployment_pct?.year, status: text(pulse.unemployment_pct?.status) }
    ],
    ...hasEuroConversion ? {
      currency_note: `Indicative euro equivalents use the ECB reference rate of \u20AC1 = US$${euroRate.toLocaleString("en-GB", { minimumFractionDigits: 4, maximumFractionDigits: 4 })}, dated ${conversionDate}. IMF source values remain in US dollars.`
    } : {},
    source_application: "Meridian Index",
    source_name: hasEuroConversion ? "IMF World Economic Outlook \xB7 April 2026 \xB7 ECB reference-rate conversion" : "IMF World Economic Outlook Database \xB7 April 2026 vintage",
    source_url: "https://data.imf.org/Datasets/WEO",
    observed_at: business?.generated_at ? `Data current to ${readableDate(business.generated_at)}` : "Data date unavailable",
    role: "Sourced macroeconomic statistics",
    source_state: "Repository observation \xB7 not a separately approved C-Ai.US release",
    limitation: hasEuroConversion ? "The 2025 values are estimates and the 2026 values projections. Euro values are indicative display conversions, not separately published IMF observations." : "The 2025 values are estimates and the 2026 values projections. IMF monetary values remain in US dollars."
  };
}
__name(meridianStatisticsLens, "meridianStatisticsLens");
var BUSINESS_DIMENSIONS = [
  { key: "macro_and_finance", label: "Economic and financial strength" },
  { key: "operating_environment", label: "Business conditions" },
  { key: "talent_and_labour", label: "People and skills" },
  { key: "connectivity_and_market_access", label: "Connections and market reach" },
  { key: "innovation_and_scalability", label: "Innovation and growth potential" }
];
function meridianBusinessLens(business) {
  const malta = business?.entities?.malta;
  const diagnostic = malta?.business_attraction;
  if (!diagnostic) return null;
  const allEntries = Object.values(business?.entities || {});
  const euEntries = allEntries.filter((entry) => entry?.region === "EU");
  const globalRank = competitionRank(allEntries.map((entry) => entry?.business_attraction?.score), diagnostic.score);
  const euRank = competitionRank(euEntries.map((entry) => entry?.business_attraction?.score), diagnostic.score);
  const weights = business?.methodology?.weights || {};
  const dimensions = BUSINESS_DIMENSIONS.map((definition) => ({
    ...definition,
    score: diagnostic?.dimensions?.[definition.key],
    weight: weightPercent(weights[definition.key], 0)
  })).filter((dimension) => Number.isFinite(Number(dimension.score)));
  const maturityLabels = new Map(array(business?.methodology?.maturity_levels).map((level) => [level?.key, text(level?.label)]));
  const industryGroups = array(malta?.industries).reduce((groups, industry) => {
    const key = text(industry?.maturity);
    if (!key || !industry?.name) return groups;
    let group = groups.find((item) => item.key === key);
    if (!group) {
      group = {
        key,
        label: maturityLabels.get(key) || displayDirection(key.replaceAll("_", " ")),
        classification: "Meridian maturity classification",
        items: []
      };
      groups.push(group);
    }
    group.items.push(text(industry.name));
    return groups;
  }, []);
  const rankedDimensions = [...dimensions].sort((a, b) => Number(b.score) - Number(a.score));
  const strongestDimensions = sentenceList(rankedDimensions.slice(0, 2).map((dimension) => dimension.label));
  const weakestDimension = rankedDimensions.at(-1)?.label;
  const businessSummary = strongestDimensions && weakestDimension ? `Malta\u2019s business position is mixed. ${strongestDimensions} are the strongest areas; ${weakestDimension} is the weakest.` : "Malta\u2019s business position is mixed. The five areas are shown with their current scores.";
  return {
    kicker: "BUSINESS & INDUSTRY",
    title: "Malta\u2019s business and industry profile",
    score: diagnostic.score,
    tier: text(diagnostic.tier),
    direction: displayDirection(diagnostic.direction),
    ranks: [
      { label: "Global", value: rankLabel(globalRank) },
      { label: "EU", value: rankLabel(euRank) }
    ],
    rank: `Global ${rankLabel(globalRank)} \xB7 EU ${rankLabel(euRank)}`,
    summary: businessSummary,
    dimensions,
    industries: industryGroups,
    methodology: "This separate five-part business view gives economic and financial strength and business conditions 25% each; people and skills 20%; connections and market reach and innovation and growth potential 15% each.",
    source_application: "Meridian Index",
    source_name: "Business Attraction & Industry Landscape dataset",
    source_url: "https://meridian.nexus-tp.com",
    observed_at: business?.generated_at ? `Data current to ${readableDate(business.generated_at)}` : "Data date unavailable",
    role: "Separate five-part business view",
    source_state: "Repository observation \xB7 not a separately approved C-Ai.US release",
    limitation: "This is a ThinkPeople Nexus business view, separate from the Sovereign Index. It is not an IMF, World Bank, OECD or UNCTAD rating, and it is not investment advice. The industry groups are ThinkPeople Nexus categories."
  };
}
__name(meridianBusinessLens, "meridianBusinessLens");
function conflictRationale(value) {
  const sentences = text(value).split(/(?<=[.!?])\s+/);
  return bounded(sentences.filter((sentence) => !/(SOCAR|Electrogas|contract expires|gas contract deadline|13 August 2026)/i.test(sentence)).join(" "), 1e3);
}
__name(conflictRationale, "conflictRationale");
function meridianConflictLens(resilience) {
  const malta = resilience?.entities?.malta;
  if (!malta) return null;
  const dimensions = array(resilience?.methodology?.dimensions);
  const components = dimensions.map((dimension) => {
    const component = malta?.components?.[dimension.key] || {};
    return {
      key: text(dimension.key),
      label: text(dimension.label),
      score: component.score,
      weight: weightPercent(dimension.weight, 0),
      summary: conflictRationale(component.rationale),
      sources: sourceList(component.sources)
    };
  }).filter((component) => component.key && Number.isFinite(Number(component.score)));
  const quadrantKey = text(malta.quadrant);
  const quadrant = array(resilience?.methodology?.quadrants).find((item) => item?.key === quadrantKey);
  const evidenceDate = resilience?.generated_at ? readableDate(resilience.generated_at) : null;
  const exposureProfile = publicConflictProfile(quadrantKey);
  const rankedComponents = [...components].sort((a, b) => Number(b.score) - Number(a.score));
  const strongestComponent = rankedComponents[0]?.label;
  const weakestComponent = rankedComponents.at(-1)?.label;
  const conflictSummary = strongestComponent && weakestComponent ? `In this assessment, Malta\u2019s exposure level is ${exposureProfile.toLowerCase()}. Its ability to cope with shocks is scored ${scoreText(malta.absorption_capacity)} out of 100. ${strongestComponent} is the strongest area; ${weakestComponent} is the weakest.` : `In this assessment, Malta\u2019s exposure level is ${exposureProfile.toLowerCase()}. Its ability to cope with shocks is scored ${scoreText(malta.absorption_capacity)} out of 100.`;
  return {
    kicker: "CONFLICT EXPOSURE & RESILIENCE",
    title: "Malta\u2019s exposure and ability to cope with regional shocks",
    exposure_score: malta.exposure_score,
    absorption_capacity: malta.absorption_capacity,
    quadrant: text(quadrant?.label || displayDirection(quadrantKey)),
    quadrant_key: quadrantKey,
    summary: conflictSummary,
    components,
    exposure_definition: bounded(resilience?.methodology?.exposure_definition || "", 300),
    source_application: "Meridian Index",
    source_name: "Conflict Exposure & Resilience dataset",
    source_url: "https://meridian.nexus-tp.com",
    observed_at: evidenceDate ? `Data current to ${evidenceDate}` : "Data date unavailable",
    role: "Evidence on exposure and ability to cope with shocks",
    source_state: "Repository observation \xB7 not a separately approved C-Ai.US release",
    limitation: evidenceDate ? `These figures reflect the evidence available on ${evidenceDate}. They are not a live security update or a prediction. \u201C${exposureProfile}\u201D describes Malta\u2019s exposure in this assessment; it does not mean Malta is free from risk. Fast-changing information may not yet be reflected.` : `The evidence date was not available. These figures are not a live security update or a prediction. \u201C${exposureProfile}\u201D describes Malta\u2019s exposure in this assessment; it does not mean Malta is free from risk.`
  };
}
__name(meridianConflictLens, "meridianConflictLens");
var VISION_TARGET_IDS = /* @__PURE__ */ new Set([
  "human-development-rank",
  "median-disposable-income",
  "greenhouse-gas-reduction",
  "municipal-landfill",
  "green-open-spaces"
]);
var VISION_READINESS_KEYS = /* @__PURE__ */ new Set([
  "institutional_delivery",
  "economic_investment",
  "digital_data"
]);
function visionTrajectory(item) {
  return {
    id: text(item?.id),
    title: text(item?.title),
    pillar: text(item?.pillar),
    statement_type: text(item?.statement_type),
    baseline: item?.baseline || null,
    milestones: array(item?.milestones),
    direction: text(item?.direction),
    note: bounded(item?.note || "", 400)
  };
}
__name(visionTrajectory, "visionTrajectory");
function meridianVisionLens(vision2050) {
  const identity = vision2050?.identity;
  const framework = vision2050?.official_framework;
  const position = vision2050?.meridian_position;
  if (!identity || !framework || !position) return null;
  const register = array(vision2050?.target_register);
  return {
    kicker: "MALTA VISION 2050",
    title: "Malta\u2019s Vision 2050: targets and readiness",
    subtitle: text(identity.subtitle),
    status: "Three readiness scores available",
    overall_score: null,
    overall_status: text(position.overall_status || "withheld_pending_complete_evidence"),
    score_note: "No overall Vision 2050 score is shown because government targets and independent readiness evidence are kept separate.",
    summary: "Malta Vision 2050 sets the country\u2019s official long-term goals. ThinkPeople Nexus shows three separate readiness scores to help readers consider whether delivery conditions are in place. These are not government ratings.",
    north_star: text(framework.north_star),
    review_milestone: framework.review_milestone,
    pillars: array(framework.pillars).map((pillar) => ({
      number: pillar.number,
      title: text(pillar.title),
      definition: bounded(pillar.definition, 400)
    })),
    targets: register.filter((item) => VISION_TARGET_IDS.has(item?.id)).map(visionTrajectory),
    analytical_scenarios: register.filter((item) => item?.statement_type === "analytical_benchmark").map(visionTrajectory),
    readiness: array(position.readiness_dimensions).filter((dimension) => VISION_READINESS_KEYS.has(text(dimension?.key)) && dimension?.score !== null && dimension?.score !== void 0 && Number.isFinite(Number(dimension.score))).map((dimension) => ({
      key: text(dimension.key),
      label: text(dimension.label),
      proposed_weight: weightPercent(dimension.proposed_weight, 0),
      score: Number(dimension.score),
      status: publicReadinessStatus(dimension.status),
      boundary: bounded(dimension.boundary || "", 300)
    })),
    official_source: framework.source ? { name: text(framework.source.name), url: String(framework.source.url || "") } : null,
    source_application: "Meridian Index",
    source_name: "Meridian Vision 2050 Compass \u2014 Malta",
    source_url: String(framework.source?.url || "https://meridian.nexus-tp.com"),
    observed_at: vision2050?.generated_at ? `Evidence current to ${readableDate(vision2050.generated_at)}` : "Evidence date unavailable",
    role: "Government targets and separate independent readiness assessment",
    source_state: "Repository observation \xB7 not a separately approved C-Ai.US release",
    limitation: "There is no overall Vision 2050 score. Government targets, possible future scenarios and early readiness estimates are shown separately. The scenarios are not targets or predictions, and the readiness estimates are ThinkPeople Nexus assessments rather than government ratings."
  };
}
__name(meridianVisionLens, "meridianVisionLens");
function projectMeridian({ dataset, liveStatus, sovereign, business, resilience, vision2050, commit, now = Date.now() }) {
  const lens = {
    summary: "A concise Malta intelligence view spanning the economic pulse, sovereign resilience, business and industry, conflict resilience, Vision 2050 and the electoral record.",
    index: meridianIndexLens(dataset, sovereign),
    election_watch: meridianElectionLens(dataset),
    statistics: meridianStatisticsLens(business),
    business: meridianBusinessLens(business),
    conflict_resilience: meridianConflictLens(resilience),
    vision_2050: meridianVisionLens(vision2050)
  };
  const datasetDates = [dataset, sovereign, business, resilience, vision2050].map((source) => source?.generated_at).filter((value) => value && !Number.isNaN(new Date(value).getTime()));
  const sourceUpdatedAt = datasetDates.length ? new Date(Math.max(...datasetDates.map((value) => new Date(value).getTime()))).toISOString() : null;
  return {
    commit,
    dataset_generated_at: dataset?.generated_at || null,
    source_updated_at: sourceUpdatedAt,
    repository_monitoring_state: liveStatus?.state || dataset?.live_monitoring?.state || "not_recorded",
    title: "Longer-term context",
    summary: "Longer-term context on infrastructure dependence, the economy, trade exposure and how Malta adapts to change.",
    source_application: "Meridian Index",
    source_url: "https://meridian.nexus-tp.com",
    items: meridianItems(dataset),
    news_ticker: meridianNewsTicker(dataset, liveStatus, 8, now),
    lens,
    world: meridianWorldView(sovereign, business, resilience, commit)
  };
}
__name(projectMeridian, "projectMeridian");
function sourceUpdateIsValid(update) {
  if (!update || update.contract_version !== "observer-source-update-v1.3") return false;
  if (update.geography !== "Malta and Gozo") return false;
  if (!update.dispatch || !update.meridian) return false;
  if (!Array.isArray(update.dispatch.items) || update.dispatch.items.length > 12 || !Array.isArray(update.meridian.items) || update.meridian.items.length > 12) return false;
  if (!update.meridian.lens?.index || !update.meridian.lens?.election_watch || !update.meridian.lens?.statistics) return false;
  if (!update.meridian.lens?.business || !update.meridian.lens?.conflict_resilience || !update.meridian.lens?.vision_2050) return false;
  const ticker = update.meridian.news_ticker;
  if (ticker && (!["current", "no-current-signal", "unavailable"].includes(ticker.state) || !["complete", "partial"].includes(ticker.coverage_state) || !Number.isFinite(Number(ticker.coverage_warning_count)) || Number(ticker.coverage_warning_count) < 0 || !Array.isArray(ticker.items) || ticker.items.length > 8 || ticker.items.some((item) => !item?.headline || !item?.theme || !item?.source_name || !/^https:\/\//i.test(String(item?.source_url || "")) || !item?.observed_at || Number.isNaN(new Date(item.observed_at).getTime())))) return false;
  const timestamps = [update.as_of, update.dispatch.source_updated_at, update.meridian.source_updated_at];
  if (timestamps.some((value) => !value || Number.isNaN(new Date(value).getTime()) || new Date(value).getTime() > Date.now() + 5 * 60 * 1e3)) return false;
  const scores = [
    update.meridian.lens.index.score,
    update.meridian.lens.business.score,
    update.meridian.lens.conflict_resilience.exposure_score,
    update.meridian.lens.conflict_resilience.absorption_capacity
  ];
  if (scores.some((value) => !Number.isFinite(Number(value)) || Number(value) < 0 || Number(value) > 100)) return false;
  const world = update.meridian.world;
  if (!world || world.repository_commit !== update.meridian.commit || !Array.isArray(world.tables) || world.tables.length !== 3 || new Set(world.tables.map((table) => table?.key)).size !== 3 || !["sovereign_resilience", "business_attraction", "conflict_absorption"].every((key) => world.tables.some((table) => table?.key === key))) return false;
  for (const table of world.tables) {
    if (!Array.isArray(table.rows) || table.rows.length < 1 || table.rows.length > 25 || !Number.isInteger(table.country_count) || table.country_count < table.rows.length || !table.generated_at || Number.isNaN(new Date(table.generated_at).getTime()) || !table.malta || table.malta.key !== "malta" || table.rows.some((row, index) => index > 0 && Number(row.score) > Number(table.rows[index - 1].score))) return false;
    const identities = /* @__PURE__ */ new Set();
    for (const row of [...table.rows, table.malta]) {
      if (!row || !Number.isInteger(row.rank) || row.rank < 1 || !/^[A-Z]{2}$/.test(String(row.iso2 || "")) || !/^[A-Z]{3}$/.test(String(row.iso3 || "")) || !Number.isFinite(Number(row.score)) || Number(row.score) < 0 || Number(row.score) > 100) return false;
      if (row !== table.malta && identities.has(row.key)) return false;
      identities.add(row.key);
    }
    if (table.key === "conflict_absorption" && [...table.rows, table.malta].some(
      (row) => !Number.isFinite(Number(row.exposure_score)) || Number(row.exposure_score) < 0 || Number(row.exposure_score) > 100
    )) return false;
  }
  const vision = update.meridian.lens.vision_2050;
  if (vision.overall_score !== null || "skilling_pilot" in vision || !Array.isArray(vision.readiness) || vision.readiness.length < 1 || vision.readiness.length > 3 || vision.readiness.some((item) => !VISION_READINESS_KEYS.has(text(item?.key)) || item?.score === null || item?.score === void 0 || !Number.isFinite(Number(item.score)))) return false;
  if (!/^[a-f0-9]{40}$/i.test(String(update.dispatch.commit || ""))) return false;
  if (!/^[a-f0-9]{40}$/i.test(String(update.meridian.commit || ""))) return false;
  return true;
}
__name(sourceUpdateIsValid, "sourceUpdateIsValid");

// src/build.js
var MERIDIAN_REPOSITORY = "jesmondsaliba4-lab/meridian-index";
var DISPATCH_REPOSITORY = "jesmondsaliba4-lab/dispatch-pro";
var CONTRACT = "observer-source-update-v1.3";
async function sha256Hex(text3) {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text3)));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(sha256Hex, "sha256Hex");
async function buildCandidate({ token, meridianBranch = "main", dispatchBranch = "master", nowMs = Date.now() }) {
  if (!token) throw new Error("No GitHub read key is configured for the publication desk.");
  const [meridianHead, dispatchHead] = await Promise.all([
    githubResolveCommit(MERIDIAN_REPOSITORY, meridianBranch, { token }),
    githubResolveCommit(DISPATCH_REPOSITORY, dispatchBranch, { token })
  ]);
  const read = /* @__PURE__ */ __name((repo, path, ref, maxBytes) => githubJsonWithMeta(repo, path, { token, ref, maxBytes }), "read");
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
__name(buildCandidate, "buildCandidate");
async function storeCandidate(db, candidate, { nowMs = Date.now() } = {}) {
  const at = new Date(nowMs).toISOString();
  await db.prepare(
    "INSERT INTO observer_editions (edition_id, body, prepared_at, meridian_commit, dispatch_commit, valid) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(candidate.edition_id, candidate.body, at, candidate.meridian_commit, candidate.dispatch_commit, candidate.valid ? 1 : 0).run();
  await db.prepare("INSERT INTO observer_candidates (edition_id, prepared_at) VALUES (?, ?)").bind(candidate.edition_id, at).run();
  return candidate.edition_id;
}
__name(storeCandidate, "storeCandidate");
async function latestCandidate(db) {
  return db.prepare(
    `SELECT e.edition_id, e.body, c.prepared_at, e.meridian_commit, e.dispatch_commit, e.valid
       FROM observer_candidates c JOIN observer_editions e ON e.edition_id = c.edition_id
      ORDER BY c.candidate_id DESC LIMIT 1`
  ).first();
}
__name(latestCandidate, "latestCandidate");
async function publishedEdition(db) {
  return db.prepare(
    `SELECT e.edition_id, e.body, e.prepared_at, a.approved_at, a.approved_by
       FROM observer_approvals a JOIN observer_editions e ON e.edition_id = a.edition_id
      ORDER BY a.approval_id DESC LIMIT 1`
  ).first();
}
__name(publishedEdition, "publishedEdition");
async function approve(db, editionId, approvedBy, { nowMs = Date.now() } = {}) {
  await db.prepare("INSERT INTO observer_approvals (edition_id, approved_at, approved_by) VALUES (?, ?, ?)").bind(editionId, new Date(nowMs).toISOString(), approvedBy).run();
}
__name(approve, "approve");

// src/page.js
var esc = /* @__PURE__ */ __name((v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]), "esc");
var fmt = new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Malta", day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
var when = /* @__PURE__ */ __name((iso) => {
  const t = Date.parse(iso || "");
  return Number.isNaN(t) ? "\u2014" : fmt.format(t);
}, "when");
var safeUrl = /* @__PURE__ */ __name((u) => /^https?:\/\//i.test(String(u || "")) ? String(u) : null, "safeUrl");
var parse = /* @__PURE__ */ __name((row) => {
  try {
    return row ? JSON.parse(row.body) : null;
  } catch {
    return null;
  }
}, "parse");
var short = /* @__PURE__ */ __name((id) => String(id || "").slice(0, 12), "short");
function headlines(edition) {
  return new Set([
    edition?.dispatch?.lead?.title,
    ...(edition?.dispatch?.items || []).map((i) => i.headline),
    ...(edition?.meridian?.items || []).map((i) => i.headline)
  ].filter(Boolean));
}
__name(headlines, "headlines");
function items(list, previous) {
  if (!list?.length) return `<p class="note">None.</p>`;
  return `<ol class="list">${list.map((i) => {
    const url = safeUrl(i.source_url);
    const isNew = previous && !previous.has(i.headline);
    return `<li>${isNew ? '<span class="new">new</span> ' : ""}<b>${esc(i.headline)}</b>${i.summary ? `<span class="sum">${esc(i.summary)}</span>` : ""}<span class="meta">${esc(i.theme || "")}${i.source_name ? ` \xB7 ${url ? `<a href="${esc(url)}" rel="noopener noreferrer" target="_blank">${esc(i.source_name)}</a>` : esc(i.source_name)}` : ""}${i.period ? ` \xB7 ${esc(i.period)}` : ""}</span></li>`;
  }).join("")}</ol>`;
}
__name(items, "items");
function editionView(edition, previous) {
  if (!edition) return `<p class="note">Nothing here yet.</p>`;
  const lead = edition.dispatch?.lead || {};
  const lens = edition.meridian?.lens || {};
  const score = /* @__PURE__ */ __name((v) => v === null || v === void 0 || Number.isNaN(Number(v)) ? "\u2014" : String(Math.round(Number(v) * 10) / 10), "score");
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
__name(editionView, "editionView");
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
header{background:var(--navy);color:#efe7d4;padding:16px;border-bottom:3px solid var(--gold)}header h1{margin:0;font-size:20px}header p{margin:4px 0 0;color:#c9c2b2;font-size:13px}
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
<header><h1>Publish to Observer</h1><p>Malta Observer publication desk \xB7 signed in as ${esc(viewer)} \xB7 nothing reaches maltaobserver.com until you press Publish</p></header>
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
__name(renderDesk, "renderDesk");

// src/index.js
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
__name(failureCode, "failureCode");
function messageFor(params) {
  const m = params.get("m");
  if (m !== "failed") return MESSAGES[m] || null;
  const why = String(params.get("why") || "");
  const reason = REASONS[why] || (/^[a-z0-9_]{1,32}$/.test(why) ? `Error code: ${why}.` : "");
  return `${MESSAGES.failed}${reason ? ` Reason: ${reason}` : ""}`;
}
__name(messageFor, "messageFor");
var text2 = /* @__PURE__ */ __name((status, body) => new Response(body, { status, headers: { ...SECURITY, "content-type": "text/plain; charset=utf-8" } }), "text");
var html = /* @__PURE__ */ __name((body) => new Response(body, { status: 200, headers: { ...SECURITY, "content-type": "text/html; charset=utf-8" } }), "html");
var back = /* @__PURE__ */ __name((code, why) => new Response(null, { status: 303, headers: { ...SECURITY, location: `/?m=${code}${why ? `&why=${encodeURIComponent(why)}` : ""}` } }), "back");
async function prepare(env, { nowMs = Date.now() } = {}) {
  const candidate = await buildCandidate({ token: env.GITHUB_READ_TOKEN, meridianBranch: env.GITHUB_MERIDIAN_BRANCH || "main", dispatchBranch: env.GITHUB_DISPATCH_BRANCH || "master", nowMs });
  const before = await latestCandidate(env.EVIDENCE_DB);
  await storeCandidate(env.EVIDENCE_DB, candidate, { nowMs });
  return { edition_id: candidate.edition_id, valid: candidate.valid, changed: before?.edition_id !== candidate.edition_id };
}
__name(prepare, "prepare");
function sameSite(request, url) {
  const origin = request.headers.get("origin");
  const site = request.headers.get("sec-fetch-site");
  if (site) return site === "same-origin" && (origin === url.origin || origin === "null" || origin === null);
  return origin === url.origin;
}
__name(sameSite, "sameSite");
async function handleRequest(request, env, deps = {}) {
  const url = new URL(request.url);
  const access = await verifyAccess(request, env, deps);
  if (!access.ok) return text2(access.status, `Not available (${access.reason}). Sign in through tpnintel.com with a reader account.`);
  const db = env.EVIDENCE_DB;
  if (request.method === "GET" && url.pathname === "/") {
    const [candidate2, published] = await Promise.all([latestCandidate(db), publishedEdition(db)]);
    return html(renderDesk({ candidate: candidate2, published, viewer: access.email, message: messageFor(url.searchParams) }));
  }
  if (request.method !== "POST" || !["/publish", "/refresh"].includes(url.pathname)) return text2(404, "Not found.");
  if (!sameSite(request, url)) return text2(403, "Refused: this action must come from the publication desk page.");
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
__name(handleRequest, "handleRequest");
var index_default = {
  fetch: /* @__PURE__ */ __name((request, env) => handleRequest(request, env), "fetch"),
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
//# sourceMappingURL=index.js.map
