var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/access.js
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

// src/config.js
var COLLECTOR_VERSION = "tpn-evidence/0.1.0-shadow";
var DEFAULT_USER_AGENT = "TPN-Evidence-Collector/0.1 (shadow collection; contact: TBD)";
var FETCH_TIMEOUT_MS = 15e3;
var MAX_BODY_BYTES = 3 * 1024 * 1024;
var FUTURE_TOLERANCE_MS = 5 * 60 * 1e3;
var FUTURE_TOLERANCE_DAY_MS = 24 * 60 * 60 * 1e3;
var FUTURE_TOLERANCE_NO_ZONE_MS = 14 * 60 * 60 * 1e3;
var SUMMARY_MAX_CHARS = 1e3;
var HEADLINE_MAX_CHARS = 500;
var MIN_INTERVAL_MINUTES = 60;
var MAX_INTERVAL_MINUTES = 720;
var MAX_BACKOFF_WAIT_MINUTES = 1440;
var RELAX_AFTER_OVERLAP_SHARE = 0.8;
var RUN_ACTIVE_MIN_HEALTHY_SHARE = 0.9;
var COVERAGE_THIN_THRESHOLD_PER_DAY = null;
var CLUSTER_WINDOW_HOURS = 72;
var CLUSTER_MIN_SHARED_TOKENS = 4;
var CLUSTER_MIN_JACCARD = 0.6;
var QUEUE_BATCH = 100;
var MAX_ITEMS_PER_POLL = 200;

// src/dates.js
var MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
var ZONES = {
  UT: 0,
  UTC: 0,
  GMT: 0,
  Z: 0,
  EST: -300,
  EDT: -240,
  CST: -360,
  CDT: -300,
  MST: -420,
  MDT: -360,
  PST: -480,
  PDT: -420,
  CET: 60,
  CEST: 120,
  BST: 60,
  EET: 120,
  EEST: 180,
  IST: 330,
  JST: 540
};
function offsetMinutes(token) {
  if (!token) return null;
  const t = token.trim().toUpperCase();
  if (t in ZONES) return ZONES[t];
  const m = t.match(/^([+-])(\d{2})(?::?(\d{2}))?$/);
  if (!m) return null;
  return (m[1] === "-" ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3] || 0));
}
__name(offsetMinutes, "offsetMinutes");
function build(y, mo, d, h, mi, s, offset) {
  const utc = Date.UTC(y, mo, d, h, mi, s);
  const check = new Date(utc);
  if (check.getUTCFullYear() !== y || check.getUTCMonth() !== mo || check.getUTCDate() !== d) return null;
  if (h > 23 || mi > 59 || s > 60) return null;
  return utc - (offset ?? 0) * 6e4;
}
__name(build, "build");
var LONG_MONTH_NAMES = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];
function monthIndex(word) {
  const w = String(word).replace(/\.$/, "").toLowerCase();
  if (LONG_MONTH_NAMES.includes(w)) return LONG_MONTH_NAMES.indexOf(w);
  if (w.length <= 4 && MONTHS[w.slice(0, 3)] !== void 0 && (w.length === 3 || w === "sept")) return MONTHS[w.slice(0, 3)];
  return void 0;
}
__name(monthIndex, "monthIndex");
var TIME_SEP = "(?:,?\\s+|\\s*[-\u2013]\\s*)";
var ZONE = "([A-Za-z]{1,5}|[+-]\\d{2}(?::?\\d{2})?)";
function hour24(h, ampm) {
  let hour = Number(h);
  if (!ampm) return hour;
  if (hour < 1 || hour > 12) return null;
  return hour % 12 + (ampm.toLowerCase() === "pm" ? 12 : 0);
}
__name(hour24, "hour24");
function parseFeedDate(raw, hints = {}) {
  const value = String(raw ?? "").trim().replace(/\s+/g, " ");
  if (!value) return null;
  let m = value.match(new RegExp(`^(?:[A-Za-z]{3,9},?\\s+)?(\\d{1,2})\\s+([A-Za-z]{3,9}\\.?)\\s+(\\d{2,4})(?:${TIME_SEP}(\\d{1,2}):(\\d{2})(?::(\\d{2}))?(?:\\s*([AaPp][Mm]))?\\s*${ZONE}?)?$`));
  let monthFirst = false;
  if (!m) {
    const mf = value.match(new RegExp(`^(?:[A-Za-z]{3,9},?\\s+)?([A-Za-z]{3,9}\\.?)\\s+(\\d{1,2}),?\\s+(\\d{4})(?:${TIME_SEP}(\\d{1,2}):(\\d{2})(?::(\\d{2}))?(?:\\s*([AaPp][Mm]))?\\s*${ZONE}?)?$`));
    if (mf) {
      m = [mf[0], mf[2], mf[1], ...mf.slice(3)];
      monthFirst = true;
    }
  }
  if (m) {
    const month = monthIndex(m[2]);
    if (month === void 0) return null;
    let year = Number(m[3]);
    if (year < 100) {
      if (monthFirst) return null;
      year += year < 50 ? 2e3 : 1900;
    }
    if (m[4] === void 0) {
      const ms2 = build(year, month, Number(m[1]), 0, 0, 0, 0);
      return ms2 === null ? null : { ms: ms2, precision: "day" };
    }
    const hour = hour24(m[4], m[7]);
    if (hour === null) return null;
    if (m[8] && offsetMinutes(m[8]) === null) return null;
    const offset = offsetMinutes(m[8]);
    const ms = build(year, month, Number(m[1]), hour, Number(m[5]), Number(m[6] || 0), offset);
    if (ms === null) return null;
    return { ms, precision: m[8] ? "second" : "no-zone" };
  }
  m = value.match(/^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?\s*(Z|[+-]\d{2}(?::?\d{2})?)?)?$/i);
  if (m) {
    if (m[4] === void 0) {
      const ms2 = build(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 0, 0, 0, 0);
      return ms2 === null ? null : { ms: ms2, precision: "day" };
    }
    const offset = m[7] ? offsetMinutes(m[7]) : null;
    const ms = build(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] || 0), offset);
    if (ms === null) return null;
    return { ms, precision: m[7] ? "second" : "no-zone" };
  }
  if (hints.date_order === "ymd") {
    m = value.match(/^(\d{2})-(\d{2})-(\d{2})(?: (\d{1,2}):(\d{2}))?$/);
    if (m) {
      const year = 2e3 + Number(m[1]);
      if (m[4] === void 0) {
        const ms2 = build(year, Number(m[2]) - 1, Number(m[3]), 0, 0, 0, 0);
        return ms2 === null ? null : { ms: ms2, precision: "day" };
      }
      const ms = build(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), 0, null);
      return ms === null ? null : { ms, precision: "no-zone" };
    }
  }
  return null;
}
__name(parseFeedDate, "parseFeedDate");
function classifyDate(raw, kind, nowMs, hints = {}) {
  const parsed = parseFeedDate(raw, hints);
  if (!parsed) {
    return { published_at: null, published_raw: raw ? String(raw).slice(0, 200) : null, precision: null, date_kind: raw ? kind : "none", status: "undated" };
  }
  const tolerance = parsed.precision === "day" ? FUTURE_TOLERANCE_DAY_MS : parsed.precision === "no-zone" ? FUTURE_TOLERANCE_NO_ZONE_MS : FUTURE_TOLERANCE_MS;
  const status = parsed.ms - nowMs > tolerance ? "future" : "dated";
  return {
    published_at: new Date(parsed.ms).toISOString(),
    published_raw: String(raw).slice(0, 200),
    precision: parsed.precision,
    date_kind: kind,
    status
  };
}
__name(classifyDate, "classifyDate");
var LONG_MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];
var formatters = /* @__PURE__ */ new Map();
function partsAt(instant, timeZone) {
  if (!formatters.has(timeZone)) {
    formatters.set(timeZone, new Intl.DateTimeFormat("en-GB", { timeZone, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" }));
  }
  return Object.fromEntries(formatters.get(timeZone).formatToParts(instant).filter((p) => p.type !== "literal").map((p) => [p.type, Number(p.value)]));
}
__name(partsAt, "partsAt");
function zoneOffsetMs(instant, timeZone) {
  const p = partsAt(instant, timeZone);
  return Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second) - instant.getTime();
}
__name(zoneOffsetMs, "zoneOffsetMs");
function localDateTimeToIso({ year, month, day, hour, minute }, timeZone) {
  const local = Date.UTC(year, month - 1, day, hour, minute, 0);
  const v = new Date(local);
  if (v.getUTCFullYear() !== year || v.getUTCMonth() !== month - 1 || v.getUTCDate() !== day || v.getUTCHours() !== hour) return null;
  const dayMs = 864e5;
  const offsets = new Set([-dayMs, 0, dayMs].map((d) => zoneOffsetMs(new Date(local + d), timeZone)));
  const candidates = [...offsets].map((o) => local - o).filter((ms) => {
    const p = partsAt(new Date(ms), timeZone);
    return p.year === year && p.month === month && p.day === day && p.hour === hour && p.minute === minute;
  });
  return candidates.length ? new Date(Math.max(...candidates)).toISOString() : null;
}
__name(localDateTimeToIso, "localDateTimeToIso");
function parseLocalPageDate(text, timeZone) {
  const m = String(text || "").trim().match(/^(\d{1,2})\s+([a-z]+)\s+(\d{4}),?\s+(\d{1,2}):(\d{2})\s*(am|pm)$/i);
  if (!m) return null;
  const month = LONG_MONTHS.indexOf(m[2].toLowerCase()) + 1;
  const h12 = Number(m[4]);
  if (!month || h12 < 1 || h12 > 12 || Number(m[5]) > 59) return null;
  const hour = h12 % 12 + (m[6].toLowerCase() === "pm" ? 12 : 0);
  return localDateTimeToIso({ year: Number(m[3]), month, day: Number(m[1]), hour, minute: Number(m[5]) }, timeZone);
}
__name(parseLocalPageDate, "parseLocalPageDate");

// src/util.js
var encoder = new TextEncoder();
async function sha256Hex(input) {
  const data = typeof input === "string" ? encoder.encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(sha256Hex, "sha256Hex");
var NAMED_ENTITIES = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
  ndash: "\u2013",
  mdash: "\u2014",
  lsquo: "\u2018",
  rsquo: "\u2019",
  ldquo: "\u201C",
  rdquo: "\u201D",
  hellip: "\u2026",
  euro: "\u20AC",
  pound: "\xA3",
  copy: "\xA9",
  reg: "\xAE",
  trade: "\u2122",
  laquo: "\xAB",
  raquo: "\xBB",
  eacute: "\xE9",
  egrave: "\xE8",
  agrave: "\xE0",
  aacute: "\xE1",
  ograve: "\xF2",
  oacute: "\xF3",
  ugrave: "\xF9",
  uacute: "\xFA",
  iacute: "\xED",
  igrave: "\xEC",
  ccedil: "\xE7",
  ntilde: "\xF1",
  auml: "\xE4",
  ouml: "\xF6",
  uuml: "\xFC",
  szlig: "\xDF",
  Eacute: "\xC9",
  Agrave: "\xC0"
};
function decodeEntities(value) {
  return String(value ?? "").replace(/&(#x[0-9a-f]+|#\d+|[a-z][a-z0-9]*);/gi, (match, code) => {
    if (code[0] === "#") {
      const n = code[1].toLowerCase() === "x" ? parseInt(code.slice(2), 16) : parseInt(code.slice(1), 10);
      try {
        return Number.isFinite(n) && n > 0 ? String.fromCodePoint(n) : match;
      } catch {
        return match;
      }
    }
    return NAMED_ENTITIES[code] ?? NAMED_ENTITIES[code.toLowerCase()] ?? match;
  });
}
__name(decodeEntities, "decodeEntities");
function stripTags(html) {
  return String(html ?? "").replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<\/?[a-z][a-z0-9:-]*(?:\s[^<>]*)?\/?>/gi, " ");
}
__name(stripTags, "stripTags");
function cleanText(value, max) {
  const text = decodeEntities(stripTags(decodeEntities(value))).replace(/\s+/g, " ").trim();
  if (!max || text.length <= max) return text;
  return `${text.slice(0, max - 1).trimEnd()}\u2026`;
}
__name(cleanText, "cleanText");
function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}
__name(hostOf, "hostOf");

// src/feed.js
function unwrapCdata(value) {
  return String(value ?? "").replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, (_, inner) => inner);
}
__name(unwrapCdata, "unwrapCdata");
function tagContent(block, names) {
  for (const name of names) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`<${escaped}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${escaped}>`, "i");
    const m = block.match(re);
    if (m) return unwrapCdata(m[1]).trim();
  }
  return "";
}
__name(tagContent, "tagContent");
function attr(tag, name) {
  const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*(["'])([\\s\\S]*?)\\1`, "i"));
  return m ? decodeEntities(m[2]) : "";
}
__name(attr, "attr");
var MAX_FEED_ITEMS = 200;
function blocks(xml, name) {
  const open = new RegExp(`<${name}(?=[\\s>/])`, "gi");
  const starts = [];
  for (const m of xml.matchAll(open)) {
    starts.push(m.index);
    if (starts.length > MAX_FEED_ITEMS) break;
  }
  const close = `</${name}>`;
  return starts.slice(0, MAX_FEED_ITEMS).map((start, i) => {
    const limit = starts[i + 1] ?? xml.length;
    const segment = xml.slice(start, limit);
    const end = segment.toLowerCase().indexOf(close.toLowerCase());
    return end === -1 ? segment : segment.slice(0, end + close.length);
  });
}
__name(blocks, "blocks");
function atomLink(entry) {
  const links = [...entry.matchAll(/<link\b[^>]*\/?>/gi)].map((m) => m[0]);
  const alternate = links.find((l) => !attr(l, "rel") || attr(l, "rel") === "alternate");
  return alternate ? attr(alternate, "href") : "";
}
__name(atomLink, "atomLink");
function parseFeed(body) {
  const text = String(body ?? "").replace(/^﻿/, "");
  const head = text.slice(0, 2048);
  let format = null;
  if (/<rss[\s>]/i.test(head)) format = "rss";
  else if (/<feed[\s>]/i.test(head) && /xmlns\s*=\s*["']http:\/\/www\.w3\.org\/2005\/Atom/i.test(head)) format = "atom";
  else if (/<feed[\s>]/i.test(head)) format = "atom";
  else if (/<rdf:RDF[\s>]/i.test(head)) format = "rdf";
  if (!format) return null;
  const channelBlock = format === "atom" ? text.split(/<entry[\s>]/i)[0] : text.match(/<channel(?:\s[^>]*)?>([\s\S]*?)(?:<item[\s>]|<\/channel>)/i)?.[0] || "";
  const feedLanguage = (tagContent(channelBlock, ["language", "dc:language"]) || attr(text.match(/<feed\b[^>]*>/i)?.[0] || "", "xml:lang") || "").toLowerCase() || null;
  const atomPrefixes = [...head.matchAll(/xmlns:([\w-]+)\s*=\s*["']http:\/\/www\.w3\.org\/2005\/Atom["']/gi)].map((x) => x[1]);
  const items = [];
  if (format === "atom") {
    for (const entry of blocks(text, "entry")) {
      const published = tagContent(entry, ["published"]);
      const updated = tagContent(entry, ["updated"]);
      items.push({
        title: tagContent(entry, ["title"]),
        link: atomLink(entry),
        guid: tagContent(entry, ["id"]),
        summary: tagContent(entry, ["summary", "content"]),
        date_raw: published || updated || "",
        date_kind: published ? "published" : updated ? "updated" : "none"
      });
    }
  } else {
    for (const item of blocks(text, "item")) {
      const pub = tagContent(item, ["pubDate"]);
      const dc = tagContent(item, ["dc:date"]);
      const atomPublished = tagContent(item, atomPrefixes.map((p) => `${p}:published`));
      const atomUpdated = tagContent(item, atomPrefixes.map((p) => `${p}:updated`));
      const guid = tagContent(item, ["guid"]);
      const guidTag = item.match(/<guid\b[^>]*>/i)?.[0] || "";
      let link = tagContent(item, ["link"]) || attr(item.match(/<link\b[^>]*\/?>/i)?.[0] || "", "href");
      if (!link && guid && attr(guidTag, "isPermaLink") !== "false" && /^https?:\/\//i.test(guid)) link = guid;
      if (!link && format === "rdf") link = attr(item.match(/<item\b[^>]*>/i)?.[0] || "", "rdf:about");
      items.push({
        title: tagContent(item, ["title"]),
        link: decodeEntities(link),
        guid,
        summary: tagContent(item, ["description", "content:encoded", "summary"]),
        date_raw: pub || dc || atomPublished || atomUpdated || "",
        date_kind: pub || atomPublished ? "published" : dc ? "dc-date" : atomUpdated ? "updated" : "none"
      });
    }
  }
  return { format, language: feedLanguage, items };
}
__name(parseFeed, "parseFeed");

// src/adapters.js
function rssAdapter(body) {
  const feed = parseFeed(body);
  if (!feed) return { parsed: false, items: [] };
  return { parsed: true, feed_language: feed.language, items: feed.items };
}
__name(rssAdapter, "rssAdapter");
function htmlAttr(tag, name) {
  const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*(["'])([\\s\\S]*?)\\1`, "i"));
  return m ? m[2] : "";
}
__name(htmlAttr, "htmlAttr");
function classTokens(tag) {
  return htmlAttr(tag, "class").split(/\s+/).filter(Boolean);
}
__name(classTokens, "classTokens");
function maltaTodayHomeAdapter(body, endpoint) {
  const html = String(body || "");
  if (!/<html[\s>]/i.test(html.slice(0, 5e3)) && !/<div\b/i.test(html)) return { parsed: false, items: [] };
  const config = endpoint.config;
  const starts = [...html.matchAll(/<div\b[^>]*>/gi)].filter((m) => classTokens(m[0]).includes("article") && htmlAttr(m[0], "data-url"));
  const items = starts.map((open, i) => {
    const block = html.slice(open.index, starts[i + 1]?.index ?? html.length);
    const title = decodeEntities((block.match(/<h3\b[^>]*>([\s\S]*?)<\/h3>/i)?.[1] || "").replace(/<[^>]+>/g, " "));
    let link = "";
    try {
      const u = new URL(decodeEntities(htmlAttr(open[0], "data-url")), endpoint.url);
      if (hostOf(u.href) === hostOf(endpoint.url)) link = u.href;
    } catch {
      link = "";
    }
    const spans = [...block.matchAll(/<span\b[^>]*>/gi)];
    const dateSpan = spans.find((m) => classTokens(m[0]).includes("article-date"));
    let dateText = "";
    if (dateSpan) {
      const rest = block.slice(dateSpan.index + dateSpan[0].length);
      dateText = decodeEntities(rest.slice(0, rest.indexOf("<") === -1 ? rest.length : rest.indexOf("<"))).trim();
    }
    const iso = parseLocalPageDate(dateText, config.time_zone || "Europe/Malta");
    let scope = null;
    try {
      if (config.scope_country && (config.scope_path_prefixes || []).some((p) => new URL(link).pathname.startsWith(p))) scope = config.scope_country;
    } catch {
      scope = null;
    }
    return { title, link, summary: "", date_raw: dateText, date_kind: "page-local-time", published_iso: iso, scope_country: scope };
  }).filter((it) => it.title && it.link).slice(0, config.article_limit || 20);
  return { parsed: true, items };
}
__name(maltaTodayHomeAdapter, "maltaTodayHomeAdapter");
var EUROBAROMETER_SURVEY = "https://europa.eu/eurobarometer/surveys/detail/";
function eurobarometerLatestAdapter(body, endpoint) {
  let data;
  try {
    data = JSON.parse(body);
  } catch {
    return { parsed: false, items: [] };
  }
  if (!Array.isArray(data)) return { parsed: false, items: [] };
  const items = data.filter((s) => s && Number.isInteger(s.id) && s.id > 0 && typeof s.titleEN === "string" && s.titleEN.trim()).map((s) => {
    const date = /^\d{4}-\d{2}-\d{2}$/.test(String(s.publicationFirstDate || "")) ? s.publicationFirstDate : "";
    return { title: s.titleEN.trim().slice(0, 400), link: `${EUROBAROMETER_SURVEY}${s.id}`, summary: "", date_raw: date, date_kind: date ? "published" : "none" };
  }).slice(0, endpoint.config?.article_limit || 30);
  return { parsed: true, items };
}
__name(eurobarometerLatestAdapter, "eurobarometerLatestAdapter");
function gdeltRequestUrl(endpoint) {
  const c = endpoint.config;
  const u = new URL(endpoint.url);
  u.searchParams.set("query", c.query);
  u.searchParams.set("mode", "artlist");
  u.searchParams.set("maxrecords", String(c.max_records || 100));
  u.searchParams.set("timespan", c.timespan || "24h");
  u.searchParams.set("sort", "datedesc");
  u.searchParams.set("format", "json");
  return u.toString();
}
__name(gdeltRequestUrl, "gdeltRequestUrl");
function gdeltSeen(value) {
  const m = String(value || "").match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/);
  return m ? `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}.000Z` : null;
}
__name(gdeltSeen, "gdeltSeen");
function gdeltAdapter(body, endpoint) {
  let data;
  try {
    data = JSON.parse(body);
  } catch {
    return { parsed: false, items: [] };
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) return { parsed: false, items: [] };
  if (!Array.isArray(data.articles)) return { parsed: Object.keys(data).length === 0, items: [] };
  const allow = new Set(endpoint.config.domain_allowlist || []);
  const items = [];
  let rejected = 0;
  for (const a of data.articles) {
    const domain = hostOf(a.url);
    const allowed = domain && [...allow].some((d) => domain === d || domain.endsWith(`.${d}`));
    if (!allowed) {
      rejected += 1;
      continue;
    }
    items.push({ title: a.title || "", link: a.url, summary: "", date_raw: "", date_kind: "aggregator-first-seen", aggregator_seen_at: gdeltSeen(a.seendate), aggregator_language: a.language || null });
  }
  return { parsed: true, items, rejected_by_allowlist: rejected };
}
__name(gdeltAdapter, "gdeltAdapter");

// src/cluster.js
var STOP = new Set("the a an and or of to in on for with as by at from that this is are was were be been has have had after over into about amid says said will would could new more than its it his her their our not but also il la le les lo gli di da del della dei des du de et e per con un una uno sur dans pour que qui el los las y en der die das und mit f\xFCr von im auf ta tal fil g\u0127al li minn u l".split(/\s+/));
function headlineTokens(headline) {
  return [...new Set(String(headline || "").toLowerCase().normalize("NFKD").replace(/\p{M}/gu, "").split(/[^\p{L}\p{N}]+/u).filter((t) => t.length >= 3 && !STOP.has(t)))];
}
__name(headlineTokens, "headlineTokens");
async function signatureFor(tokens) {
  return (await sha256Hex([...tokens].sort().join(" "))).slice(0, 24);
}
__name(signatureFor, "signatureFor");
function jaccard(a, b) {
  const A = new Set(a), B = new Set(b);
  let shared = 0;
  for (const t of A) if (B.has(t)) shared += 1;
  const union = A.size + B.size - shared;
  return { shared, score: union ? shared / union : 0 };
}
__name(jaccard, "jaccard");
function bestCluster(tokens, candidates) {
  let best = null;
  for (const c of candidates) {
    const { shared, score } = jaccard(tokens, c.tokens);
    if (shared >= CLUSTER_MIN_SHARED_TOKENS && score >= CLUSTER_MIN_JACCARD && (!best || score > best.score)) best = { cluster_id: c.cluster_id, score };
  }
  return best;
}
__name(bestCluster, "bestCluster");

// src/countries.js
var COUNTRIES = [
  { key: "austria", region: "EU", names: ["Austria", "Awstrija", "Autriche", "\xD6sterreich", "Oesterreich"], demonyms: ["Austrian", "austriaco", "austriaca", "autrichien", "autrichienne", "austr\xEDaco", "\xF6sterreichisch", "\xF6sterreichische"], places: ["Vienna", "Vjenna", "Vienne", "Viena", "Wien"], institutions: ["Nationalrat"] },
  { key: "belgium", region: "EU", names: ["Belgium", "Bel\u0121ju", "Belgio", "Belgique", "B\xE9lgica", "Belgien"], demonyms: ["Belgian", "belga", "belge", "belgisch", "belgische"], places: [], institutions: [] },
  { key: "bulgaria", region: "EU", names: ["Bulgaria", "Bulgarija", "Bulgarie", "Bulgarien"], demonyms: ["Bulgarian", "bulgaro", "bulgara", "bulgare", "b\xFAlgaro", "bulgarisch"], places: ["Sofija"], ambiguous: ["Sofia", "Sof\xEDa"], institutions: [] },
  { key: "croatia", region: "EU", names: ["Croatia", "Kroazja", "Croazia", "Croatie", "Croacia", "Kroatien", "Hrvatska"], demonyms: ["Croatian", "croato", "croata", "croate", "kroatisch"], places: ["Zagreb", "Zagabria"], institutions: ["Sabor"] },
  { key: "cyprus", region: "EU", names: ["Cyprus", "\u010Aipru", "Cipru", "Cipro", "Chypre", "Chipre", "Zypern"], demonyms: ["Cypriot", "cipriota", "chypriote", "chipriota", "zypriotisch"], places: ["Nicosia", "Nikosija", "Nicosie", "Nikosia"], institutions: [] },
  { key: "czech-republic", region: "EU", names: ["Czech Republic", "Czechia", "Repubblika \u010Aeka", "Repubblica Ceca", "Cechia", "R\xE9publique tch\xE8que", "Tch\xE9quie", "Rep\xFAblica Checa", "Chequia", "Tschechien"], demonyms: ["Czech", "ceco", "ceca", "tch\xE8que", "checo", "checa", "tschechisch"], places: ["Prague", "Praga", "Prag"], institutions: [] },
  { key: "denmark", region: "EU", names: ["Denmark", "Danimarka", "Danimarca", "Danemark", "Dinamarca", "D\xE4nemark"], demonyms: ["Danish", "danese", "danois", "dan\xE9s", "d\xE4nisch"], places: ["Copenhagen", "Kopen\u0127agen", "Copenaghen", "Copenhague", "Kopenhagen"], institutions: ["Folketing"] },
  { key: "estonia", region: "EU", names: ["Estonia", "Estonja", "Estonie", "Estland"], demonyms: ["Estonian", "estone", "estonien", "estonio", "estnisch"], places: ["Tallinn"], institutions: ["Riigikogu"] },
  { key: "finland", region: "EU", names: ["Finland", "Finlandja", "Finlandia", "Finlande", "Finnland"], demonyms: ["Finnish", "finlandese", "finlandais", "finland\xE9s", "finnisch"], places: ["Helsinki"], institutions: ["Eduskunta"] },
  { key: "france", region: "EU", names: ["France", "Franza", "Francia", "Frankreich"], demonyms: ["French", "francese", "fran\xE7ais", "fran\xE7aise", "franc\xE9s", "francesa", "franz\xF6sisch", "franz\xF6sische"], places: ["Paris", "Parigi", "Par\xEDs"], institutions: ["\xC9lys\xE9e", "Elysee", "Assembl\xE9e nationale", "Matignon"] },
  { key: "germany", region: "EU", names: ["Germany", "\u0120ermanja", "Germanja", "Germania", "Allemagne", "Alemania", "Deutschland"], demonyms: ["German", "tedesco", "tedesca", "allemand", "allemande", "alem\xE1n", "alemana", "deutsch", "deutsche"], places: ["Berlin", "Berlino", "Berl\xEDn"], institutions: ["Bundestag", "Bundesrat", "Bundesregierung", "Bundeskanzler"] },
  { key: "greece", region: "EU", names: ["Greece", "Gre\u010Bja", "Grecja", "Grecia", "Gr\xE8ce", "Griechenland", "Hellenic Republic"], demonyms: ["Greek", "greco", "greca", "grec", "grecque", "griego", "griega", "griechisch"], places: ["Athens", "Ateni", "Atene", "Ath\xE8nes", "Atenas", "Athen"], institutions: [] },
  { key: "hungary", region: "EU", names: ["Hungary", "Ungerija", "Ungheria", "Hongrie", "Hungr\xEDa", "Ungarn", "Magyarorsz\xE1g"], demonyms: ["Hungarian", "ungherese", "hongrois", "h\xFAngaro", "ungarisch"], places: ["Budapest"], institutions: [] },
  { key: "ireland", region: "EU", names: ["Ireland", "Irlanda", "Irlande", "Irland", "\xC9ire"], demonyms: ["Irish", "irlandese", "irlandais", "irland\xE9s", "irisch"], places: ["Dublin", "Dublino", "Dubl\xEDn"], institutions: ["D\xE1il", "Taoiseach", "T\xE1naiste", "Oireachtas", "Leinster House"] },
  { key: "italy", region: "EU", names: ["Italy", "Italja", "Italia", "Italie", "Italien"], demonyms: ["Italian", "Taljan", "Taljana", "italiano", "italiana", "italiani", "italiane", "italien", "italienne", "italienisch"], places: ["Rome", "Ruma", "Roma", "Rom"], institutions: ["Palazzo Chigi", "Quirinale", "Montecitorio"] },
  { key: "latvia", region: "EU", names: ["Latvia", "Latvja", "Lettonia", "Lettonie", "Letonia", "Lettland"], demonyms: ["Latvian", "lettone", "letton", "let\xF3n", "lettisch"], places: ["Riga"], institutions: ["Saeima"] },
  { key: "lithuania", region: "EU", names: ["Lithuania", "Litwanja", "Lituania", "Lituanie", "Litauen"], demonyms: ["Lithuanian", "lituano", "lituanien", "litauisch"], places: ["Vilnius"], institutions: ["Seimas"] },
  { key: "luxembourg", region: "EU", names: ["Luxembourg", "Lussemburgu", "Lussemburgo", "Luxemburgo", "Luxemburg"], demonyms: ["Luxembourgish", "lussemburghese", "luxembourgeois", "luxemburgu\xE9s", "luxemburgisch"], places: [], institutions: [] },
  { key: "malta", region: "EU", names: ["Malta", "Gozo", "G\u0127awdex", "Comino", "Kemmuna"], demonyms: ["Maltese", "Malti", "Maltija", "Maltin", "maltais", "malt\xE9s", "maltesisch", "maltesische"], places: ["Valletta", "La Valette", "La Valeta"], institutions: ["Castille", "Kastilja"] },
  { key: "netherlands", region: "EU", names: ["Netherlands", "Olanda", "Pajji\u017Ci l-Baxxi", "Paesi Bassi", "Pays-Bas", "Pa\xEDses Bajos", "Niederlande", "Holland"], demonyms: ["Dutch", "olandese", "n\xE9erlandais", "neerland\xE9s", "niederl\xE4ndisch"], places: ["Amsterdam", "The Hague", "Den Haag", "L'Aia", "La Haye", "La Haya"], institutions: ["Tweede Kamer", "Binnenhof"] },
  { key: "poland", region: "EU", names: ["Poland", "Polonja", "Polonia", "Pologne", "Polen"], demonyms: ["Polish", "polacco", "polacca", "polonais", "polaco", "polaca", "polnisch"], places: ["Warsaw", "Varsavja", "Varsavia", "Varsovie", "Varsovia", "Warschau"], institutions: ["Sejm"] },
  { key: "portugal", region: "EU", names: ["Portugal", "Portugall", "Portogallo"], demonyms: ["Portuguese", "portoghese", "portugais", "portugu\xE9s", "portuguesa", "portugiesisch"], places: ["Lisbon", "Lisbona", "Lisbonne", "Lisboa", "Lissabon"], institutions: [] },
  { key: "romania", region: "EU", names: ["Romania", "Rumanija", "Roumanie", "Ruman\xEDa", "Rum\xE4nien"], demonyms: ["Romanian", "rumeno", "rumena", "roumain", "roumaine", "rumano", "rum\xE4nisch"], places: ["Bucharest", "Bukarest", "Bucarest"], institutions: [] },
  { key: "slovakia", region: "EU", names: ["Slovakia", "Slovakkja", "Slovacchia", "Slovaquie", "Eslovaquia", "Slowakei"], demonyms: ["Slovak", "slovacco", "slovaque", "eslovaco", "slowakisch"], places: ["Bratislava"], institutions: [] },
  { key: "slovenia", region: "EU", names: ["Slovenia", "Slovenja", "Slov\xE9nie", "Eslovenia", "Slowenien"], demonyms: ["Slovenian", "Slovene", "sloveno", "slov\xE8ne", "esloveno", "slowenisch"], places: ["Ljubljana", "Lubiana"], institutions: [] },
  { key: "spain", region: "EU", names: ["Spain", "Spanja", "Spagna", "Espagne", "Espa\xF1a", "Spanien"], demonyms: ["Spanish", "spagnolo", "spagnola", "espagnol", "espagnole", "espa\xF1ol", "espa\xF1ola", "spanisch"], places: ["Madrid"], institutions: ["Moncloa", "Congreso de los Diputados"] },
  { key: "sweden", region: "EU", names: ["Sweden", "\u017Bvezja", "Svezja", "Svezia", "Su\xE8de", "Suecia", "Schweden"], demonyms: ["Swedish", "svedese", "su\xE9dois", "sueco", "schwedisch"], places: ["Stockholm", "Stoccolma", "Estocolmo"], institutions: ["Riksdag"] },
  { key: "united-kingdom", region: "UK", names: ["United Kingdom", "Britain", "Great Britain", "England", "Scotland", "Wales", "Northern Ireland", "Renju Unit", "Ingilterra", "Regno Unito", "Gran Bretagna", "Royaume-Uni", "Reino Unido", "Gro\xDFbritannien", "Vereinigtes K\xF6nigreich"], demonyms: ["British", "britannico", "britannica", "britannique", "brit\xE1nico", "britisch"], places: ["London", "Londra", "Londres"], institutions: ["Downing Street", "Westminster", "Whitehall"], exact: ["UK", "U.K."], exclude: [/\bNew South Wales\b/i] },
  { key: "united-states", region: "North America", names: ["United States", "United States of America", "Stati Uniti", "Istati Uniti", "\xC9tats-Unis", "Etats-Unis", "Estados Unidos", "Vereinigte Staaten"], demonyms: ["American", "americano", "americana", "am\xE9ricain", "am\xE9ricaine", "amerikanisch"], notAfter: /(?:latin|south|central|north|native|african|asian|mexican|pan|anglo|irish|italian|arab)[\s-]+$/i, places: ["Washington"], institutions: ["White House", "Casa Bianca", "Maison Blanche", "Casa Blanca", "Wei\xDFes Haus", "Pentagon", "Capitol Hill", "US Congress"], exact: ["US", "U.S.", "USA", "U.S.A."] },
  { key: "china", region: "Asia-Pacific", names: ["China", "\u010Aina", "Cina", "Chine"], demonyms: ["Chinese", "\u010Aini\u017C", "cinese", "chinois", "chinoise", "chino", "chinesisch"], places: ["Beijing", "Pechino", "P\xE9kin", "Pek\xEDn", "Peking"], institutions: [] },
  { key: "japan", region: "Asia-Pacific", names: ["Japan", "\u0120appun", "Giappone", "Japon", "Jap\xF3n"], demonyms: ["Japanese", "giapponese", "japonais", "japon\xE9s", "japanisch"], places: ["Tokyo", "Tokjo", "Tokio"], institutions: [] },
  { key: "australia", region: "Asia-Pacific", names: ["Australia", "Awstralja", "Australie", "Australien"], demonyms: ["Australian", "australiano", "australien", "australisch"], places: ["Canberra"], institutions: [] },
  { key: "switzerland", region: "Wider Europe", names: ["Switzerland", "Svizzera", "\u017Bvizzera", "Suisse", "Suiza", "Schweiz"], demonyms: ["Swiss", "svizzero", "svizzera", "suisse", "suizo", "schweizerisch"], places: ["Bern", "Berna", "Berne"], institutions: [] },
  { key: "libya", region: "North Africa", names: ["Libya", "Libja", "Libia", "Libye", "Libyen"], demonyms: ["Libyan", "Libjan", "libico", "libica", "libyen", "libyenne", "libio", "libysch"], places: ["Tripoli", "Tripli", "Tr\xEDpoli", "Benghazi"], institutions: [] },
  { key: "israel", region: "Middle East & Gulf", names: ["Israel", "I\u017Crael", "Israele", "Isra\xEBl"], demonyms: ["Israeli", "I\u017Craeljan", "israeliano", "israeliana", "isra\xE9lien", "isra\xE9lienne", "israel\xED", "israelisch"], places: ["Jerusalem", "\u0120erusalemm", "Gerusalemme", "J\xE9rusalem", "Jerusal\xE9n", "Tel Aviv"], institutions: ["Knesset"] },
  { key: "qatar", region: "Middle East & Gulf", names: ["Qatar", "Katar"], demonyms: ["Qatari", "qatariota", "qatarien", "catar\xED", "katarisch"], places: ["Doha"], institutions: [] },
  { key: "uae", region: "Middle East & Gulf", names: ["United Arab Emirates", "Emirati Arabi Uniti", "\xC9mirats arabes unis", "Emiratos \xC1rabes Unidos", "Vereinigte Arabische Emirate"], demonyms: ["Emirati"], places: ["Abu Dhabi", "Dubai", "Duba\xEF"], institutions: [], exact: ["UAE"] },
  { key: "saudi-arabia", region: "Middle East & Gulf", names: ["Saudi Arabia", "G\u0127arabja Sawdija", "Arabia Saudita", "Arabie saoudite", "Arabia Saud\xED", "Saudi-Arabien"], demonyms: ["Saudi", "saudita", "saoudien", "saoudienne", "saud\xED", "saudisch"], places: ["Riyadh", "Riad", "Riyad"], institutions: [] },
  { key: "norway", region: "Wider Europe", names: ["Norway", "Norve\u0121ja", "Norvegia", "Norv\xE8ge", "Noruega", "Norwegen"], demonyms: ["Norwegian", "norvegese", "norv\xE9gien", "noruego", "norwegisch"], places: ["Oslo"], institutions: ["Storting", "Stortinget"] },
  { key: "iceland", region: "Wider Europe", names: ["Iceland", "I\u017Clanda", "Islanda", "Islande", "Islandia"], demonyms: ["Icelandic", "islandese", "islandais", "island\xE9s", "isl\xE4ndisch"], places: ["Reykjavik", "Reykjav\xEDk"], institutions: ["Althing", "Al\xFEingi"] },
  { key: "ukraine", region: "Balkans & Eastern Europe", names: ["Ukraine", "Ukrajna", "Ucraina", "Ucrania"], demonyms: ["Ukrainian", "Ukren", "ucraino", "ucraina", "ukrainien", "ukrainienne", "ucraniano", "ukrainisch"], places: ["Kyiv", "Kiev", "Kijiv", "Kiew"], institutions: ["Verkhovna Rada"] },
  { key: "serbia", region: "Balkans & Eastern Europe", names: ["Serbia", "Serbja", "Serbie", "Serbien"], demonyms: ["Serbian", "serbo", "serba", "serbe", "serbio", "serbisch"], places: ["Belgrade", "Belgrad", "Belgrado"], institutions: [] },
  { key: "bosnia-and-herzegovina", region: "Balkans & Eastern Europe", names: ["Bosnia and Herzegovina", "Bosnia-Herzegovina", "Bosnia", "Bo\u017Cnija", "Bosnia ed Erzegovina", "Bosnie-Herz\xE9govine", "Bosnia y Herzegovina", "Bosnien und Herzegowina", "Bosnien", "Republika Srpska"], demonyms: ["Bosnian", "bosniaco", "bosniaque", "bosnio", "bosnisch"], places: ["Sarajevo"], institutions: [] },
  { key: "albania", region: "Balkans & Eastern Europe", names: ["Albania", "Albanija", "Albanie", "Albanien"], demonyms: ["Albanian", "albanese", "albanais", "alban\xE9s", "albanisch"], places: ["Tirana"], institutions: [] },
  { key: "north-macedonia", region: "Balkans & Eastern Europe", names: ["North Macedonia", "Macedonia ta' Fuq", "Macedonia del Nord", "Mac\xE9doine du Nord", "Macedonia del Norte", "Nordmazedonien"], demonyms: ["Macedonian", "macedone", "mac\xE9donien", "macedonio", "mazedonisch"], places: ["Skopje", "Skopie"], institutions: [] },
  { key: "montenegro", region: "Balkans & Eastern Europe", names: ["Montenegro", "Mont\xE9n\xE9gro"], demonyms: ["Montenegrin", "montenegrino", "mont\xE9n\xE9grin"], places: ["Podgorica"], institutions: [] },
  { key: "kosovo", region: "Balkans & Eastern Europe", names: ["Kosovo", "Kosova"], demonyms: ["Kosovar", "Kosovan", "kosovaro", "kosovar"], places: ["Pristina", "Prishtina", "Pri\u0161tina"], institutions: [] },
  { key: "moldova", region: "Balkans & Eastern Europe", names: ["Moldova", "Moldavja", "Moldavia", "Moldavie", "Moldau", "Republik Moldau", "Transnistria"], demonyms: ["Moldovan", "moldavo", "moldave", "moldauisch"], places: ["Chisinau", "Chi\u0219in\u0103u", "Chi\u015Fin\u0103u", "Kishinev"], institutions: [] },
  { key: "turkey", region: "Levant & Turkey", names: ["Turkey", "T\xFCrkiye", "Turkiye", "Turkija", "Turchia", "Turquie", "Turqu\xEDa", "T\xFCrkei"], demonyms: ["Turkish", "Tork", "turco", "turca", "turc", "turque", "t\xFCrkisch"], places: ["Ankara", "Istanbul", "Estambul"], institutions: [], exclude: [/\bturkey\s+(?:dinner|recipe|sandwich|breast|roast|day)\b/i, /\b(?:roast|thanksgiving|christmas)\s+turkey\b/i] },
  { key: "lebanon", region: "Levant & Turkey", names: ["Lebanon", "Libanu", "Libano", "Liban", "L\xEDbano", "Libanon"], demonyms: ["Lebanese", "libanese", "libanais", "liban\xE9s", "libanesisch"], places: ["Beirut", "Bejrut", "Beyrouth"], institutions: [] },
  { key: "syria", region: "Levant & Turkey", names: ["Syria", "Sirja", "Siria", "Syrie", "Syrien"], demonyms: ["Syrian", "Sirjan", "siriano", "syrien", "syrienne", "sirio", "syrisch"], places: ["Damascus", "Damasku", "Damasco", "Damas", "Damaskus", "Aleppo"], institutions: [] },
  { key: "morocco", region: "North Africa", names: ["Morocco", "Marokk", "Marocco", "Maroc", "Marruecos", "Marokko"], demonyms: ["Moroccan", "marocchino", "marocain", "marocaine", "marroqu\xED", "marokkanisch"], places: ["Casablanca"], ambiguous: ["Rabat"], institutions: [], aliasExclude: { Rabat: /\b(?:Malta|Gozo|Mdina|Għawdex|Maltese|Malti)\b/i } },
  { key: "algeria", region: "North Africa", names: ["Algeria", "Al\u0121erija", "Alg\xE9rie", "Argelia", "Algerien"], demonyms: ["Algerian", "algerino", "alg\xE9rien", "alg\xE9rienne", "argelino", "algerisch"], places: ["Algiers", "Algeri", "Alger", "Argel", "Algier"], institutions: [] },
  { key: "tunisia", region: "North Africa", names: ["Tunisia", "Tune\u017Cija", "Tunisie", "T\xFAnez", "Tunesien"], demonyms: ["Tunisian", "tunisino", "tunisien", "tunisienne", "tunecino", "tunesisch"], places: ["Tunis"], institutions: [] }
];
var COUNTRY_BY_KEY = new Map(COUNTRIES.map((c) => [c.key, c]));

// src/fetching.js
async function boundedGet(fetchImpl, url, { userAgent, accept, etag, lastModified, timeoutMs = FETCH_TIMEOUT_MS, maxBytes = MAX_BODY_BYTES } = {}) {
  const started = Date.now();
  const headers = { "user-agent": userAgent, accept: accept || "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.3" };
  if (etag) headers["if-none-match"] = etag;
  if (lastModified) headers["if-modified-since"] = lastModified;
  let response;
  try {
    response = await fetchImpl(url, { method: "GET", headers, redirect: "follow", signal: AbortSignal.timeout(timeoutMs) });
  } catch (error) {
    const name = error?.name || "";
    return { transport: name === "TimeoutError" || name === "AbortError" ? "timeout" : "network-error", error: String(error?.message || error).slice(0, 300), duration_ms: Date.now() - started };
  }
  const outcome = {
    transport: "response",
    http_status: response.status,
    content_type: response.headers.get("content-type"),
    etag: response.headers.get("etag"),
    last_modified: response.headers.get("last-modified"),
    final_url: response.url || url,
    duration_ms: 0,
    body: "",
    bytes: 0
  };
  const finalHost = hostOf(outcome.final_url);
  if (finalHost && hostOf(url) && finalHost !== hostOf(url) && !finalHost.endsWith(`.${hostOf(url)}`) && !hostOf(url).endsWith(`.${finalHost}`)) {
    outcome.transport = "redirect-offsite";
  }
  if (response.status === 304 || !response.body) {
    outcome.duration_ms = Date.now() - started;
    return outcome;
  }
  try {
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    for (; ; ) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return { ...outcome, transport: "too-large", bytes: total, duration_ms: Date.now() - started };
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
      bytes.set(c, offset);
      offset += c.byteLength;
    }
    outcome.raw = bytes;
    outcome.bytes = total;
    outcome.charset = declaredCharset(outcome.content_type, bytes);
    try {
      outcome.body = new TextDecoder(outcome.charset).decode(bytes);
    } catch {
      outcome.body = new TextDecoder("utf-8").decode(bytes);
      outcome.error = `unsupported charset ${outcome.charset}; decoded as utf-8`;
    }
  } catch (error) {
    const name = error?.name || "";
    return { ...outcome, transport: name === "TimeoutError" || name === "AbortError" ? "timeout" : "network-error", error: String(error?.message || error).slice(0, 300), duration_ms: Date.now() - started };
  }
  outcome.duration_ms = Date.now() - started;
  return outcome;
}
__name(boundedGet, "boundedGet");
function declaredCharset(contentType, bytes) {
  const fromHeader = String(contentType || "").match(/charset\s*=\s*["']?([\w.:-]+)/i)?.[1];
  if (fromHeader) return fromHeader.toLowerCase();
  const head = new TextDecoder("latin1").decode(bytes.subarray(0, 200));
  return (head.match(/<\?xml[^>]*encoding\s*=\s*["']([\w.:-]+)["']/i)?.[1] || "utf-8").toLowerCase();
}
__name(declaredCharset, "declaredCharset");
var RATE_LIMIT_TEXT = /(rate limit|too many requests|limit requests|please limit|request limit)/i;
function transportClass(outcome) {
  if (outcome.transport === "timeout") return "timeout";
  if (outcome.transport === "network-error") return "network-error";
  if (outcome.transport === "too-large") return "too-large";
  if (outcome.transport === "redirect-offsite") return "redirect-offsite";
  const s = outcome.http_status;
  if (s === 304) return "not-modified";
  if (s === 429) return "rate-limited";
  if (s === 401 || s === 403 || s === 451) return "blocked";
  if (s >= 400) return "http-error";
  if (s >= 200 && s < 300 && outcome.bytes === 0) return "empty-body";
  if (s >= 300) return "http-error";
  if (RATE_LIMIT_TEXT.test(outcome.body.slice(0, 2e3)) && !/<(rss|feed|rdf:RDF)[\s>]/i.test(outcome.body.slice(0, 2e3))) return "rate-limited";
  return null;
}
__name(transportClass, "transportClass");

// src/routing.js
var STOPWORDS = {
  en: ["the", "and", "of", "to", "in", "is", "for", "on", "with", "as", "by", "at", "from", "that", "says", "after", "over", "will", "has", "its"],
  mt: ["il", "l", "u", "ta", "tal", "fil", "g\u0127al", "li", "huwa", "hija", "mill", "biex", "minn", "ma", "dan", "din", "dwar", "kien", "kienet", "wara", "lill", "fuq", "b\u0127ala", "aktar"],
  it: ["il", "la", "di", "che", "e", "per", "del", "della", "con", "non", "un", "una", "sono", "dei", "alle", "nel", "nella", "dopo", "anche", "degli", "gli", "le"],
  fr: ["le", "la", "les", "des", "et", "est", "une", "pour", "dans", "du", "au", "aux", "avec", "sur", "que", "qui", "apr\xE8s", "selon", "un", "pas"],
  es: ["el", "la", "los", "las", "de", "y", "que", "en", "del", "por", "con", "una", "para", "se", "al", "tras", "seg\xFAn", "sobre", "un", "m\xE1s"],
  de: ["der", "die", "das", "und", "ist", "mit", "f\xFCr", "den", "von", "im", "auf", "nicht", "ein", "eine", "nach", "zu", "dem", "bei", "wird", "\xFCber"]
};
var STOP_SETS = Object.fromEntries(Object.entries(STOPWORDS).map(([k, v]) => [k, new Set(v)]));
function normaliseLanguageTag(tag) {
  const base = String(tag || "").trim().toLowerCase().split(/[-_]/)[0];
  return /^[a-z]{2,3}$/.test(base) ? base : null;
}
__name(normaliseLanguageTag, "normaliseLanguageTag");
function detectLanguage(text, { feedLanguage, channelLanguages } = {}) {
  const fromFeed = normaliseLanguageTag(feedLanguage);
  const tokens = String(text || "").toLowerCase().split(/[^\p{L}']+/u).flatMap((t) => t.split("'")).filter(Boolean);
  const scores = Object.fromEntries(Object.keys(STOP_SETS).map((k) => [k, 0]));
  for (const t of tokens) for (const [k, set] of Object.entries(STOP_SETS)) if (set.has(t)) scores[k] += 1;
  if (/[ħġżċ]/i.test(text || "")) scores.mt += 3;
  const ranked = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  const [best, second] = ranked;
  const detected = best[1] >= 2 && best[1] >= second[1] + 2 ? best[0] : null;
  if (fromFeed && (!detected || detected === fromFeed)) return { language: fromFeed, method: "feed-tag" };
  if (detected) return { language: detected, method: fromFeed ? "detected-over-feed-tag" : "detected" };
  if (fromFeed) return { language: fromFeed, method: "feed-tag" };
  if (Array.isArray(channelLanguages) && channelLanguages.length === 1) return { language: channelLanguages[0], method: "channel-register" };
  return { language: null, method: "unknown" };
}
__name(detectLanguage, "detectLanguage");
var escape = /* @__PURE__ */ __name((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "escape");
var MATCHERS = COUNTRIES.map((country) => {
  const groups = [
    ["name", country.names],
    ["demonym", country.demonyms],
    ["place", country.places],
    ["institution", country.institutions],
    ["ambiguous", country.ambiguous]
  ];
  const aliases = [];
  for (const [kind, list] of groups) for (const alias of list || []) aliases.push({ alias, kind, exact: false });
  for (const alias of country.exact || []) aliases.push({ alias, kind: "name", exact: true });
  for (const a of aliases) if (a.kind === "demonym" && country.notAfter) a.notAfter = country.notAfter;
  return {
    country,
    aliases: aliases.map((a) => ({
      ...a,
      capitalised: /^\p{Lu}/u.test(a.alias),
      re: new RegExp(`(?<![\\p{L}\\p{N}])${escape(a.alias)}(?![\\p{L}\\p{N}])`, a.exact ? "gu" : "giu")
    }))
  };
});
var CONFIDENCE = { name: "high", institution: "high", demonym: "medium", place: "medium", ambiguous: "low" };
function isAllCaps(text) {
  const letters = text.replace(/[^\p{L}]/gu, "");
  return letters.length > 3 && letters === letters.toUpperCase();
}
__name(isAllCaps, "isAllCaps");
function findMatches(text, field) {
  const found = [];
  const allCaps = isAllCaps(text);
  for (const { country, aliases } of MATCHERS) {
    if (country.exclude?.some((re) => re.test(text))) continue;
    for (const a of aliases) {
      a.re.lastIndex = 0;
      for (const m of text.matchAll(a.re)) {
        if (!a.exact && a.capitalised && !allCaps && !/^\p{Lu}/u.test(m[0])) continue;
        if (a.notAfter && a.notAfter.test(text.slice(Math.max(0, m.index - 20), m.index))) continue;
        if (country.aliasExclude?.[a.alias]?.test(text)) continue;
        const shouting = a.exact && allCaps && m[0].replace(/\./g, "").length <= 3;
        found.push({ country: country.key, region: country.region, kind: shouting ? "ambiguous" : a.kind, matched: m[0], start: m.index, end: m.index + m[0].length, field });
      }
    }
  }
  return found.filter((f) => !found.some((g) => g !== f && g.start <= f.start && g.end >= f.end && g.end - g.start > f.end - f.start));
}
__name(findMatches, "findMatches");
function routeCountries({ headline, summary }) {
  const matches = [...findMatches(headline || "", "headline"), ...findMatches(summary || "", "summary")];
  const rank = /* @__PURE__ */ __name((m) => (m.field === "headline" ? 0 : 10) + { name: 0, institution: 1, demonym: 2, place: 3, ambiguous: 4 }[m.kind], "rank");
  const best = /* @__PURE__ */ new Map();
  for (const m of matches) {
    const current = best.get(m.country);
    if (!current || rank(m) < rank(current)) best.set(m.country, m);
  }
  return [...best.values()].sort((a, b) => rank(a) - rank(b)).map((m) => ({
    country: m.country,
    region: m.region,
    method: `content-${m.kind}`,
    field: m.field,
    matched: m.matched,
    confidence: m.field === "headline" ? CONFIDENCE[m.kind] : "low"
  }));
}
__name(routeCountries, "routeCountries");
var words = /* @__PURE__ */ __name((pattern) => new RegExp(`(?<![\\p{L}\\p{N}])(?:${pattern})(?![\\p{L}\\p{N}])`, "iu"), "words");
var CATEGORY_RULES = [
  ["Elections & Democracy", words("elections?|electoral|ballot|polling|referend(?:um|a)|votes?|voters?|democra(?:cy|tic)|elezzjoni(?:jiet)?|elezioni|\xE9lections?|elecciones|wahlen?|voto|scrutin")],
  ["Security & Defense", words("security|defen[cs]e|military|armed forces|war|conflicts?|missiles?|attacks?|terror\\w*|nato|ceasefire|gwerra|guerra|guerre|difesa|d\xE9fense|militare|militaire")],
  ["Foreign Affairs & Diplomacy", words("diploma(?:cy|tic)|foreign affairs|summit|bilateral|ambassador|sanctions?|treaty|geopolitic\\w*|united nations|vertice|sommet|cumbre|ambasciatore|ambassadeur")],
  ["Energy & Climate", words("energy|climate|emissions?|renewables?|oil|gas|electricity|solar|wind power|carbon|environment|ener\u0121ija|klima|energia|clima|\xE9nergie|climat|energ\xEDa")],
  ["Economy & Trade", words("econom(?:y|ic|ics|ical|ically)?|trade|tariffs?|markets?|inflation|gdp|finance|banks?|investment|business|employment|tax|budget|credit[- ]?rating|ekonomija|ba\u0121it|economia|bilancio|\xE9conomie|budget|econom\xEDa|presupuesto|inflazione")],
  ["Migration & Borders", words("migration|migrants?|immigration|asylum|refugees?|borders?|deport\\w*|visas?|migranti|immigrazzjoni|immigrazione|migrants?|asile|migrantes|asilo")],
  ["Society & Rights", words("rights?|society|social|health|education|welfare|equality|discrimination|protests?|justice|courts?|sa\u0127\u0127a|edukazzjoni|diritti|salute|droits|sant\xE9|derechos|salud")],
  ["Sports", words("sports?|football|soccer|olympics?|championship|tournament|league|tennis|cycling|cricket|rugby|basketball|baseball|formula\\s*1|grand prix|world cup|calcio|futbol|f\xFAtbol")]
];
function routeCategories(text) {
  if (/\bconflicts?[-\s]+of[-\s]+interests?\b/i.test(text || "")) return ["Governance & Institutions"];
  const hits = CATEGORY_RULES.filter(([, re]) => re.test(text || "")).map(([name]) => name);
  return hits.length ? hits : ["Governance & Institutions"];
}
__name(routeCategories, "routeCategories");

// src/store.js
var CHUNK = 90;
async function loadEndpoint(db, endpointId) {
  const endpoint = await db.prepare("SELECT * FROM endpoints WHERE endpoint_id = ?").bind(endpointId).first();
  if (!endpoint) return null;
  const { results: channels } = await db.prepare(
    `SELECT c.channel_id, c.name, c.rights, c.collection, c.languages_json, c.editorial_rules_json, c.publisher_country_iso,
            json_extract(c.record_json, '$.home_country') AS home_country
       FROM endpoint_channels ec JOIN channels c ON c.channel_id = ec.channel_id WHERE ec.endpoint_id = ? ORDER BY c.channel_id`
  ).bind(endpointId).all();
  const state = await db.prepare("SELECT * FROM endpoint_state WHERE endpoint_id = ?").bind(endpointId).first();
  return {
    ...endpoint,
    config: JSON.parse(endpoint.config_json || "{}"),
    channels: channels.map((c) => ({ ...c, languages: JSON.parse(c.languages_json || "null"), editorial_rules: JSON.parse(c.editorial_rules_json || "[]") })),
    state: state || { interval_minutes: endpoint.base_interval_minutes, consecutive_failures: 0, consecutive_gaps: 0, consecutive_overlaps: 0 }
  };
}
__name(loadEndpoint, "loadEndpoint");
async function dueEndpointIds(db, nowIso, slackMs = 6e4) {
  const cutoff = new Date(Date.parse(nowIso) + slackMs).toISOString();
  const { results } = await db.prepare(
    `SELECT e.endpoint_id FROM endpoints e LEFT JOIN endpoint_state s ON s.endpoint_id = e.endpoint_id
      WHERE e.enabled = 1 AND (s.next_due_at IS NULL OR s.next_due_at <= ?) ORDER BY e.endpoint_id`
  ).bind(cutoff).all();
  return results.map((r) => r.endpoint_id);
}
__name(dueEndpointIds, "dueEndpointIds");
async function leaseEndpoints(db, endpointIds, untilIso) {
  for (let i = 0; i < endpointIds.length; i += CHUNK) {
    const part = endpointIds.slice(i, i + CHUNK);
    await db.prepare(`UPDATE endpoint_state SET next_due_at = ? WHERE endpoint_id IN (${part.map(() => "?").join(",")})`).bind(untilIso, ...part).run();
  }
}
__name(leaseEndpoints, "leaseEndpoints");
async function createRun(db, run) {
  await db.prepare("INSERT INTO runs (run_id, started_at, trigger, endpoints_due, collector) VALUES (?, ?, ?, ?, ?)").bind(run.run_id, run.started_at, run.trigger, run.endpoints_due, run.collector).run();
}
__name(createRun, "createRun");
async function inChunks(db, sqlFor, values, extraBinds = []) {
  const out = [];
  for (let i = 0; i < values.length; i += CHUNK) {
    const part = values.slice(i, i + CHUNK);
    const { results } = await db.prepare(sqlFor(part.map(() => "?").join(","))).bind(...extraBinds, ...part).all();
    out.push(...results);
  }
  return out;
}
__name(inChunks, "inChunks");
async function existingItems(db, itemIds) {
  if (!itemIds.length) return /* @__PURE__ */ new Map();
  const rows = await inChunks(db, (q) => `SELECT item_id, published_at FROM items WHERE item_id IN (${q})`, itemIds);
  return new Map(rows.map((r) => [r.item_id, r.published_at]));
}
__name(existingItems, "existingItems");
async function seenFromEndpoint(db, endpointId, itemIds) {
  if (!itemIds.length) return /* @__PURE__ */ new Set();
  const rows = await inChunks(db, (q) => `SELECT DISTINCT item_id FROM observations WHERE endpoint_id = ? AND item_id IN (${q})`, itemIds, [endpointId]);
  return new Set(rows.map((r) => r.item_id));
}
__name(seenFromEndpoint, "seenFromEndpoint");
async function recentClusters(db, sinceIso, limit = 3e3) {
  const { results } = await db.prepare("SELECT cluster_id, signature, tokens FROM clusters WHERE created_at >= ? ORDER BY created_at DESC LIMIT ?").bind(sinceIso, limit).all();
  return results.map((r) => ({ cluster_id: r.cluster_id, signature: r.signature, tokens: JSON.parse(r.tokens) }));
}
__name(recentClusters, "recentClusters");
function multiInsert(db, head, columns, rows, tail = "") {
  const perRow = columns.length;
  const per = Math.max(1, Math.floor(99 / perRow));
  const out = [];
  for (let i = 0; i < rows.length; i += per) {
    const part = rows.slice(i, i + per);
    const values = part.map(() => `(${columns.map(() => "?").join(", ")})`).join(", ");
    out.push(db.prepare(`${head} (${columns.join(", ")}) VALUES ${values}${tail}`).bind(...part.flatMap((r) => columns.map((c) => r[c] ?? null))));
  }
  return out;
}
__name(multiInsert, "multiInsert");
var ITEM_COLUMNS = [
  "item_id",
  "url_key",
  "canonical_url",
  "original_url",
  "publisher_domain",
  "headline",
  "summary",
  "summary_policy",
  "published_at",
  "published_raw",
  "published_precision",
  "date_kind",
  "date_status",
  "aggregator_seen_at",
  "first_seen_at",
  "first_endpoint_id",
  "first_run_id",
  "language",
  "language_method",
  "cluster_id",
  "via_aggregator",
  "collector"
];
var statements = {
  insertClusters: /* @__PURE__ */ __name((db, rows) => multiInsert(
    db,
    "INSERT OR IGNORE INTO clusters",
    ["cluster_id", "signature", "tokens", "created_at"],
    rows.map((c) => ({ ...c, tokens: JSON.stringify(c.tokens) }))
  ), "insertClusters"),
  insertItems: /* @__PURE__ */ __name((db, rows) => multiInsert(db, "INSERT OR IGNORE INTO items", ITEM_COLUMNS, rows), "insertItems"),
  insertItemChannels: /* @__PURE__ */ __name((db, rows) => multiInsert(db, "INSERT OR IGNORE INTO item_channels", ["item_id", "channel_id", "first_seen_at"], rows), "insertItemChannels"),
  insertObservations: /* @__PURE__ */ __name((db, rows) => multiInsert(
    db,
    "INSERT OR IGNORE INTO observations",
    ["item_id", "endpoint_id", "run_id", "observed_at", "published_raw", "headline_seen"],
    rows
  ), "insertObservations"),
  insertRoutes: /* @__PURE__ */ __name((db, rows) => multiInsert(db, "INSERT OR IGNORE INTO item_routes", ["item_id", "kind", "value", "method", "field", "matched", "confidence"], rows), "insertRoutes"),
  insertResult: /* @__PURE__ */ __name((db, r) => multiInsert(db, "INSERT OR IGNORE INTO endpoint_results", [
    "run_id",
    "endpoint_id",
    "attempted_at",
    "duration_ms",
    "http_status",
    "content_type",
    "final_url",
    "bytes",
    "class",
    "healthy",
    "items_parsed",
    "items_dated",
    "items_undated",
    "items_future",
    "items_rejected",
    "items_new",
    "items_seen_before",
    "oldest_published_at",
    "newest_published_at",
    "overlap",
    "interval_after",
    "body_sha256",
    "snapshot_key",
    "snapshot_policy",
    "detail"
  ], [{ ...r, healthy: r.healthy ? 1 : 0 }]), "insertResult"),
  upsertState: /* @__PURE__ */ __name((db, s) => db.prepare(
    `INSERT INTO endpoint_state (endpoint_id, interval_minutes, next_due_at, last_attempt_at, last_success_at, last_class, etag, last_modified,
       last_body_sha256, last_newest_item_id, last_newest_published_at, consecutive_failures, consecutive_gaps, consecutive_overlaps)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(endpoint_id) DO UPDATE SET interval_minutes = excluded.interval_minutes, next_due_at = excluded.next_due_at,
       last_attempt_at = excluded.last_attempt_at, last_success_at = excluded.last_success_at, last_class = excluded.last_class,
       etag = excluded.etag, last_modified = excluded.last_modified, last_body_sha256 = excluded.last_body_sha256,
       last_newest_item_id = excluded.last_newest_item_id, last_newest_published_at = excluded.last_newest_published_at,
       consecutive_failures = excluded.consecutive_failures, consecutive_gaps = excluded.consecutive_gaps,
       consecutive_overlaps = excluded.consecutive_overlaps`
  ).bind(
    s.endpoint_id,
    s.interval_minutes,
    s.next_due_at,
    s.last_attempt_at,
    s.last_success_at ?? null,
    s.last_class,
    s.etag ?? null,
    s.last_modified ?? null,
    s.last_body_sha256 ?? null,
    s.last_newest_item_id ?? null,
    s.last_newest_published_at ?? null,
    s.consecutive_failures,
    s.consecutive_gaps,
    s.consecutive_overlaps
  ), "upsertState")
};
async function resultExists(db, runId, endpointId) {
  return Boolean(await db.prepare("SELECT 1 AS x FROM endpoint_results WHERE run_id = ? AND endpoint_id = ?").bind(runId, endpointId).first());
}
__name(resultExists, "resultExists");

// src/urls.js
var TRACKING = /^(utm_[a-z]+|fbclid|gclid|dclid|msclkid|mc_cid|mc_eid|ocid|cmpid|cmp|at_medium|at_campaign|at_custom\d|at_ptr_name|at_link_id|ito|xtor|ns_mchannel|ns_source|ns_campaign|ns_linkname|ns_fee|smid|sr_share|taid|guccounter|_ga|_hsenc|_hsmi|mkt_tok|ref_src|s_cid)$/i;
function canonicalizeUrl(link, base) {
  let url;
  try {
    url = new URL(String(link || "").trim(), base || void 0);
  } catch {
    return null;
  }
  if (!/^https?:$/.test(url.protocol)) return null;
  const routedHash = /^#[!/]/.test(url.hash) ? url.hash : "";
  url.hash = routedHash;
  url.username = "";
  url.password = "";
  url.hostname = url.hostname.toLowerCase();
  if (url.protocol === "https:" && url.port === "443" || url.protocol === "http:" && url.port === "80") url.port = "";
  const kept = [...url.searchParams.entries()].filter(([k]) => !TRACKING.test(k)).sort(([a, av], [b, bv]) => a === b ? av.localeCompare(bv) : a.localeCompare(b));
  url.search = "";
  for (const [k, v] of kept) url.searchParams.append(k, v);
  const host = url.host.replace(/^www\./, "");
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const key = `${host}${path}${url.search}${routedHash}`;
  return { canonical_url: url.toString(), url_key: key, publisher_domain: url.hostname.replace(/^www\./, "") };
}
__name(canonicalizeUrl, "canonicalizeUrl");
async function itemIdFor(urlKey) {
  return `it_${(await sha256Hex(urlKey)).slice(0, 24)}`;
}
__name(itemIdFor, "itemIdFor");

// src/collect.js
var HEALTHY = /* @__PURE__ */ new Set(["ok", "not-modified"]);
var CONFIDENCE_ORDER = ["low", "medium", "high"];
var bestConfidence = /* @__PURE__ */ __name((list) => list.reduce((best, c) => CONFIDENCE_ORDER.indexOf(c) > CONFIDENCE_ORDER.indexOf(best) ? c : best, "low"), "bestConfidence");
var HEADLINE_ONLY_RULE = /headline\s*\+\s*link only/i;
function adapterFor(endpoint) {
  if (endpoint.adapter === "rss") return { url: endpoint.url, parse: /* @__PURE__ */ __name((body) => rssAdapter(body), "parse"), accept: void 0 };
  if (endpoint.adapter === "direct-page") {
    if (endpoint.config.parser === "eurobarometer-latest-v1") return { url: endpoint.url, parse: /* @__PURE__ */ __name((body) => eurobarometerLatestAdapter(body, endpoint), "parse"), accept: "application/json" };
    if (endpoint.config.parser !== "maltatoday-home-v1") throw new Error(`No parser for ${endpoint.config.parser}`);
    return { url: endpoint.url, parse: /* @__PURE__ */ __name((body) => maltaTodayHomeAdapter(body, endpoint), "parse"), accept: "text/html" };
  }
  if (endpoint.adapter === "aggregator") return { url: gdeltRequestUrl(endpoint), parse: /* @__PURE__ */ __name((body) => gdeltAdapter(body, endpoint), "parse"), accept: "application/json" };
  throw new Error(`Unknown adapter ${endpoint.adapter}`);
}
__name(adapterFor, "adapterFor");
function snapshotPolicy(endpoint) {
  if (endpoint.adapter === "direct-page") return "hash-only";
  const restricted = endpoint.channels.some((c) => c.rights === "paywalled" || (c.editorial_rules || []).some((r) => HEADLINE_ONLY_RULE.test(r)));
  return restricted ? "hash-only" : "body";
}
__name(snapshotPolicy, "snapshotPolicy");
function nextInterval(state, endpoint, overlap, seenShare, failed) {
  let interval = state.interval_minutes || endpoint.base_interval_minutes;
  let gaps = state.consecutive_gaps || 0;
  let overlaps = state.consecutive_overlaps || 0;
  if (overlap === 0) {
    interval = Math.max(MIN_INTERVAL_MINUTES, Math.floor(interval / 2));
    gaps += 1;
    overlaps = 0;
  } else if (overlap === 1) {
    gaps = 0;
    if (seenShare >= RELAX_AFTER_OVERLAP_SHARE) {
      overlaps += 1;
      if (overlaps >= 4) {
        const ceiling = Math.min(MAX_INTERVAL_MINUTES, Number(endpoint.config?.max_interval_minutes) || MAX_INTERVAL_MINUTES);
        interval = Math.min(ceiling, Math.max(endpoint.base_interval_minutes, Math.round(interval * 1.5)));
        overlaps = 0;
      }
    } else overlaps = 0;
  }
  const failures = failed ? (state.consecutive_failures || 0) + 1 : 0;
  const backoff = failed ? Math.min(2 ** (failures - 1), 8) : 1;
  return { interval, gaps, overlaps, failures, waitMinutes: failed ? Math.min(interval * backoff, MAX_BACKOFF_WAIT_MINUTES) : interval };
}
__name(nextInterval, "nextInterval");
function assessOverlap(state, stable) {
  if (!stable.length || !state.last_newest_item_id) return null;
  if (stable.some((it) => it.item_id === state.last_newest_item_id && it.published_at === state.last_newest_published_at)) return 1;
  const newer = stable.filter((it) => it.published_at > state.last_newest_published_at);
  if (!newer.length) return 1;
  return 0;
}
__name(assessOverlap, "assessOverlap");
function emptyResult(runId, endpointId, now) {
  return {
    run_id: runId,
    endpoint_id: endpointId,
    attempted_at: now,
    duration_ms: null,
    http_status: null,
    content_type: null,
    final_url: null,
    bytes: null,
    class: null,
    healthy: false,
    items_parsed: 0,
    items_dated: 0,
    items_undated: 0,
    items_future: 0,
    items_rejected: 0,
    items_new: 0,
    items_seen_before: 0,
    oldest_published_at: null,
    newest_published_at: null,
    overlap: null,
    interval_after: null,
    body_sha256: null,
    snapshot_key: null,
    snapshot_policy: "none",
    detail: null
  };
}
__name(emptyResult, "emptyResult");
async function collectEndpoint(endpointId, deps) {
  const { db, runId } = deps;
  const nowMs = deps.nowMs ?? Date.now();
  const now = new Date(nowMs).toISOString();
  const endpoint = await loadEndpoint(db, endpointId);
  if (!endpoint) throw new Error(`Unknown endpoint ${endpointId}`);
  if (await resultExists(db, runId, endpointId)) return { skipped: "already-collected-in-this-run", run_id: runId, endpoint_id: endpointId };
  try {
    return await collectOnce(endpoint, deps, nowMs, now);
  } catch (error) {
    const result = { ...emptyResult(runId, endpointId, now), class: "internal-error", detail: String(error?.message || error).slice(0, 300) };
    const state = endpoint.state;
    const next = nextInterval(state, endpoint, null, 0, true);
    result.interval_after = next.interval;
    const anchor = deps.scheduledMs ?? nowMs;
    await db.batch([
      ...statements.insertResult(db, result),
      statements.upsertState(db, {
        ...state,
        endpoint_id: endpointId,
        interval_minutes: next.interval,
        next_due_at: new Date(anchor + next.waitMinutes * 6e4).toISOString(),
        last_attempt_at: now,
        last_class: "internal-error",
        consecutive_failures: next.failures,
        consecutive_gaps: state.consecutive_gaps || 0,
        consecutive_overlaps: state.consecutive_overlaps || 0
      })
    ]);
    return result;
  }
}
__name(collectEndpoint, "collectEndpoint");
async function collectOnce(endpoint, deps, nowMs, now) {
  const { db, bucket, fetchImpl, runId } = deps;
  const endpointId = endpoint.endpoint_id;
  const state = endpoint.state;
  const adapter = adapterFor(endpoint);
  const outcome = await boundedGet(fetchImpl, adapter.url, {
    userAgent: deps.userAgent || DEFAULT_USER_AGENT,
    accept: adapter.accept,
    etag: endpoint.adapter === "rss" ? state.etag : null,
    lastModified: endpoint.adapter === "rss" ? state.last_modified : null
  });
  const result = {
    ...emptyResult(runId, endpointId, now),
    duration_ms: outcome.duration_ms,
    http_status: outcome.http_status ?? null,
    content_type: outcome.content_type ?? null,
    final_url: outcome.final_url ?? null,
    bytes: outcome.bytes ?? null,
    detail: outcome.error || null
  };
  let cls = transportClass(outcome);
  const writes = [];
  let seenShare = 0;
  let newest = null;
  if (cls === null) {
    const parsed = adapter.parse(outcome.body);
    if (!parsed.parsed) cls = "unparseable";
    else {
      const records = await buildRecords(parsed, endpoint, nowMs);
      result.items_parsed = parsed.items.length;
      result.items_rejected = records.rejected + (parsed.rejected_by_allowlist || 0);
      const items = records.items;
      for (const it of items) {
        if (it.date_status === "dated") result.items_dated += 1;
        else if (it.date_status === "future") result.items_future += 1;
        else result.items_undated += 1;
      }
      const byDate = /* @__PURE__ */ __name((a, b) => a.published_at < b.published_at ? -1 : a.published_at > b.published_at ? 1 : 0, "byDate");
      const dated = items.filter((it) => it.date_status === "dated").sort(byDate);
      result.oldest_published_at = dated[0]?.published_at || null;
      result.newest_published_at = dated.at(-1)?.published_at || null;
      const ids = items.map((it) => it.item_id);
      const known = await existingItems(db, ids);
      const stable = dated.filter((it) => !known.has(it.item_id) || known.get(it.item_id) === it.published_at);
      newest = stable.at(-1) || null;
      const seenHere = await seenFromEndpoint(db, endpointId, ids);
      result.items_seen_before = seenHere.size;
      result.items_new = items.filter((it) => !known.has(it.item_id)).length;
      seenShare = items.length ? seenHere.size / items.length : 0;
      const fresh = items.filter((it) => !known.has(it.item_id));
      const clusters = fresh.length ? await recentClusters(db, new Date(nowMs - CLUSTER_WINDOW_HOURS * 36e5).toISOString()) : [];
      const newClusters = [];
      const itemRows = [];
      const routeRows = [];
      for (const it of fresh) {
        let clusterId = null;
        if (it.tokens.length >= CLUSTER_MIN_SHARED_TOKENS) {
          const signature = await signatureFor(it.tokens);
          const match = clusters.find((c) => c.signature === signature) || bestCluster(it.tokens, clusters);
          if (match) clusterId = match.cluster_id;
          else {
            const created = { cluster_id: `cl_${(await sha256Hex(`${signature}|${now}|${it.item_id}`)).slice(0, 24)}`, signature, tokens: it.tokens, created_at: now };
            clusters.unshift(created);
            newClusters.push(created);
            clusterId = created.cluster_id;
          }
        }
        itemRows.push({ ...it, first_seen_at: now, first_endpoint_id: endpointId, first_run_id: runId, cluster_id: clusterId, collector: COLLECTOR_VERSION });
        for (const r of it.routes) routeRows.push({ item_id: it.item_id, ...r });
      }
      writes.push(...statements.insertClusters(db, newClusters));
      writes.push(...statements.insertItems(db, itemRows));
      writes.push(...statements.insertRoutes(db, routeRows));
      writes.push(...statements.insertItemChannels(db, items.flatMap((it) => endpoint.channels.map((ch) => ({ item_id: it.item_id, channel_id: ch.channel_id, first_seen_at: now })))));
      writes.push(...statements.insertObservations(db, items.map((it) => ({ item_id: it.item_id, endpoint_id: endpointId, run_id: runId, observed_at: now, published_raw: it.published_raw, headline_seen: it.headline }))));
      if (!items.length) cls = "ok-empty";
      else if (endpoint.adapter === "aggregator") cls = items.some((it) => it.aggregator_seen_at) ? "ok" : "ok-undated-only";
      else cls = result.items_dated ? "ok" : "ok-undated-only";
      if (cls === "ok" && endpoint.adapter !== "aggregator") result.overlap = assessOverlap(state, stable);
    }
  }
  if (cls === "not-modified") result.overlap = 1;
  result.class = cls;
  result.healthy = HEALTHY.has(cls);
  if (outcome.raw && outcome.bytes) {
    result.body_sha256 = await sha256Hex(outcome.raw);
    result.snapshot_policy = snapshotPolicy(endpoint);
    if (bucket && result.snapshot_policy === "body" && result.body_sha256 !== state.last_body_sha256) {
      const key = `snapshots/${endpointId}/${now.slice(0, 10)}/${result.body_sha256}.${endpoint.adapter === "aggregator" ? "json" : "xml"}`;
      try {
        await bucket.put(key, outcome.raw, {
          httpMetadata: { contentType: outcome.content_type || "application/octet-stream" },
          customMetadata: { endpoint_id: endpointId, url: endpoint.url, fetched_at: now, run_id: runId }
        });
        result.snapshot_key = key;
      } catch (error) {
        result.detail = [result.detail, `snapshot-failed: ${String(error?.message || error).slice(0, 120)}`].filter(Boolean).join("; ");
      }
    }
  }
  const failed = !result.healthy && !["ok-empty", "ok-undated-only"].includes(cls);
  const next = nextInterval(state, endpoint, result.overlap, seenShare, failed);
  result.interval_after = next.interval;
  const anchor = deps.scheduledMs ?? nowMs;
  writes.push(...statements.insertResult(db, result));
  writes.push(statements.upsertState(db, {
    endpoint_id: endpointId,
    interval_minutes: next.interval,
    next_due_at: new Date(anchor + next.waitMinutes * 6e4).toISOString(),
    last_attempt_at: now,
    last_success_at: result.healthy ? now : state.last_success_at,
    last_class: cls,
    etag: cls === "ok" || cls === "not-modified" ? outcome.etag || state.etag : state.etag,
    last_modified: cls === "ok" || cls === "not-modified" ? outcome.last_modified || state.last_modified : state.last_modified,
    last_body_sha256: result.body_sha256 || state.last_body_sha256,
    last_newest_item_id: cls === "ok" && newest ? newest.item_id : state.last_newest_item_id,
    last_newest_published_at: cls === "ok" && newest ? newest.published_at : state.last_newest_published_at,
    consecutive_failures: next.failures,
    consecutive_gaps: next.gaps,
    consecutive_overlaps: next.overlaps
  }));
  await db.batch(writes);
  return result;
}
__name(collectOnce, "collectOnce");
async function buildRecords(parsed, endpoint, nowMs) {
  const headlineOnly = endpoint.channels.some((c) => (c.editorial_rules || []).some((r) => HEADLINE_ONLY_RULE.test(r)));
  const channelLanguages = [...new Set(endpoint.channels.flatMap((c) => c.languages || []))];
  const byKey = /* @__PURE__ */ new Map();
  let rejected = 0;
  for (const raw of parsed.items.slice(0, MAX_ITEMS_PER_POLL)) {
    const headline = cleanText(raw.title, HEADLINE_MAX_CHARS);
    const url = canonicalizeUrl(raw.link, endpoint.url);
    if (!headline || !url) {
      rejected += 1;
      continue;
    }
    if (byKey.has(url.url_key)) continue;
    let date;
    if (raw.date_kind === "page-local-time") {
      date = classifyDate(raw.published_iso || "", "page-local-time", nowMs);
      date.date_kind = "page-local-time";
      if (raw.published_iso) date.published_raw = raw.date_raw;
    } else if (raw.date_kind === "aggregator-first-seen") {
      date = { published_at: null, published_raw: null, precision: null, date_kind: "aggregator-first-seen", status: "undated" };
    } else {
      date = classifyDate(raw.date_raw, raw.date_kind, nowMs, { date_order: endpoint.config?.date_order });
    }
    const summaryText = headlineOnly ? "" : cleanText(raw.summary, SUMMARY_MAX_CHARS);
    const text = `${headline}. ${summaryText}`;
    const lang = endpoint.adapter === "aggregator" ? detectLanguage(text, { feedLanguage: raw.aggregator_language === "English" ? "en" : null }) : detectLanguage(text, { feedLanguage: parsed.feed_language, channelLanguages });
    const countryRoutes = routeCountries({ headline, summary: summaryText });
    const routes = [
      ...countryRoutes.map((r) => ({ kind: "country", value: r.country, method: r.method, field: r.field, matched: r.matched, confidence: r.confidence })),
      ...[...new Set(countryRoutes.map((r) => r.region))].map((region) => ({
        kind: "region",
        value: region,
        method: "from-country",
        field: null,
        matched: null,
        confidence: bestConfidence(countryRoutes.filter((r) => r.region === region).map((r) => r.confidence))
      })),
      ...routeCategories(text).map((c) => ({ kind: "category", value: c, method: "keyword-rules-v1", field: null, matched: null, confidence: null }))
    ];
    const homeCountry = endpoint.channels.map((c) => c.home_country).find((k) => k && COUNTRY_BY_KEY.has(k));
    if (homeCountry && !countryRoutes.some((r) => r.confidence === "high" || r.confidence === "medium")) {
      routes.push({ kind: "country", value: homeCountry, method: "home-newsroom", field: null, matched: null, confidence: "medium" });
      const region = COUNTRY_BY_KEY.get(homeCountry).region;
      if (!routes.some((r) => r.kind === "region" && r.value === region)) routes.push({ kind: "region", value: region, method: "from-country", field: null, matched: null, confidence: "medium" });
    }
    if (raw.scope_country && !countryRoutes.some((r) => r.country === raw.scope_country)) {
      routes.push({ kind: "country", value: raw.scope_country, method: "publisher-section", field: "url-path", matched: null, confidence: "medium" });
      const region = COUNTRY_BY_KEY.get(raw.scope_country)?.region;
      if (region && !routes.some((r) => r.kind === "region" && r.value === region)) routes.push({ kind: "region", value: region, method: "from-country", field: null, matched: null, confidence: "medium" });
    }
    byKey.set(url.url_key, {
      item_id: await itemIdFor(url.url_key),
      url_key: url.url_key,
      canonical_url: url.canonical_url,
      original_url: String(raw.link).slice(0, 2e3),
      publisher_domain: url.publisher_domain,
      headline,
      summary: summaryText || null,
      summary_policy: headlineOnly ? "omitted-by-rule" : summaryText ? "feed-text" : "none",
      published_at: date.published_at,
      published_raw: date.published_raw,
      published_precision: date.precision,
      date_kind: date.date_kind,
      date_status: date.status,
      aggregator_seen_at: raw.aggregator_seen_at || null,
      language: lang.language,
      language_method: lang.method,
      via_aggregator: endpoint.adapter === "aggregator" ? 1 : 0,
      tokens: headlineTokens(headline),
      routes
    });
  }
  return { items: [...byKey.values()], rejected };
}
__name(buildRecords, "buildRecords");

// src/reports.js
async function healthReport(db, { days = 14, nowMs = Date.now() } = {}) {
  const run = await db.prepare(
    "SELECT r.* FROM runs r WHERE EXISTS (SELECT 1 FROM endpoint_results x WHERE x.run_id = r.run_id) ORDER BY r.started_at DESC LIMIT 1"
  ).first();
  let latest = null;
  if (run) {
    const { results } = await db.prepare("SELECT class, healthy, COUNT(*) AS n FROM endpoint_results WHERE run_id = ? GROUP BY class, healthy").bind(run.run_id).all();
    const reported = results.reduce((s, r) => s + r.n, 0);
    const healthy = results.filter((r) => r.healthy).reduce((s, r) => s + r.n, 0);
    const share = reported ? healthy / reported : 0;
    const pending = Math.max(0, run.endpoints_due - reported);
    const state = healthy === 0 ? "failed" : share >= RUN_ACTIVE_MIN_HEALTHY_SHARE && pending === 0 ? "active" : "partial";
    latest = {
      run_id: run.run_id,
      started_at: run.started_at,
      trigger: run.trigger,
      endpoints_due: run.endpoints_due,
      reported,
      pending,
      healthy,
      healthy_share: Number(share.toFixed(3)),
      state,
      threshold: { healthy_share: RUN_ACTIVE_MIN_HEALTHY_SHARE, status: "TBD \u2014 placeholder" },
      classes: Object.fromEntries(results.map((r) => [r.class, r.n]))
    };
  }
  const since = new Date(nowMs - days * 864e5).toISOString();
  const { results: perEndpoint } = await db.prepare(
    `SELECT e.endpoint_id, e.url, e.adapter, e.enabled, s.interval_minutes, s.last_class, s.last_success_at, s.last_attempt_at, s.next_due_at, s.consecutive_failures,
            (SELECT GROUP_CONCAT(c.name, ' \xB7 ') FROM endpoint_channels ec JOIN channels c ON c.channel_id = ec.channel_id WHERE ec.endpoint_id = e.endpoint_id) AS names,
            json_extract(e.config_json, '$.status') AS registry_status, json_extract(e.config_json, '$.reason') AS registry_reason,
            COUNT(r.result_id) AS polls, SUM(r.healthy) AS healthy_polls,
            SUM(CASE WHEN r.overlap IS NOT NULL THEN 1 ELSE 0 END) AS assessed, SUM(CASE WHEN r.overlap = 1 THEN 1 ELSE 0 END) AS overlapped,
            SUM(CASE WHEN r.overlap = 0 THEN 1 ELSE 0 END) AS gaps, SUM(r.items_new) AS items_new, SUM(r.items_undated) AS undated_seen,
            SUM(r.items_future) AS future_seen
       FROM endpoints e LEFT JOIN endpoint_state s ON s.endpoint_id = e.endpoint_id
       LEFT JOIN endpoint_results r ON r.endpoint_id = e.endpoint_id AND r.attempted_at >= ?
      GROUP BY e.endpoint_id ORDER BY e.url`
  ).bind(since).all();
  const endpoints = perEndpoint.map((e) => {
    const overlapShare = e.assessed ? e.overlapped / e.assessed : null;
    return {
      ...e,
      overlap_share: overlapShare === null ? null : Number(overlapShare.toFixed(3)),
      c5: overlapShare === null ? "not-assessable" : overlapShare >= 0.95 ? "pass" : "flagged"
    };
  });
  return { generated_at: new Date(nowMs).toISOString(), window_days: days, latest_run: latest, endpoints };
}
__name(healthReport, "healthReport");
async function coverageReport(db, { hours = 24, nowMs = Date.now() } = {}) {
  const since = new Date(nowMs - hours * 36e5).toISOString();
  const { results } = await db.prepare(
    `SELECT r.kind, r.value, COUNT(DISTINCT CASE WHEN r.confidence IS NULL OR r.confidence != 'low' THEN i.item_id END) AS items,
            COUNT(DISTINCT CASE WHEN r.confidence = 'low' THEN i.item_id END) AS low_confidence,
            COUNT(DISTINCT i.publisher_domain) AS publishers,
            SUM(CASE WHEN i.date_status = 'undated' THEN 1 ELSE 0 END) AS undated
       FROM item_routes r JOIN items i ON i.item_id = r.item_id
      WHERE i.first_seen_at >= ? AND i.date_status != 'future'
      GROUP BY r.kind, r.value`
  ).bind(since).all();
  const by = /* @__PURE__ */ __name((kind) => new Map(results.filter((r) => r.kind === kind).map((r) => [r.value, r])), "by");
  const countries = by("country");
  const threshold = COVERAGE_THIN_THRESHOLD_PER_DAY === null ? null : COVERAGE_THIN_THRESHOLD_PER_DAY * (hours / 24);
  return {
    generated_at: new Date(nowMs).toISOString(),
    window_hours: hours,
    threshold: threshold === null ? "not set (TBD, recovery register R16)" : threshold,
    countries: COUNTRIES.map((c) => {
      const row = countries.get(c.key);
      const items = row?.items || 0;
      return {
        country: c.key,
        name: c.names[0],
        region: c.region,
        items,
        low_confidence_only: row?.low_confidence || 0,
        publishers: row?.publishers || 0,
        undated: row?.undated || 0,
        status: items === 0 ? "no-coverage" : threshold === null ? "threshold-not-set" : items < threshold ? "thin" : "covered"
      };
    }),
    regions: Object.fromEntries([...by("region").values()].map((r) => [r.value, r.items])),
    categories: Object.fromEntries([...by("category").values()].map((r) => [r.value, r.items]))
  };
}
__name(coverageReport, "coverageReport");
async function listItems(db, { since, until, country, category, channel, q, includeFuture = false, includeLowConfidence = false, limit = 100 } = {}) {
  const where = ["1 = 1"];
  const binds = [];
  const text = String(q || "").trim().slice(0, 100);
  if (text) {
    where.push("i.headline LIKE ? ESCAPE '\\'");
    binds.push(`%${text.replace(/[\\%_]/g, (ch) => `\\${ch}`)}%`);
  }
  if (since) {
    where.push("i.first_seen_at >= ?");
    binds.push(since);
  }
  if (until) {
    where.push("i.first_seen_at < ?");
    binds.push(until);
  }
  if (!includeFuture) where.push("i.date_status != 'future'");
  const conf = includeLowConfidence ? "" : " AND (r.confidence IS NULL OR r.confidence != 'low')";
  if (country) {
    where.push(`EXISTS (SELECT 1 FROM item_routes r WHERE r.item_id = i.item_id AND r.kind = 'country' AND r.value = ?${conf})`);
    binds.push(country);
  }
  if (category) {
    where.push("EXISTS (SELECT 1 FROM item_routes r WHERE r.item_id = i.item_id AND r.kind = 'category' AND r.value = ?)");
    binds.push(category);
  }
  if (channel) {
    where.push("EXISTS (SELECT 1 FROM item_channels c WHERE c.item_id = i.item_id AND c.channel_id = ?)");
    binds.push(channel);
  }
  const { results } = await db.prepare(
    `SELECT i.item_id, i.canonical_url, i.publisher_domain, i.headline, i.summary, i.summary_policy, i.published_at, i.published_precision,
            i.date_kind, i.date_status, i.aggregator_seen_at, i.first_seen_at, i.language, i.cluster_id, i.via_aggregator,
            (SELECT MAX(o.observed_at) FROM observations o WHERE o.item_id = i.item_id) AS last_seen_at,
            (SELECT GROUP_CONCAT(c.channel_id) FROM item_channels c WHERE c.item_id = i.item_id) AS channel_ids
       FROM items i WHERE ${where.join(" AND ")} ORDER BY i.first_seen_at DESC, i.item_id LIMIT ?`
  ).bind(...binds, Math.max(1, Math.min(Math.trunc(Number(limit)) || 100, 500))).all();
  return results.map((r) => ({
    ...r,
    channel_ids: r.channel_ids ? r.channel_ids.split(",").sort() : [],
    date_label: r.date_status === "undated" ? "undated" : r.date_status === "future" ? "future-dated (quarantined)" : r.published_precision === "day" ? "date only" : r.published_precision === "no-zone" ? "time without zone" : "dated"
  }));
}
__name(listItems, "listItems");
async function getItem(db, itemId) {
  const item = await db.prepare("SELECT * FROM items WHERE item_id = ?").bind(itemId).first();
  if (!item) return null;
  const [channels, observations, routes, cluster] = await Promise.all([
    db.prepare("SELECT channel_id, first_seen_at FROM item_channels WHERE item_id = ? ORDER BY channel_id").bind(itemId).all(),
    db.prepare("SELECT endpoint_id, run_id, observed_at, published_raw FROM observations WHERE item_id = ? ORDER BY observed_at").bind(itemId).all(),
    db.prepare("SELECT kind, value, method, field, matched, confidence FROM item_routes WHERE item_id = ? ORDER BY kind, value").bind(itemId).all(),
    item.cluster_id ? db.prepare("SELECT item_id, publisher_domain, headline, published_at FROM items WHERE cluster_id = ? AND item_id != ? ORDER BY first_seen_at").bind(item.cluster_id, itemId).all() : Promise.resolve({ results: [] })
  ]);
  return { item, channels: channels.results, observations: observations.results, routes: routes.results, same_story: cluster.results };
}
__name(getItem, "getItem");
async function summaryReport(db, { nowMs = Date.now() } = {}) {
  const day = new Date(nowMs - 864e5).toISOString();
  const totals = await db.prepare(
    `SELECT COUNT(*) AS items,
            SUM(CASE WHEN first_seen_at >= ? THEN 1 ELSE 0 END) AS items_24h,
            SUM(CASE WHEN date_status = 'dated' THEN 1 ELSE 0 END) AS dated,
            SUM(CASE WHEN date_status = 'undated' THEN 1 ELSE 0 END) AS undated,
            SUM(CASE WHEN date_status = 'future' THEN 1 ELSE 0 END) AS future,
            COUNT(DISTINCT publisher_domain) AS publishers
       FROM items`
  ).bind(day).first();
  const { results: runs } = await db.prepare(
    `SELECT r.run_id, r.started_at, r.trigger, r.endpoints_due, COUNT(x.result_id) AS reported, COALESCE(SUM(x.healthy), 0) AS healthy,
            COALESCE(SUM(x.items_new), 0) AS items_new
       FROM runs r JOIN endpoint_results x ON x.run_id = r.run_id
      GROUP BY r.run_id ORDER BY r.started_at DESC LIMIT 30`
  ).all();
  const { results: feedRows } = await db.prepare(
    `SELECT e.enabled, COALESCE(s.last_class, 'not-yet-checked') AS last_class, COUNT(*) AS n
       FROM endpoints e LEFT JOIN endpoint_state s ON s.endpoint_id = e.endpoint_id GROUP BY e.enabled, COALESCE(s.last_class, 'not-yet-checked')`
  ).all();
  const on = feedRows.filter((r) => r.enabled);
  const healthyNow = on.filter((r) => r.last_class === "ok" || r.last_class === "not-modified").reduce((a, r) => a + r.n, 0);
  const notYet = on.filter((r) => r.last_class === "not-yet-checked").reduce((a, r) => a + r.n, 0);
  const enabled = on.reduce((a, r) => a + r.n, 0);
  const next = await db.prepare(
    `SELECT MIN(s.next_due_at) AS next_due_at FROM endpoint_state s JOIN endpoints e ON e.endpoint_id = s.endpoint_id WHERE e.enabled = 1 AND s.next_due_at > ?`
  ).bind(new Date(nowMs).toISOString()).first();
  const first = await db.prepare("SELECT MIN(started_at) AS first_run_at FROM runs").first();
  return {
    generated_at: new Date(nowMs).toISOString(),
    first_run_at: first?.first_run_at || null,
    totals: { items: totals?.items || 0, items_24h: totals?.items_24h || 0, dated: totals?.dated || 0, undated: totals?.undated || 0, future: totals?.future || 0, publishers: totals?.publishers || 0 },
    feeds: {
      enabled,
      switched_off: feedRows.filter((r) => !r.enabled).reduce((a, r) => a + r.n, 0),
      healthy_now: healthyNow,
      not_yet_checked: notYet,
      failing_now: enabled - healthyNow - notYet,
      by_last_result: Object.fromEntries(on.map((r) => [r.last_class, r.n]))
    },
    next_check_at: next?.next_due_at || null,
    runs
  };
}
__name(summaryReport, "summaryReport");

// src/ui-bundle.js
var UI_FILES = {
  "index.html": {
    "type": "text/html; charset=utf-8",
    "body": `<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Evidence Engine \xB7 Trial</title>
<link rel="stylesheet" href="/app.css">
<script src="/app.js" defer><\/script>
</head>
<body>
<header class="top">
  <div class="wrap top-row">
    <div class="brand">
      <span class="mark" aria-hidden="true">TPN</span>
      <div>
        <div class="brand-name">Evidence Engine</div>
        <div class="brand-sub" id="trial-line">Shadow trial</div>
      </div>
    </div>
    <div class="who" id="who"></div>
  </div>
  <nav class="wrap tabs" aria-label="Views">
    <a href="#overview" data-view="overview">Overview</a>
    <a href="#feeds" data-view="feeds">Feeds</a>
    <a href="#coverage" data-view="coverage">Coverage</a>
    <a href="#articles" data-view="articles">Articles</a>
    <a href="https://meridian.tpnintel.com/trial/compare" rel="noopener">Live vs engine \u2197</a>
  </nav>
</header>

<main class="wrap" id="main">
  <section id="view-overview" class="view" hidden>
    <div class="tiles" id="tiles"></div>
    <div class="grid2">
      <article class="card">
        <h2>Recent runs</h2>
        <p class="note">Each run checks only the feeds that are due. Times are Malta time.</p>
        <div class="table-wrap"><table id="runs-table"><thead><tr><th>Started</th><th class="num">Checked</th><th class="num">Healthy</th><th class="num">New</th></tr></thead><tbody></tbody></table></div>
      </article>
      <article class="card">
        <h2>Feeds now, by last result</h2>
        <p class="note">The latest result of every switched-on feed. Only "ok" and "not modified" count as healthy.</p>
        <ul class="bars" id="class-bars"></ul>
      </article>
    </div>
    <article class="card">
      <h2>How articles are dated</h2>
      <p class="note">An article without a date stays "undated"; it is never given the time it was collected. Articles dated in the future are set aside.</p>
      <ul class="bars" id="date-bars"></ul>
    </article>
  </section>

  <section id="view-feeds" class="view" hidden>
    <div class="toolbar">
      <div class="chips" id="feed-chips" role="group" aria-label="Show feeds">
        <button type="button" data-filter="all" aria-pressed="true">All</button>
        <button type="button" data-filter="healthy" aria-pressed="false">Healthy</button>
        <button type="button" data-filter="failing" aria-pressed="false">Failing</button>
        <button type="button" data-filter="waiting" aria-pressed="false">Not yet checked</button>
        <button type="button" data-filter="off" aria-pressed="false">Switched off</button>
      </div>
      <input type="search" id="feed-search" placeholder="Search sources" aria-label="Search sources">
    </div>
    <p class="note" id="feed-count"></p>
    <div class="table-wrap"><table id="feeds-table"><thead><tr>
      <th>Source</th><th>Status</th><th>Last result</th><th>Last success</th><th class="num">Every</th><th class="num">Healthy checks</th><th class="num">New articles</th><th class="num">Gaps</th>
    </tr></thead><tbody></tbody></table></div>
  </section>

  <section id="view-coverage" class="view" hidden>
    <div class="toolbar">
      <div class="chips" id="cov-chips" role="group" aria-label="Time window">
        <button type="button" data-hours="24" aria-pressed="true">Last 24 hours</button>
        <button type="button" data-hours="168" aria-pressed="false">Last 7 days</button>
        <button type="button" data-hours="720" aria-pressed="false">Last 30 days</button>
      </div>
    </div>
    <p class="note">Country comes from the article's own words, never from where the publisher is based. Mentions that are only weak hints (an ambiguous name, a country named only in the summary) are shown separately and not counted.</p>
    <div class="grid2">
      <article class="card"><h2>Countries</h2><div id="cov-countries"></div></article>
      <article class="card"><h2>Topics</h2><ul class="bars" id="cov-topics"></ul><h2 class="mt">Regions</h2><ul class="bars" id="cov-regions"></ul></article>
    </div>
  </section>

  <section id="view-articles" class="view" hidden>
    <form class="toolbar filters" id="item-filters">
      <input type="search" name="q" placeholder="Search headlines" aria-label="Search headlines">
      <select name="country" aria-label="Country"><option value="">All countries</option></select>
      <select name="category" aria-label="Topic"><option value="">All topics</option></select>
      <select name="channel" aria-label="Source"><option value="">All sources</option></select>
      <select name="since" aria-label="Collected">
        <option value="24">Collected in the last 24 hours</option>
        <option value="168">Last 7 days</option>
        <option value="">Any time</option>
      </select>
    </form>
    <p class="note" id="item-count"></p>
    <ol class="items" id="items"></ol>
  </section>

  <p class="status" id="status" role="status"></p>
</main>

<div class="drawer" id="drawer" hidden>
  <div class="drawer-panel" role="dialog" aria-modal="true" aria-labelledby="drawer-title">
    <button type="button" class="close" id="drawer-close" aria-label="Close">\xD7</button>
    <div id="drawer-body"></div>
  </div>
</div>

<footer class="wrap foot">Read-only view of the evidence engine. Stored in the EU. Visible to named readers only.</footer>
</body>
</html>
`,
    "sha256": "13674c77f1d8362c832c6899ccca10af14516e1fc73a9c43e51d5a573f10d168"
  },
  "app.css": {
    "type": "text/css; charset=utf-8",
    "body": ':root {\n  --navy: #0a1226;\n  --navy-2: #16213d;\n  --gold: #c89244;\n  --gold-soft: #f3e3c6;\n  --parchment: #efe7d4;\n  --paper: #faf7f0;\n  --card: #ffffff;\n  --ink: #1d2233;\n  --muted: #5f6475;\n  --line: #ddd4bf;\n  --ok: #2f7d4f;\n  --ok-soft: #e1f1e7;\n  --warn: #9a6512;\n  --warn-soft: #f8ecd4;\n  --bad: #a3392f;\n  --bad-soft: #f6e0dd;\n  --off: #6b6f7c;\n  --off-soft: #eceae4;\n  --bar: #c89244;\n  --serif: "EB Garamond", Garamond, "Iowan Old Style", Georgia, serif;\n  --sans: "Hanken Grotesk", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;\n  color-scheme: light;\n}\n@media (prefers-color-scheme: dark) {\n  :root {\n    --paper: #0d1324;\n    --card: #141c33;\n    --ink: #e9e4d8;\n    --muted: #a3a8b8;\n    --line: #2a3452;\n    --ok: #6cc391; --ok-soft: #173a29;\n    --warn: #e2b062; --warn-soft: #3d2f15;\n    --bad: #ec8b80; --bad-soft: #43201c;\n    --off: #a3a8b8; --off-soft: #232b44;\n    --gold-soft: #3a2f1b;\n    color-scheme: dark;\n  }\n}\n* { box-sizing: border-box; }\nhtml { -webkit-text-size-adjust: 100%; }\nbody { margin: 0; background: var(--paper); color: var(--ink); font: 15px/1.5 var(--sans); }\n.wrap { max-width: 1180px; margin: 0 auto; padding: 0 16px; }\na { color: inherit; }\nh2 { font: 600 1.15rem/1.3 var(--serif); margin: 0 0 4px; letter-spacing: .01em; }\n.mt { margin-top: 20px; }\n.note { color: var(--muted); font-size: .86rem; margin: 0 0 12px; }\n\n.top { background: var(--navy); color: var(--parchment); position: sticky; top: 0; z-index: 5; }\n.top-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding-top: 14px; padding-bottom: 10px; }\n.brand { display: flex; align-items: center; gap: 12px; min-width: 0; }\n.mark { font: 600 .8rem/1 var(--serif); letter-spacing: .18em; border: 1px solid var(--gold); color: var(--gold); padding: 7px 6px 6px 8px; }\n.brand-name { font: 600 1.25rem/1.1 var(--serif); letter-spacing: .02em; }\n.brand-sub { font-size: .8rem; color: #c9c2ae; }\n.who { font-size: .8rem; color: #c9c2ae; text-align: right; overflow-wrap: anywhere; }\n.tabs { display: flex; gap: 2px; overflow-x: auto; scrollbar-width: none; }\n.tabs a { text-decoration: none; padding: 10px 14px 11px; font-size: .92rem; color: #c9c2ae; border-bottom: 3px solid transparent; white-space: nowrap; }\n.tabs a:hover { color: var(--parchment); }\n.tabs a[aria-current="page"] { color: #fff; border-bottom-color: var(--gold); }\n\nmain.wrap { padding-top: 20px; padding-bottom: 24px; }\n.card { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 16px; margin-bottom: 16px; min-width: 0; }\n.grid2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }\n.grid2 > .card { margin-bottom: 0; }\n.grid2 + .card { margin-top: 16px; }\n\n.tiles { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin-bottom: 16px; }\n.tile { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; min-width: 0; }\n.tile .k { font-size: .78rem; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }\n.tile .v { font: 600 1.7rem/1.2 var(--serif); margin-top: 2px; font-variant-numeric: tabular-nums; }\n.tile .s { font-size: .82rem; color: var(--muted); }\n.tile.accent { border-top: 3px solid var(--gold); }\n\n.toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 12px; }\n.chips { display: flex; flex-wrap: wrap; gap: 6px; }\n.chips button { font: inherit; font-size: .86rem; border: 1px solid var(--line); background: var(--card); color: var(--ink); border-radius: 999px; padding: 5px 12px; cursor: pointer; min-height: 32px; }\n.chips button[aria-pressed="true"] { background: var(--navy); color: var(--parchment); border-color: var(--navy); }\n@media (prefers-color-scheme: dark) { .chips button[aria-pressed="true"] { background: var(--gold); color: #1a1408; border-color: var(--gold); } }\ninput[type="search"], select { font: inherit; font-size: .9rem; color: var(--ink); background: var(--card); border: 1px solid var(--line); border-radius: 6px; padding: 6px 10px; min-height: 36px; max-width: 100%; }\ninput[type="search"] { flex: 1 1 220px; }\n.filters select { flex: 0 1 200px; }\n:focus-visible { outline: 2px solid var(--gold); outline-offset: 2px; }\n\n.table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 8px; background: var(--card); }\n.card .table-wrap { border: 0; border-radius: 0; margin: 0 -4px; }\ntable { border-collapse: collapse; width: 100%; font-size: .88rem; }\nth, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }\nth { font-weight: 600; color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .05em; white-space: nowrap; }\ntbody tr:last-child td { border-bottom: 0; }\n.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }\ntd .host { color: var(--muted); font-size: .8rem; overflow-wrap: anywhere; }\ntd .reason { color: var(--muted); font-size: .8rem; }\ntd.name { min-width: 200px; }\n\n.pill { display: inline-block; font-size: .76rem; font-weight: 600; padding: 2px 8px; border-radius: 999px; white-space: nowrap; }\n.pill.ok { background: var(--ok-soft); color: var(--ok); }\n.pill.warn { background: var(--warn-soft); color: var(--warn); }\n.pill.bad { background: var(--bad-soft); color: var(--bad); }\n.pill.off { background: var(--off-soft); color: var(--off); }\n.pill.gold { background: var(--gold-soft); color: var(--warn); }\n\n.bars { list-style: none; margin: 0; padding: 0; }\n.bars li { display: grid; grid-template-columns: minmax(110px, 38%) 1fr auto; gap: 10px; align-items: center; padding: 4px 0; font-size: .88rem; }\n.bars .label { overflow-wrap: anywhere; }\n.bars .track { height: 10px; background: var(--off-soft); border-radius: 5px; overflow: hidden; }\n.bars .fill { height: 100%; background: var(--bar); border-radius: 5px; min-width: 2px; }\n.bars .fill.ok { background: var(--ok); }\n.bars .fill.bad { background: var(--bad); }\n.bars .fill.off { background: var(--off); }\n.bars .n { font-variant-numeric: tabular-nums; color: var(--muted); min-width: 3ch; text-align: right; }\n.region { margin-bottom: 14px; }\n.region h3 { font: 600 .82rem/1.3 var(--sans); text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 10px 0 4px; }\n.zero { color: var(--muted); font-size: .84rem; }\n\n.items { list-style: none; margin: 0; padding: 0; }\n.items li { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; margin-bottom: 10px; }\n.items .h { font: 600 1.05rem/1.35 var(--serif); }\n.items .h a { text-decoration: none; }\n.items .h a:hover { text-decoration: underline; }\n.items .meta { display: flex; flex-wrap: wrap; gap: 6px 12px; align-items: center; font-size: .8rem; color: var(--muted); margin-top: 6px; }\n.items .sum { font-size: .88rem; margin: 6px 0 0; color: var(--ink); opacity: .85; overflow-wrap: anywhere; }\n.linkbtn { font: inherit; font-size: .8rem; color: var(--warn); background: none; border: 0; padding: 0; cursor: pointer; text-decoration: underline; }\n\n.drawer { position: fixed; inset: 0; background: rgba(10, 18, 38, .55); z-index: 10; display: flex; justify-content: flex-end; }\n.drawer[hidden] { display: none; }\n.drawer-panel { background: var(--paper); width: min(560px, 100%); height: 100%; overflow-y: auto; padding: 20px 18px 30px; position: relative; }\n.drawer-panel h2 { padding-right: 36px; }\n.close { position: absolute; top: 10px; right: 10px; font-size: 1.6rem; line-height: 1; background: none; border: 0; color: var(--ink); cursor: pointer; width: 40px; height: 40px; }\ndl.kv { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; font-size: .86rem; margin: 10px 0; }\ndl.kv dt { color: var(--muted); }\ndl.kv dd { margin: 0; overflow-wrap: anywhere; }\n.drawer-panel ul { padding-left: 18px; font-size: .86rem; }\n.drawer-panel h3 { font: 600 .82rem/1.3 var(--sans); text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 16px 0 6px; }\n\n.status { color: var(--muted); font-size: .86rem; min-height: 1.2em; }\n.status.err { color: var(--bad); }\n.foot { color: var(--muted); font-size: .78rem; padding-top: 6px; padding-bottom: 28px; }\n\n@media (max-width: 900px) {\n  .tiles { grid-template-columns: repeat(2, minmax(0, 1fr)); }\n  .grid2 { grid-template-columns: minmax(0, 1fr); }\n  .grid2 > .card { margin-bottom: 0; }\n}\n@media (max-width: 520px) {\n  .who { display: none; }\n  .tile .v { font-size: 1.45rem; }\n  .bars li { grid-template-columns: minmax(90px, 42%) 1fr auto; }\n}\n',
    "sha256": "b1395d33267e4fb07d87f4e10917ae9e278b42e7dab4dd00128a4182eb0f2803"
  },
  "app.js": {
    "type": "text/javascript; charset=utf-8",
    "body": '// Evidence Engine dashboard. Read-only: every request is a GET to this engine\'s own API.\n// All text from feeds is untrusted, so it is only ever set with textContent, and only\n// http(s) links are made clickable.\n"use strict";\n\nconst TZ = "Europe/Malta";\nconst fmtDateTime = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });\nconst fmtDate = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, day: "numeric", month: "short", year: "numeric" });\nconst fmtNum = new Intl.NumberFormat("en-GB");\n\nconst CLASS_LABEL = {\n  "ok": "ok",\n  "not-modified": "not modified",\n  "ok-undated-only": "articles, but no dates",\n  "ok-empty": "empty feed",\n  "empty-body": "empty response",\n  "unparseable": "not a feed",\n  "blocked": "refused by publisher",\n  "rate-limited": "too many requests",\n  "http-error": "server error",\n  "timeout": "timed out",\n  "network-error": "network error",\n  "too-large": "too large",\n  "redirect-offsite": "redirected elsewhere",\n  "internal-error": "engine error",\n  "not-yet-checked": "not yet checked",\n};\nconst HEALTHY = new Set(["ok", "not-modified"]);\n\nconst state = { registry: null, channelNames: new Map(), coverage: null, health: null, feedFilter: "all", covHours: 24 };\n\n// ---------- small helpers ----------\nfunction el(tag, attrs = {}, ...children) {\n  const node = document.createElement(tag);\n  for (const [k, v] of Object.entries(attrs)) {\n    if (v === null || v === undefined || v === false) continue;\n    if (k === "class") node.className = v;\n    else if (k === "text") node.textContent = v;\n    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);\n    else node.setAttribute(k, v === true ? "" : String(v));\n  }\n  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) node.append(c instanceof Node ? c : document.createTextNode(String(c)));\n  return node;\n}\nconst $ = (sel) => document.querySelector(sel);\nconst n = (v) => fmtNum.format(v || 0);\nconst when = (iso) => (iso ? fmtDateTime.format(new Date(iso)) : "\u2014");\nconst day = (iso) => (iso ? fmtDate.format(new Date(iso)) : "\u2014");\nconst hours = (min) => (min == null ? "\u2014" : min % 60 === 0 ? `${min / 60} h` : `${min} min`);\nfunction safeUrl(u) {\n  try { const x = new URL(u); return x.protocol === "https:" || x.protocol === "http:" ? x.href : null; } catch { return null; }\n}\nfunction host(u) { try { return new URL(u).hostname.replace(/^www\\./, ""); } catch { return ""; } }\nfunction relative(iso) {\n  if (!iso) return "\u2014";\n  const mins = Math.round((Date.parse(iso) - Date.now()) / 60000);\n  if (Math.abs(mins) < 60) return mins >= 0 ? `in ${mins} min` : `${-mins} min ago`;\n  const h = Math.round(mins / 60);\n  return h >= 0 ? `in ${h} h` : `${-h} h ago`;\n}\nfunction setStatus(text, isError = false) { const s = $("#status"); s.textContent = text; s.className = isError ? "status err" : "status"; }\n\nasync function api(path) {\n  const r = await fetch(path, { credentials: "same-origin", headers: { accept: "application/json" } });\n  if (!r.ok) {\n    let reason = `${r.status}`;\n    try { reason = (await r.json()).error || reason; } catch { /* not JSON */ }\n    throw new Error(r.status === 401 || r.status === 403 ? `Not signed in as a reader (${reason}). Reload to sign in again.` : `The engine answered ${reason}.`);\n  }\n  return r.json();\n}\n\nfunction bars(listEl, rows, { max, kind } = {}) {\n  listEl.replaceChildren();\n  const top = max ?? Math.max(1, ...rows.map((r) => r.value));\n  if (!rows.length) { listEl.append(el("li", { class: "zero", text: "Nothing yet." })); return; }\n  for (const r of rows) {\n    const pct = Math.max(0, Math.min(100, (r.value / top) * 100));\n    const fill = el("div", { class: `fill ${r.kind || kind || ""}` });\n    fill.style.width = `${pct}%`;\n    listEl.append(el("li", {}, el("span", { class: "label", text: r.label }), el("div", { class: "track" }, fill), el("span", { class: "n", text: n(r.value) })));\n  }\n}\n\n// ---------- shared data ----------\nasync function loadRegistry() {\n  if (state.registry) return state.registry;\n  state.registry = await api("/api/registry");\n  for (const c of state.registry.channels) state.channelNames.set(c.channel_id, c.name);\n  return state.registry;\n}\n\n// ---------- overview ----------\nasync function showOverview() {\n  const s = await api("/api/summary");\n  const f = s.feeds;\n  const tiles = $("#tiles");\n  tiles.replaceChildren(\n    tile("Articles stored", n(s.totals.items), `${n(s.totals.publishers)} publishers`, true),\n    tile("New in 24 hours", n(s.totals.items_24h), "first seen by the engine"),\n    tile("Feeds healthy now", `${n(f.healthy_now)} / ${n(f.enabled)}`, f.not_yet_checked ? `${n(f.not_yet_checked)} not yet checked` : "switched-on feeds"),\n    tile("Feeds failing now", n(f.failing_now), `${n(f.switched_off)} switched off`),\n    tile("Next check", relative(s.next_check_at), when(s.next_check_at)),\n  );\n  if (s.first_run_at) {\n    const d = Math.floor((Date.now() - Date.parse(s.first_run_at)) / 86_400_000) + 1;\n    $("#trial-line").textContent = `Shadow trial \xB7 day ${Math.min(d, 99)} of 14 \xB7 since ${day(s.first_run_at)}`;\n  }\n  const body = $("#runs-table tbody");\n  body.replaceChildren(...s.runs.map((r) => el("tr", {},\n    el("td", { text: when(r.started_at) }),\n    el("td", { class: "num", text: n(r.reported) }),\n    el("td", { class: "num" }, `${n(r.healthy)} `, el("span", { class: "host", text: r.reported ? `(${Math.round((r.healthy / r.reported) * 100)}%)` : "" })),\n    el("td", { class: "num", text: n(r.items_new) }),\n  )));\n  if (!s.runs.length) body.append(el("tr", {}, el("td", { colspan: 4, class: "zero", text: "No runs yet." })));\n  const byClass = Object.entries(f.by_last_result).sort((a, b) => b[1] - a[1]);\n  bars($("#class-bars"), byClass.map(([k, v]) => ({ label: CLASS_LABEL[k] || k, value: v, kind: HEALTHY.has(k) ? "ok" : k === "not-yet-checked" ? "off" : "bad" })));\n  bars($("#date-bars"), [\n    { label: "dated by the publisher", value: s.totals.dated, kind: "ok" },\n    { label: "undated (kept that way)", value: s.totals.undated, kind: "off" },\n    { label: "dated in the future (set aside)", value: s.totals.future, kind: "bad" },\n  ], { max: Math.max(1, s.totals.items) });\n}\nfunction tile(k, v, sub, accent = false) {\n  return el("div", { class: accent ? "tile accent" : "tile" }, el("div", { class: "k", text: k }), el("div", { class: "v", text: v }), el("div", { class: "s", text: sub }));\n}\n\n// ---------- feeds ----------\nfunction feedState(e) {\n  if (!e.enabled) return "off";\n  if (!e.last_class) return "waiting";\n  return HEALTHY.has(e.last_class) ? "healthy" : "failing";\n}\nfunction feedPill(e) {\n  const s = feedState(e);\n  if (s === "off") return el("span", { class: "pill off", text: e.registry_status === "replaced" ? "Moved" : "Switched off" });\n  if (s === "waiting") return el("span", { class: "pill warn", text: "Waiting" });\n  return el("span", { class: s === "healthy" ? "pill ok" : "pill bad", text: s === "healthy" ? "Healthy" : "Failing" });\n}\nasync function showFeeds() {\n  state.health = state.health || await api("/api/health?days=14");\n  renderFeeds();\n}\nfunction renderFeeds() {\n  const q = $("#feed-search").value.trim().toLowerCase();\n  const rows = state.health.endpoints.filter((e) => {\n    if (state.feedFilter !== "all" && feedState(e) !== state.feedFilter) return false;\n    if (!q) return true;\n    return `${e.names || ""} ${e.url}`.toLowerCase().includes(q);\n  });\n  const order = { failing: 0, waiting: 1, healthy: 2, off: 3 };\n  rows.sort((a, b) => order[feedState(a)] - order[feedState(b)] || String(a.names || a.url).localeCompare(String(b.names || b.url)));\n  $("#feed-count").textContent = `${n(rows.length)} of ${n(state.health.endpoints.length)} feed addresses.`;\n  const body = $("#feeds-table tbody");\n  body.replaceChildren(...rows.map((e) => {\n    const href = safeUrl(e.url);\n    const nameCell = el("td", { class: "name" },\n      el("div", { text: e.names || host(e.url) }),\n      el("div", { class: "host" }, href && e.adapter !== "aggregator" ? el("a", { href, target: "_blank", rel: "noopener noreferrer", text: host(e.url) + new URL(e.url).pathname }) : e.adapter === "aggregator" ? "GDELT search" : e.url),\n      !e.enabled && e.registry_reason ? el("div", { class: "reason", text: e.registry_reason }) : null,\n      !e.enabled && e.registry_status === "replaced" ? el("div", { class: "reason", text: "Replaced by a new address (listed separately)." }) : null);\n    return el("tr", {},\n      nameCell,\n      el("td", {}, feedPill(e)),\n      el("td", { text: e.last_class ? (CLASS_LABEL[e.last_class] || e.last_class) : "\u2014" }),\n      el("td", { text: when(e.last_success_at) }),\n      el("td", { class: "num", text: e.enabled ? hours(e.interval_minutes) : "\u2014" }),\n      el("td", { class: "num", text: e.polls ? `${n(e.healthy_polls)} / ${n(e.polls)}` : "\u2014" }),\n      el("td", { class: "num", text: e.items_new ? n(e.items_new) : "\u2014" }),\n      el("td", { class: "num", text: e.assessed ? n(e.gaps) : "\u2014", title: e.assessed ? `${n(e.gaps)} suspected gaps in ${n(e.assessed)} assessed checks` : "Needs two healthy checks to assess" }),\n    );\n  }));\n}\n\n// ---------- coverage ----------\nasync function loadCoverage(hoursWindow) {\n  state.coverage = await api(`/api/coverage?hours=${hoursWindow}`);\n  return state.coverage;\n}\nasync function showCoverage() {\n  const c = await loadCoverage(state.covHours);\n  const box = $("#cov-countries");\n  box.replaceChildren();\n  const regions = new Map();\n  for (const row of c.countries) { if (!regions.has(row.region)) regions.set(row.region, []); regions.get(row.region).push(row); }\n  const max = Math.max(1, ...c.countries.map((r) => r.items));\n  for (const [region, rows] of regions) {\n    rows.sort((a, b) => b.items - a.items || a.name.localeCompare(b.name));\n    const list = el("ul", { class: "bars" });\n    box.append(el("div", { class: "region" }, el("h3", { text: region }), list));\n    bars(list, rows.map((r) => ({ label: r.low_confidence_only ? `${r.name} (+${r.low_confidence_only} weak)` : r.name, value: r.items, kind: r.items ? "" : "off" })), { max });\n  }\n  bars($("#cov-topics"), Object.entries(c.categories).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ label: k, value: v })));\n  bars($("#cov-regions"), Object.entries(c.regions).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ label: k, value: v })));\n}\n\n// ---------- articles ----------\nlet filtersReady = false;\nasync function prepareFilters() {\n  if (filtersReady) return;\n  const [reg, cov] = await Promise.all([loadRegistry(), state.coverage ? state.coverage : loadCoverage(168)]);\n  const form = $("#item-filters");\n  for (const c of [...cov.countries].sort((a, b) => a.name.localeCompare(b.name))) form.country.append(el("option", { value: c.country, text: c.name }));\n  const cats = ["Elections & Democracy", "Security & Defense", "Foreign Affairs & Diplomacy", "Energy & Climate", "Economy & Trade", "Migration & Borders", "Society & Rights", "Sports", ...Object.keys(cov.categories)];\n  for (const k of [...new Set(cats)].sort()) form.category.append(el("option", { value: k, text: k }));\n  const collected = reg.channels.filter((c) => c.collection !== "manual-not-collected").sort((a, b) => a.name.localeCompare(b.name));\n  for (const c of collected) form.channel.append(el("option", { value: c.channel_id, text: c.name }));\n  let timer;\n  form.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(showArticles, 250); });\n  form.addEventListener("submit", (e) => { e.preventDefault(); showArticles(); });\n  filtersReady = true;\n}\nfunction dateLine(it) {\n  if (it.date_status === "dated") return `${when(it.published_at)}${it.published_precision === "day" ? " (date only)" : it.published_precision === "no-zone" ? " (no time zone given)" : ""}`;\n  if (it.date_status === "future") return "dated in the future, set aside";\n  return it.via_aggregator ? `undated \xB7 seen by GDELT ${when(it.aggregator_seen_at)}` : "undated";\n}\nasync function showArticles() {\n  await prepareFilters();\n  const form = $("#item-filters");\n  const p = new URLSearchParams({ limit: "200" });\n  for (const k of ["q", "country", "category", "channel"]) if (form[k].value) p.set(k, form[k].value);\n  if (form.since.value) p.set("since", new Date(Date.now() - Number(form.since.value) * 3_600_000).toISOString());\n  const { items } = await api(`/api/items?${p}`);\n  $("#item-count").textContent = items.length === 200 ? "Showing the 200 most recently collected. Narrow the filters to see others." : `${n(items.length)} articles.`;\n  const list = $("#items");\n  list.replaceChildren(...items.map((it) => {\n    const href = safeUrl(it.canonical_url);\n    const secondary = it.channel_ids.includes("malta:cde-malta24");\n    return el("li", {},\n      el("div", { class: "h" }, href ? el("a", { href, target: "_blank", rel: "noopener noreferrer", text: it.headline }) : it.headline),\n      el("div", { class: "meta" },\n        el("span", { text: it.publisher_domain }),\n        el("span", { text: dateLine(it) }),\n        secondary ? el("span", { class: "pill gold", text: "Secondary \xB7 CDE briefing" }) : null,\n        it.via_aggregator ? el("span", { class: "pill off", text: "via GDELT" }) : null,\n        it.language ? el("span", { text: it.language }) : null,\n        el("button", { type: "button", class: "linkbtn", onclick: () => openItem(it.item_id).catch((err) => setStatus(err.message, true)), text: "Details" })),\n      it.summary ? el("p", { class: "sum", text: it.summary.length > 280 ? `${it.summary.slice(0, 280)}\u2026` : it.summary }) : null);\n  }));\n  if (!items.length) list.append(el("li", { class: "zero", text: "No articles match these filters." }));\n}\nasync function openItem(id) {\n  const d = await api(`/api/items/${encodeURIComponent(id)}`);\n  const it = d.item;\n  const href = safeUrl(it.canonical_url);\n  const body = $("#drawer-body");\n  body.replaceChildren(\n    el("h2", { id: "drawer-title", text: it.headline }),\n    href ? el("p", {}, el("a", { href, target: "_blank", rel: "noopener noreferrer", text: "Open the original \u2197" })) : null,\n    el("dl", { class: "kv" },\n      el("dt", { text: "Publisher" }), el("dd", { text: it.publisher_domain }),\n      el("dt", { text: "Date" }), el("dd", { text: dateLine(it) }),\n      el("dt", { text: "As written" }), el("dd", { text: it.published_raw || "\u2014" }),\n      el("dt", { text: "First seen" }), el("dd", { text: when(it.first_seen_at) }),\n      el("dt", { text: "Language" }), el("dd", { text: `${it.language || "\u2014"} (${it.language_method})` }),\n      el("dt", { text: "Text kept" }), el("dd", { text: it.summary_policy === "feed-text" ? "the feed\'s own text" : it.summary_policy === "omitted-by-rule" ? "none, by the publisher\'s rules" : "none" })),\n    el("h3", { text: "Sources it appeared in" }),\n    el("ul", {}, d.channels.map((c) => el("li", { text: `${state.channelNames.get(c.channel_id) || c.channel_id} \xB7 ${when(c.first_seen_at)}` }))),\n    el("h3", { text: "Routed to" }),\n    d.routes.length ? el("ul", {}, d.routes.map((r) => el("li", { text: `${r.kind}: ${r.value}${r.confidence === "low" ? " (weak)" : ""} \u2014 ${r.matched ? `matched \u201C${r.matched}\u201D${r.field ? ` in the ${r.field}` : ""}` : `by ${r.method}`}` }))) : el("p", { class: "zero", text: "Not routed to any country or topic." }),\n    el("h3", { text: "Same story elsewhere" }),\n    d.same_story.length ? el("ul", {}, d.same_story.map((s) => el("li", { text: `${s.publisher_domain}: ${s.headline}` }))) : el("p", { class: "zero", text: "No matching story from another publisher within 72 hours." }),\n    el("h3", { text: "Sightings" }),\n    el("p", { class: "note", text: `Seen ${d.observations.length === 1 ? "once" : `${n(d.observations.length)} times`}, last ${when(d.observations.at(-1)?.observed_at)}.` }),\n  );\n  $("#drawer").hidden = false;\n  $("#drawer-close").focus();\n}\n\n// ---------- routing ----------\nconst VIEWS = { overview: showOverview, feeds: showFeeds, coverage: showCoverage, articles: showArticles };\nasync function route() {\n  const name = VIEWS[location.hash.slice(1)] ? location.hash.slice(1) : "overview";\n  for (const v of Object.keys(VIEWS)) document.getElementById(`view-${v}`).hidden = v !== name;\n  for (const a of document.querySelectorAll(".tabs a")) {\n    if (a.dataset.view === name) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");\n  }\n  setStatus("Loading\u2026");\n  try { await loadRegistry(); await VIEWS[name](); setStatus(`Updated ${when(new Date().toISOString())}.`); }\n  catch (e) { setStatus(e.message || String(e), true); }\n}\n\ndocument.addEventListener("DOMContentLoaded", () => {\n  api("/api/me").then((m) => { $("#who").textContent = m.email; }).catch(() => {});\n  $("#feed-chips").addEventListener("click", (e) => {\n    const b = e.target.closest("button"); if (!b) return;\n    state.feedFilter = b.dataset.filter;\n    for (const x of $("#feed-chips").querySelectorAll("button")) x.setAttribute("aria-pressed", String(x === b));\n    renderFeeds();\n  });\n  $("#feed-search").addEventListener("input", () => state.health && renderFeeds());\n  $("#cov-chips").addEventListener("click", (e) => {\n    const b = e.target.closest("button"); if (!b) return;\n    state.covHours = Number(b.dataset.hours);\n    for (const x of $("#cov-chips").querySelectorAll("button")) x.setAttribute("aria-pressed", String(x === b));\n    showCoverage().catch((err) => setStatus(err.message, true));\n  });\n  const close = () => { $("#drawer").hidden = true; };\n  $("#drawer-close").addEventListener("click", close);\n  $("#drawer").addEventListener("click", (e) => { if (e.target.id === "drawer") close(); });\n  document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });\n  window.addEventListener("hashchange", route);\n  route();\n});\n',
    "sha256": "50ea696dbada3f19fc4cca66ee76d3e4c391d0bba8721c3d8d9deaa20fe1f7ea"
  }
};

// src/index.js
var LEASE_MINUTES = 30;
var json = /* @__PURE__ */ __name((status, body) => new Response(JSON.stringify(body, null, 2), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store, private", "x-content-type-options": "nosniff" }
}), "json");
async function startRun(env, { nowMs = Date.now(), trigger = "cron", fetchImpl = fetch } = {}) {
  const now = new Date(nowMs).toISOString();
  const due = await dueEndpointIds(env.EVIDENCE_DB, now);
  const runId = `run_${now.replace(/[-:.TZ]/g, "").slice(0, 14)}_${crypto.randomUUID().slice(0, 8)}`;
  await createRun(env.EVIDENCE_DB, { run_id: runId, started_at: now, trigger, endpoints_due: due.length, collector: COLLECTOR_VERSION });
  await leaseEndpoints(env.EVIDENCE_DB, due, new Date(nowMs + LEASE_MINUTES * 6e4).toISOString());
  if (env.COLLECT_QUEUE) {
    for (let i = 0; i < due.length; i += QUEUE_BATCH) {
      await env.COLLECT_QUEUE.sendBatch(due.slice(i, i + QUEUE_BATCH).map((endpoint_id) => ({ body: { run_id: runId, endpoint_id, scheduled_ms: nowMs } })));
    }
    return { run_id: runId, queued: due.length };
  }
  const results = [];
  for (const endpointId of due) {
    results.push(await collectEndpoint(endpointId, { db: env.EVIDENCE_DB, bucket: env.SNAPSHOTS, fetchImpl, userAgent: env.COLLECTOR_USER_AGENT, nowMs, scheduledMs: nowMs, runId }));
  }
  return { run_id: runId, collected: results.length, results };
}
__name(startRun, "startRun");
var UI_HEADERS = {
  "content-security-policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "cache-control": "no-store, private"
};
var UI_ROUTES = { "/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/app.css": "app.css" };
async function handleUi(request, env, deps = {}) {
  const file = UI_FILES[UI_ROUTES[new URL(request.url).pathname]];
  if (request.method !== "GET" && request.method !== "HEAD") return new Response("Read-only.", { status: 405, headers: UI_HEADERS });
  const access = await verifyAccess(request, env, deps);
  if (!access.ok) return new Response(`Not available (${access.reason}). Sign in through tpnintel.com with a reader account.`, { status: access.status, headers: { ...UI_HEADERS, "content-type": "text/plain; charset=utf-8" } });
  return new Response(request.method === "HEAD" ? null : file.body, { status: 200, headers: { ...UI_HEADERS, "content-type": file.type } });
}
__name(handleUi, "handleUi");
async function handleRequest(request, env, deps = {}) {
  const path = new URL(request.url).pathname;
  if (UI_ROUTES[path]) return handleUi(request, env, deps);
  return handleApi(request, env, deps);
}
__name(handleRequest, "handleRequest");
async function handleApi(request, env, deps = {}) {
  const url = new URL(request.url);
  if (!url.pathname.startsWith("/api/")) return json(404, { error: "not_found" });
  if (request.method !== "GET" && request.method !== "HEAD") return json(405, { error: "read_only" });
  const access = await verifyAccess(request, env, deps);
  if (!access.ok) return json(access.status, { error: access.reason });
  const db = env.EVIDENCE_DB;
  const p = url.searchParams;
  const clamp = /* @__PURE__ */ __name((v, lo, hi, dflt) => {
    const n = Math.trunc(Number(v));
    return Number.isFinite(n) && n >= lo ? Math.min(n, hi) : dflt;
  }, "clamp");
  if (url.pathname === "/api/me") return json(200, { email: access.email });
  if (url.pathname === "/api/summary") return json(200, await summaryReport(db));
  if (url.pathname === "/api/health") return json(200, await healthReport(db, { days: clamp(p.get("days"), 1, 90, 14) }));
  if (url.pathname === "/api/coverage") return json(200, await coverageReport(db, { hours: clamp(p.get("hours"), 1, 720, 24) }));
  if (url.pathname === "/api/items") {
    return json(200, { items: await listItems(db, { since: p.get("since"), until: p.get("until"), country: p.get("country"), category: p.get("category"), channel: p.get("channel"), q: p.get("q"), includeFuture: p.get("include_future") === "1", includeLowConfidence: p.get("include_low_confidence") === "1", limit: clamp(p.get("limit"), 1, 500, 100) }) });
  }
  const m = url.pathname.match(/^\/api\/items\/(it_[a-f0-9]{24})$/);
  if (m) {
    const item = await getItem(db, m[1]);
    return item ? json(200, item) : json(404, { error: "not_found" });
  }
  if (url.pathname === "/api/registry") {
    const { results } = await db.prepare("SELECT channel_id, name, register_id, rights, collection, id_origin, same_publisher_hint FROM channels ORDER BY channel_id").all();
    return json(200, { channels: results });
  }
  return json(404, { error: "not_found" });
}
__name(handleApi, "handleApi");
var index_default = {
  fetch: /* @__PURE__ */ __name((request, env) => handleRequest(request, env), "fetch"),
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(startRun(env, { nowMs: controller.scheduledTime, trigger: "cron" }).then((r) => {
      console.log(JSON.stringify({ event: "evidence_run_started", ...r, results: void 0 }));
    }));
  },
  async queue(batch, env) {
    for (const message of batch.messages) {
      const { run_id: runId, endpoint_id: endpointId, scheduled_ms: scheduledMs } = message.body;
      try {
        const result = await collectEndpoint(endpointId, { db: env.EVIDENCE_DB, bucket: env.SNAPSHOTS, fetchImpl: fetch, userAgent: env.COLLECTOR_USER_AGENT, runId, scheduledMs });
        console.log(JSON.stringify({ event: "endpoint_collected", run_id: runId, endpoint_id: endpointId, class: result.class, new: result.items_new, overlap: result.overlap }));
        message.ack();
      } catch (error) {
        console.error(JSON.stringify({ event: "endpoint_collect_error", run_id: runId, endpoint_id: endpointId, message: String(error?.message || error) }));
        message.retry({ delaySeconds: 300 });
      }
    }
  }
};
export {
  index_default as default,
  handleApi,
  handleRequest,
  handleUi,
  startRun
};
//# sourceMappingURL=index.js.map
