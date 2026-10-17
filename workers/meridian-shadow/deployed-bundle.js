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

// src/vendor/expanded-news.js
var DIRECT_SOURCE_LIMIT = 20;
var FEED_SOURCE_LIMIT = 20;
var GLOBAL_LIMIT = 12;
var COUNTRY_LIMIT = 18;
var CATEGORY_LIMIT = 3;
var NEWS_DESK_COUNTRIES = Object.freeze([
  { key: "austria", display_name: "Austria", region: "EU", aliases: ["austrian", "vienna"] },
  { key: "belgium", display_name: "Belgium", region: "EU", aliases: ["belgian"] },
  { key: "bulgaria", display_name: "Bulgaria", region: "EU", aliases: ["bulgarian", "sofia"] },
  { key: "croatia", display_name: "Croatia", region: "EU", aliases: ["croatian", "zagreb"] },
  { key: "cyprus", display_name: "Cyprus", region: "EU", aliases: ["cypriot", "nicosia"] },
  { key: "czech-republic", display_name: "Czech Republic", region: "EU", aliases: ["czechia", "czech", "prague"] },
  { key: "denmark", display_name: "Denmark", region: "EU", aliases: ["danish", "copenhagen"] },
  { key: "estonia", display_name: "Estonia", region: "EU", aliases: ["estonian", "tallinn"] },
  { key: "finland", display_name: "Finland", region: "EU", aliases: ["finnish", "helsinki"] },
  { key: "france", display_name: "France", region: "EU", aliases: ["french", "paris"] },
  { key: "germany", display_name: "Germany", region: "EU", aliases: ["german", "berlin"] },
  { key: "greece", display_name: "Greece", region: "EU", aliases: ["greek", "athens"] },
  { key: "hungary", display_name: "Hungary", region: "EU", aliases: ["hungarian", "budapest"] },
  { key: "ireland", display_name: "Ireland", region: "EU", aliases: ["irish", "dublin"] },
  { key: "italy", display_name: "Italy", region: "EU", aliases: ["italian", "rome"] },
  { key: "latvia", display_name: "Latvia", region: "EU", aliases: ["latvian", "riga"] },
  { key: "lithuania", display_name: "Lithuania", region: "EU", aliases: ["lithuanian", "vilnius"] },
  { key: "luxembourg", display_name: "Luxembourg", region: "EU", aliases: ["luxembourgish"] },
  { key: "malta", display_name: "Malta", region: "EU", aliases: ["maltese", "valletta"] },
  { key: "netherlands", display_name: "Netherlands", region: "EU", aliases: ["dutch", "the hague", "amsterdam"] },
  { key: "poland", display_name: "Poland", region: "EU", aliases: ["polish", "warsaw"] },
  { key: "portugal", display_name: "Portugal", region: "EU", aliases: ["portuguese", "lisbon"] },
  { key: "romania", display_name: "Romania", region: "EU", aliases: ["romanian", "bucharest"] },
  { key: "slovakia", display_name: "Slovakia", region: "EU", aliases: ["slovak", "bratislava"] },
  { key: "slovenia", display_name: "Slovenia", region: "EU", aliases: ["slovenian", "ljubljana"] },
  { key: "spain", display_name: "Spain", region: "EU", aliases: ["spanish", "madrid"] },
  { key: "sweden", display_name: "Sweden", region: "EU", aliases: ["swedish", "stockholm"] },
  { key: "united-kingdom", display_name: "United Kingdom", region: "UK", aliases: ["britain", "british", "u.k.", "uk", "london"] },
  { key: "united-states", display_name: "United States", region: "North America", aliases: ["united states of america", "american", "u.s.", "usa", "white house", "trump"] },
  { key: "china", display_name: "China", region: "Asia-Pacific", aliases: ["chinese", "beijing"] },
  { key: "japan", display_name: "Japan", region: "Asia-Pacific", aliases: ["japanese", "tokyo"] },
  { key: "australia", display_name: "Australia", region: "Asia-Pacific", aliases: ["australian", "canberra"] },
  { key: "switzerland", display_name: "Switzerland", region: "Wider Europe", aliases: ["swiss", "bern"] },
  { key: "libya", display_name: "Libya", region: "North Africa", aliases: ["libyan", "tripoli"] },
  { key: "israel", display_name: "Israel", region: "Middle East & Gulf", aliases: ["israeli", "jerusalem", "tel aviv"] },
  { key: "qatar", display_name: "Qatar", region: "Middle East & Gulf", aliases: ["qatari", "doha"] },
  { key: "uae", display_name: "United Arab Emirates (Dubai)", region: "Middle East & Gulf", aliases: ["united arab emirates", "uae", "emirati", "dubai", "abu dhabi"] },
  { key: "saudi-arabia", display_name: "Saudi Arabia", region: "Middle East & Gulf", aliases: ["saudi", "riyadh"] },
  { key: "norway", display_name: "Norway", region: "Wider Europe", aliases: ["norwegian", "oslo"] },
  { key: "iceland", display_name: "Iceland", region: "Wider Europe", aliases: ["icelandic", "reykjavik"] },
  { key: "ukraine", display_name: "Ukraine", region: "Balkans & Eastern Europe", aliases: ["ukrainian", "kyiv", "kiev", "zelensky", "zelenskyy"] },
  { key: "serbia", display_name: "Serbia", region: "Balkans & Eastern Europe", aliases: ["serbian", "belgrade"] },
  { key: "bosnia-and-herzegovina", display_name: "Bosnia and Herzegovina", region: "Balkans & Eastern Europe", aliases: ["bosnia", "bosnian", "sarajevo"] },
  { key: "albania", display_name: "Albania", region: "Balkans & Eastern Europe", aliases: ["albanian", "tirana"] },
  { key: "north-macedonia", display_name: "North Macedonia", region: "Balkans & Eastern Europe", aliases: ["macedonian", "skopje"] },
  { key: "montenegro", display_name: "Montenegro", region: "Balkans & Eastern Europe", aliases: ["montenegrin", "podgorica"] },
  { key: "kosovo", display_name: "Kosovo", region: "Balkans & Eastern Europe", aliases: ["kosovan", "kosovar", "pristina"] },
  { key: "moldova", display_name: "Moldova", region: "Balkans & Eastern Europe", aliases: ["moldovan", "chisinau", "chi\u0219in\u0103u"] },
  { key: "turkey", display_name: "Turkey", region: "Levant & Turkey", aliases: ["t\xFCrkiye", "turkiye", "turkish", "ankara", "istanbul", "erdogan", "erdo\u011Fan"] },
  { key: "lebanon", display_name: "Lebanon", region: "Levant & Turkey", aliases: ["lebanese", "beirut"] },
  { key: "syria", display_name: "Syria", region: "Levant & Turkey", aliases: ["syrian", "damascus"] },
  { key: "morocco", display_name: "Morocco", region: "North Africa", aliases: ["moroccan", "rabat"] },
  { key: "algeria", display_name: "Algeria", region: "North Africa", aliases: ["algerian", "algiers"] },
  { key: "tunisia", display_name: "Tunisia", region: "North Africa", aliases: ["tunisian", "tunis"] }
].map((country) => Object.freeze({ ...country, aliases: Object.freeze(country.aliases) })));
var NEWS_DESK_COUNTRY_BY_KEY = new Map(NEWS_DESK_COUNTRIES.map((country) => [country.key, country]));
var NEWSBOOK_ENGLISH_FEED = Object.freeze({
  name: "Newsbook English",
  url: "https://newsbook.com.mt/en/feed/",
  kind: "publisher_feed",
  sourcecountry: "Malta",
  scopeCountryKey: "malta",
  scopeCategories: Object.freeze(["Local"]),
  trustedDomains: Object.freeze(["newsbook.com.mt"]),
  articleLimit: FEED_SOURCE_LIMIT
});
var GLOBAL_FALLBACK_FEEDS = Object.freeze([
  Object.freeze({
    name: "UN News",
    url: "https://news.un.org/feed/subscribe/en/news/all/rss.xml",
    kind: "official_feed",
    sourcecountry: "United Nations",
    trustedDomains: Object.freeze(["news.un.org"]),
    articleLimit: FEED_SOURCE_LIMIT
  }),
  Object.freeze({
    name: "France 24 English",
    url: "https://www.france24.com/en/rss",
    kind: "publisher_feed",
    sourcecountry: "France",
    trustedDomains: Object.freeze(["france24.com"]),
    articleLimit: FEED_SOURCE_LIMIT
  }),
  Object.freeze({
    name: "Euronews World",
    url: "https://www.euronews.com/rss?format=mrss&level=theme&name=news",
    kind: "publisher_feed",
    sourcecountry: "Europe",
    trustedDomains: Object.freeze(["euronews.com"]),
    articleLimit: FEED_SOURCE_LIMIT
  }),
  Object.freeze({
    name: "Euronews My Europe",
    url: "https://www.euronews.com/rss?format=mrss&level=vertical&name=my-europe",
    kind: "publisher_feed",
    sourcecountry: "Europe",
    trustedDomains: Object.freeze(["euronews.com"]),
    articleLimit: FEED_SOURCE_LIMIT
  }),
  Object.freeze({ name: "BBC World", url: "https://feeds.bbci.co.uk/news/world/rss.xml", kind: "publisher_feed", sourcecountry: "United Kingdom", trustedDomains: Object.freeze(["bbc.com", "bbc.co.uk"]), articleLimit: FEED_SOURCE_LIMIT }),
  Object.freeze({ name: "Guardian World", url: "https://www.theguardian.com/world/rss", kind: "publisher_feed", sourcecountry: "United Kingdom", trustedDomains: Object.freeze(["theguardian.com"]), articleLimit: FEED_SOURCE_LIMIT })
]);
var DIRECT_SOURCE_PAGES = Object.freeze([
  Object.freeze({
    name: "MaltaToday",
    url: "https://www.maltatoday.com.mt/",
    alternateUrls: Object.freeze([
      "https://www.maltatoday.com.mt/index.php"
    ]),
    sourcecountry: "Malta",
    scopeCountryKey: "malta",
    scopePathPrefixes: Object.freeze(["/news/national/"]),
    timeZone: "Europe/Malta",
    articleLimit: DIRECT_SOURCE_LIMIT
  })
]);
var CATEGORY_RULES = [
  ["Elections & Democracy", /\b(election|electoral|ballot|polling|referendum|vote|voters|democra(?:cy|tic))\b/i],
  ["Security & Defense", /\b(security|defen[cs]e|military|armed forces|war|conflicts?|missile|attack|terror|nato|ceasefire)\b/i],
  ["Foreign Affairs & Diplomacy", /\b(diploma(?:cy|tic)|foreign affairs|summit|bilateral|ambassador|sanction|treaty|geopolitic|united nations)\b/i],
  ["Energy & Climate", /\b(energy|climate|emission|renewable|oil|gas|electricity|solar|wind power|carbon|environment)\b/i],
  ["Economy & Trade", /\b(econom(?:y|ic|ics|ical|ically)?|trade|tariff|market|inflation|gdp|finance|bank|investment|business|employment|tax|budget|credit[- ]?rating|sovereign[- ]?rating|dbrs)\b/i],
  ["Migration & Borders", /\b(migration|migrant|immigration|asylum|refugee|border|deport|visa)\b/i],
  ["Society & Rights", /\b(rights?|society|social|health|education|welfare|equality|discrimination|protest|justice|court)\b/i],
  ["Sports", /\b(sports?|football|soccer|olympics?|championship|tournament|league|tennis|cycling|cricket|rugby|basketball|baseball|formula\s*1|grand prix|world cup)\b/i]
];
var PUBLIC_AFFAIRS_PATTERN = /\b(?:elections?|electoral|ballot|polling|referend(?:um|a)|votes?|voters?|democra(?:cy|tic)|governance|government|institutions?|reports?|parliament|meps?|commission|council|president|prime minister|minister|cabinet|law|legal|legislation|policy|regulat(?:ion|or|ory)|court|judge|justice|police|prosecutor|corruption|protest|strikes?|summit|sanctions?|diploma(?:cy|tic)|foreign affairs|bilateral|ambassador|geopolitic(?:al|s)?|treaty|ceasefire|war|conflicts?|attacks?|military|missiles?|security|defen[cs]e|nato|terror|hostages?|occupation|united nations|un|european (?:commission|council|union|parliament)|eu|ecb|central bank|econom(?:y|ic|ics|ical|ically)?|competitiveness|trade|tariffs?|markets?|inflation|gdp|finance|banks?|investment|business|employment|labou?r|jobs?|tax|budget|credit[- ]?rating|sovereign[- ]?rating|dbrs|energy|climate|emissions?|renewable|oil|gas|electricity|solar|wind power|carbon|environment|migration|migrants?|immigration|asylum|refugees?|borders?|deport|visa|rights?|society|social|health|education|welfare|equality|discrimination|infrastructure|transport|housing|artificial intelligence|ai|technology|digital|data|cyber)\b/i;
function classifyHeadline(headline) {
  if (/\bconflicts?[-\s]+of[-\s]+interests?\b/i.test(headline || "")) {
    return "Governance & Institutions";
  }
  const match = CATEGORY_RULES.find(([, pattern]) => pattern.test(headline || ""));
  return match ? match[0] : "Governance & Institutions";
}
__name(classifyHeadline, "classifyHeadline");
function normalizeHeadlineKey(headline) {
  return String(headline || "").split("|")[0].normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/\b(live|update|breaking|exclusive)\b/g, " ").replace(/[^a-z0-9]+/g, " ").trim().split(" ").slice(0, 24).join(" ");
}
__name(normalizeHeadlineKey, "normalizeHeadlineKey");
function normaliseText(value) {
  return String(value || "").normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
}
__name(normaliseText, "normaliseText");
function containsAlias(headline, alias) {
  const escaped = alias.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^a-z0-9])${escaped}([^a-z0-9]|$)`, "i").test(headline);
}
__name(containsAlias, "containsAlias");
function entityAliases(entity) {
  const governedCountry = NEWS_DESK_COUNTRY_BY_KEY.get(entity.key);
  if (!governedCountry) return [normaliseText(entity.display_name)];
  return [governedCountry.display_name, ...governedCountry.aliases];
}
__name(entityAliases, "entityAliases");
function reconcileNewsDeskCountries(entities) {
  const current = Array.isArray(entities) ? entities : [];
  const existingKeys = new Set(current.map((entity) => entity?.key).filter(Boolean));
  const missing = NEWS_DESK_COUNTRIES.filter((country) => !existingKeys.has(country.key)).map((country) => ({
    key: country.key,
    display_name: country.display_name,
    region: country.region,
    stories: []
  }));
  return [...current, ...missing];
}
__name(reconcileNewsDeskCountries, "reconcileNewsDeskCountries");
function articleDomain(article) {
  try {
    return new URL(article.url).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return "";
  }
}
__name(articleDomain, "articleDomain");
function parseSeenDate(value) {
  const raw = String(value || "");
  const compact = raw.match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/);
  if (compact) {
    const canonical = `${compact[1]}-${compact[2]}-${compact[3]}T${compact[4]}:${compact[5]}:${compact[6]}Z`;
    const parsed2 = new Date(canonical);
    if (Number.isNaN(parsed2.getTime()) || parsed2.getUTCFullYear() !== Number(compact[1]) || parsed2.getUTCMonth() !== Number(compact[2]) - 1 || parsed2.getUTCDate() !== Number(compact[3]) || parsed2.getUTCHours() !== Number(compact[4]) || parsed2.getUTCMinutes() !== Number(compact[5]) || parsed2.getUTCSeconds() !== Number(compact[6])) return null;
    return canonical;
  }
  const parsed = new Date(raw);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}
__name(parseSeenDate, "parseSeenDate");
function isRelevantMonitoringArticle(article) {
  const headline = String(article?.title || "").trim();
  if (!headline) return false;
  if (/^(?:spotlight|top stories?|latest news(?: bulletin)?(?:\s*\|.*)?|news bulletin|live)$/i.test(headline)) return false;
  if (/\b(?:box office|celebrity|recipe)\b/i.test(headline)) return false;
  return PUBLIC_AFFAIRS_PATTERN.test(headline) || classifyHeadline(headline) === "Sports";
}
__name(isRelevantMonitoringArticle, "isRelevantMonitoringArticle");
function selectCategoryBalancedStories(candidates, limit, categoryLimit = CATEGORY_LIMIT) {
  const selected = [];
  const counts = /* @__PURE__ */ new Map();
  for (const item of candidates) {
    const category = item.story.category;
    if (!counts.has(category) && selected.length < limit) {
      selected.push(item);
      counts.set(category, 1);
    }
  }
  for (const item of candidates) {
    const category = item.story.category;
    if (selected.length >= limit) break;
    if (!selected.includes(item) && (counts.get(category) || 0) < categoryLimit) {
      selected.push(item);
      counts.set(category, (counts.get(category) || 0) + 1);
    }
  }
  return candidates.filter((item) => selected.includes(item)).map(({ story }) => story);
}
__name(selectCategoryBalancedStories, "selectCategoryBalancedStories");
var DIRECT_BROWSER_HEADERS = Object.freeze({
  accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  "accept-language": "en-GB,en;q=0.9",
  "cache-control": "no-cache",
  pragma: "no-cache",
  "sec-fetch-dest": "document",
  "sec-fetch-mode": "navigate",
  "sec-fetch-site": "none",
  "sec-fetch-user": "?1",
  "upgrade-insecure-requests": "1",
  "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
});
var FEED_REQUEST_HEADERS = Object.freeze({
  accept: "application/rss+xml,application/xml;q=0.9,text/xml;q=0.8,*/*;q=0.5",
  "accept-language": "en-GB,en;q=0.9",
  "user-agent": DIRECT_BROWSER_HEADERS["user-agent"]
});
function groupArticles(articles) {
  const groups = /* @__PURE__ */ new Map();
  for (const article of articles) {
    const headline = String(article.title || "").trim();
    const domain = articleDomain(article);
    const key = normalizeHeadlineKey(headline);
    if (!isRelevantMonitoringArticle(article) || !domain || !key || !/^https?:\/\//i.test(String(article.url || ""))) continue;
    const group = groups.get(key) || { headline, items: [], latest: null };
    if (!group.items.some((item) => articleDomain(item) === domain)) group.items.push(article);
    const seenAt = parseSeenDate(article.seendate);
    if (seenAt && (!group.latest || seenAt > group.latest)) group.latest = seenAt;
    groups.set(key, group);
  }
  return [...groups.values()].sort((a, b) => String(b.latest || "").localeCompare(String(a.latest || "")));
}
__name(groupArticles, "groupArticles");
function storyFromGroup(group, collectedAt) {
  const sources = group.items.slice(0, 4).map((article) => ({
    name: articleDomain(article),
    url: article.url
  }));
  const crossSource = sources.length > 1;
  return {
    headline: group.headline.replace(/\s+([,.;:!?])/g, "$1").replace(/\s+/g, " ").trim(),
    category: classifyHeadline(group.headline),
    summary: crossSource ? `Automatically collected across ${sources.length} monitored outlets. Cross-source presence is not the same as substantive verification; open the sources for context.` : "Automatically collected source signal. It has not been independently corroborated; open the source for context.",
    sources,
    briefing_state: "monitored",
    live_monitoring: {
      automated: true,
      status: crossSource ? "cross-source" : "source-signal",
      collected_at: collectedAt,
      seen_at: group.latest,
      source_country: group.items[0]?.sourcecountry || null,
      scope_country_keys: [...new Set(
        group.items.map((article) => article.scope_country_key).filter((key) => NEWS_DESK_COUNTRY_BY_KEY.has(key))
      )]
    }
  };
}
__name(storyFromGroup, "storyFromGroup");
function isWithinMonitoringWindow(story, collectedAt, windowHours = 24) {
  const seenAt = story?.live_monitoring?.seen_at;
  const seenMs = Date.parse(seenAt || "");
  const collectedMs = Date.parse(collectedAt || "");
  if (Number.isNaN(seenMs) || Number.isNaN(collectedMs)) return false;
  const ageMs = collectedMs - seenMs;
  return ageMs >= -5 * 60 * 1e3 && ageMs <= windowHours * 60 * 60 * 1e3;
}
__name(isWithinMonitoringWindow, "isWithinMonitoringWindow");
function mergeLiveNewsDataset(dataset, articles, collectedAt = (/* @__PURE__ */ new Date()).toISOString(), provider = "GDELT DOC 2.0", sourceStatus = []) {
  if (!dataset || !Array.isArray(dataset.entities)) throw new Error("The briefing dataset is not valid.");
  const normalisedSourceStatus = Array.isArray(sourceStatus) ? sourceStatus : [];
  const coverageGapCount = normalisedSourceStatus.filter(
    (source) => source?.state === "partial" || source?.state === "empty" || source?.state === "unavailable"
  ).length;
  const groups = groupArticles(Array.isArray(articles) ? articles : []);
  const liveStories = groups.map((group) => ({
    story: storyFromGroup(group, collectedAt),
    searchableHeadline: normaliseText(group.headline)
  })).filter(({ story }) => isWithinMonitoringWindow(story, collectedAt));
  const reconciledEntities = reconcileNewsDeskCountries(dataset.entities);
  const entities = reconciledEntities.map((entity) => {
    const curated = (entity.stories || []).filter((story) => !story.live_monitoring?.automated).map((story) => ({
      ...story,
      briefing_state: story.briefing_state || "background",
      edition_at: story.edition_at || dataset.generated_at || null
    }));
    let selected = [];
    if (entity.key === "global-wire-desk") {
      selected = selectCategoryBalancedStories(liveStories, GLOBAL_LIMIT, GLOBAL_LIMIT);
    } else {
      const aliases = entityAliases(entity);
      selected = selectCategoryBalancedStories(liveStories.filter(({ story, searchableHeadline }) => story.live_monitoring.scope_country_keys?.includes(entity.key) || aliases.some((alias) => containsAlias(searchableHeadline, normaliseText(alias)))), COUNTRY_LIMIT);
    }
    const latestSignalAt = selected.map((story) => story.live_monitoring?.seen_at).filter(Boolean).sort().at(-1) || null;
    return {
      ...entity,
      stories: [...selected, ...curated],
      monitoring: {
        checked_at: collectedAt,
        window_hours: 24,
        signal_count: selected.length,
        latest_signal_at: latestSignalAt
      }
    };
  });
  const signals = liveStories.length;
  const crossSource = liveStories.filter(({ story }) => story.live_monitoring.status === "cross-source").length;
  const countryEntities = entities.filter((entity) => NEWS_DESK_COUNTRY_BY_KEY.has(entity.key));
  const countrySignals = countryEntities.reduce(
    (total, entity) => total + (entity.stories || []).filter((story) => story.live_monitoring?.automated).length,
    0
  );
  const matchedCountries = countryEntities.filter((entity) => (entity.stories || []).some((story) => story.live_monitoring?.automated)).length;
  const newestStoryObservedAt = liveStories.map(({ story }) => story.live_monitoring.seen_at).filter(Boolean).sort().at(-1) || null;
  return {
    ...dataset,
    entities,
    live_monitoring: {
      state: coverageGapCount ? "partial" : "active",
      provider,
      cadence_minutes: 30,
      last_success: collectedAt,
      signals,
      cross_source: crossSource,
      country_signals: countrySignals,
      country_scope: {
        configured_countries: NEWS_DESK_COUNTRIES.length,
        checked_countries: countryEntities.length,
        matched_countries: matchedCountries
      },
      newest_story_observed_at: newestStoryObservedAt,
      source_status: normalisedSourceStatus,
      coverage_warning_count: coverageGapCount,
      indices_unchanged: true,
      disclaimer: "Automated source monitoring; source presence is not independent verification."
    }
  };
}
__name(mergeLiveNewsDataset, "mergeLiveNewsDataset");

// src/vendor/verified-updates.js
var SPAIN_SOURCE = "https://www.lamoncloa.gob.es/lang/en/presidente/intervenciones/Paginas/2026/20261005-institutional-statement-speech.aspx";
function applyVerifiedUpdates(dataset) {
  const result = structuredClone(dataset);
  const spain = result.entities?.find((entity) => entity.key === "spain");
  const election = spain?.election;
  if (!election || election.next_election?.verified_at >= "2026-10-11") return result;
  election.previous_next_election ??= structuredClone(election.next_election);
  election.next_election = {
    date: "2026-11-29",
    type: "General election \u2014 announced snap election",
    summary: "In his institutional statement of 5 October 2026, Spain\u2019s President announced a general election for Sunday, 29 November 2026. This replaces the previous expected 2027 timetable. This field records that announcement; it does not revalidate the older polling or political analysis below.",
    verified_at: "2026-10-11T00:00:00Z",
    source_date: "2026-10-05",
    verification_method: "Editorial check of the official institutional statement",
    sources: [{ name: "La Moncloa \u2014 institutional statement, 5 October 2026", url: SPAIN_SOURCE }]
  };
  return result;
}
__name(applyVerifiedUpdates, "applyVerifiedUpdates");

// src/meridian-api.js
var PROVIDER = "TPN evidence engine (trial copy)";
var WINDOW_HOURS = 24;
var MAX_ARTICLES = 1500;
var STALE_AFTER_MS = 3 * 36e5;
var PASS_THROUGH = /* @__PURE__ */ new Map([
  ["/api/sovereign", "sovereign.json"],
  ["/api/business", "business.json"],
  ["/api/vision2050", "vision2050.json"],
  ["/api/resilience", "resilience.json"],
  ["/api/history", "news_history.json"],
  ["/api/comuniq", "comuniq.json"]
]);
async function latestRun(db) {
  return db.prepare(
    `SELECT r.run_id, r.started_at, MAX(x.attempted_at) AS completed_at, COUNT(x.result_id) AS reported,
            COALESCE(SUM(x.healthy), 0) AS healthy
       FROM runs r JOIN endpoint_results x ON x.run_id = r.run_id
      GROUP BY r.run_id ORDER BY r.started_at DESC LIMIT 1`
  ).first();
}
__name(latestRun, "latestRun");
var SOFT_STORY = /\b(?:exhibitions?|festivals?|concerts?|albums?|(?<!operating )theatres?|(?<!operating )theaters?|musicals?|comedy|comedians?|recipes?|restaurants?|cuisine|fashion|horoscopes?|celebrit(?:y|ies)|premieres?|box office|film review|book review|things to do|what'?s on|live shows?|new show|solo show|oscars?|artists?|kite)\b/i;
var HARD_STORY = /\b(?:minist(?:er|ers|ry)|government|cabinet|parliament|mps?|meps?|court|judges?|magistrate|police|prosecut\w*|elections?|electoral|polls?|budget|tax(?:es)?|eu|european (?:commission|union|parliament|council)|nato|sanctions?|war|military|strikes?|attacks?|probe|investigation|inquiry|laws?|bills?|legislation|regulat\w*|polic(?:y|ies)|central bank|prime minister|president|protest\w*|corruption|migration|asylum)\b/i;
function isSoftStory(headline) {
  const h = String(headline || "");
  return SOFT_STORY.test(h) && !HARD_STORY.test(h);
}
__name(isSoftStory, "isSoftStory");
async function engineArticles(db, collectedAt) {
  const end = Date.parse(collectedAt);
  const from = new Date(end - WINDOW_HOURS * 36e5).toISOString();
  const to = new Date(end + 5 * 6e4).toISOString();
  const { results } = await db.prepare(
    `SELECT i.item_id, i.headline, i.canonical_url, i.published_at,
            (SELECT r.value FROM item_routes r
              WHERE r.item_id = i.item_id AND r.kind = 'country' AND r.confidence IN ('high','medium')
              ORDER BY CASE r.confidence WHEN 'high' THEN 0 ELSE 1 END, r.value LIMIT 1) AS country,
            EXISTS (SELECT 1 FROM item_channels ic JOIN channels c ON c.channel_id = ic.channel_id
                     WHERE ic.item_id = i.item_id AND c.register_id = 'malta') AS maltese_outlet
       FROM items i
      WHERE i.date_status = 'dated' AND i.published_precision = 'second'
        AND i.published_at >= ?1 AND i.published_at <= ?2
        AND NOT EXISTS (SELECT 1 FROM item_channels rc JOIN channels rp ON rp.channel_id = rc.channel_id
                         WHERE rc.item_id = i.item_id AND rp.register_id = 'research-publishers')
      ORDER BY i.published_at DESC, i.item_id
      LIMIT ${MAX_ARTICLES}`
  ).bind(from, to).all();
  return results.filter((r) => !isSoftStory(r.headline)).map((r) => ({
    title: r.headline,
    url: r.canonical_url,
    seendate: r.published_at,
    sourcecountry: null,
    // Like the live Meridian's local-news rule for Maltese outlets: a story from a Maltese
    // outlet belongs on the Malta desk unless its own words name another country.
    scope_country_key: r.country || (r.maltese_outlet ? "malta" : null)
  }));
}
__name(engineArticles, "engineArticles");
function engineState(run, nowMs) {
  if (!run?.completed_at) return "awaiting";
  if (nowMs - Date.parse(run.completed_at) > STALE_AFTER_MS) return "degraded";
  if (run.reported && run.healthy / run.reported < 0.5) return "partial";
  return "active";
}
__name(engineState, "engineState");
async function engineBriefing(env, { nowMs = Date.now() } = {}) {
  const object = await env.LIVE_BRIEFING.get("data.json");
  if (!object) return { error: "dataset_unavailable" };
  const dataset = applyVerifiedUpdates(await object.json());
  const run = await latestRun(env.EVIDENCE_DB);
  const state = engineState(run, nowMs);
  if (!run?.completed_at) {
    const merged2 = mergeLiveNewsDataset(dataset, [], new Date(nowMs).toISOString(), PROVIDER, []);
    return { dataset: { ...merged2, live_monitoring: statusFrom(merged2, run, state, 0) } };
  }
  const articles = await engineArticles(env.EVIDENCE_DB, run.completed_at);
  const merged = mergeLiveNewsDataset(dataset, articles, run.completed_at, PROVIDER, []);
  const domains = new Set(articles.map((a) => {
    try {
      return new URL(a.url).hostname.replace(/^www\./, "");
    } catch {
      return "";
    }
  }).filter(Boolean));
  return { dataset: { ...merged, live_monitoring: statusFrom(merged, run, state, domains.size) } };
}
__name(engineBriefing, "engineBriefing");
function statusFrom(merged, run, state, domainCount) {
  const live = merged.live_monitoring;
  return {
    ...live,
    state: state === "awaiting" ? "awaiting" : state,
    provider: PROVIDER,
    cadence_minutes: 60,
    last_success: run?.completed_at || null,
    last_attempt: run?.completed_at || null,
    source_domain_count: domainCount,
    providers: [],
    engine_run: run ? { run_id: run.run_id, started_at: run.started_at, feeds_reported: run.reported, feeds_healthy: run.healthy } : null,
    disclaimer: "Trial copy: signals come from the TPN evidence engine. Automated source monitoring; source presence is not independent verification."
  };
}
__name(statusFrom, "statusFrom");

// ../observer-feed/src/index.js
var CONTRACT = "tpn-observer-ticker/1";
var MAX_ITEMS = 12;
var STALE_AFTER_MS2 = 3 * 36e5;
var CACHE_SECONDS = 300;
var ALLOWED_ORIGIN = "https://www.maltaobserver.com";
var BOUNDARY = "Automatically monitored headlines from Maltese and international outlets, shown with each publisher's own time. A source signal is not verification: open the source. Monitored headlines are separate from the Observer's dated analysis.";
var HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": `public, max-age=${CACHE_SECONDS}`,
  "access-control-allow-origin": ALLOWED_ORIGIN,
  "vary": "Origin",
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  "referrer-policy": "no-referrer",
  "x-robots-tag": "noindex"
};
var HEALTHY = /* @__PURE__ */ new Set(["ok", "not-modified", "ok-undated-only"]);
async function maltaCoverage(db) {
  const { results } = await db.prepare(
    `SELECT c.name AS name, e.enabled AS enabled, json_extract(e.config_json, '$.status') AS status, s.last_class AS last_class
       FROM endpoints e
       JOIN endpoint_channels ec ON ec.endpoint_id = e.endpoint_id
       JOIN channels c ON c.channel_id = ec.channel_id
       LEFT JOIN endpoint_state s ON s.endpoint_id = e.endpoint_id
      WHERE c.register_id = 'malta' AND e.adapter = 'rss'`
  ).all();
  const refusing = [...new Set(results.filter((r) => r.status === "blocked").map((r) => r.name))].sort();
  const failing = [...new Set(results.filter((r) => r.enabled && r.last_class && !HEALTHY.has(r.last_class)).map((r) => r.name))].sort();
  const working = new Set(results.filter((r) => r.enabled && HEALTHY.has(r.last_class)).map((r) => r.name)).size;
  return { working, refusing, failing };
}
__name(maltaCoverage, "maltaCoverage");
async function buildTicker(db, { nowMs = Date.now() } = {}) {
  const run = await latestRun(db);
  const coverage = await maltaCoverage(db);
  const base = {
    contract: CONTRACT,
    source_application: "TPN evidence engine",
    geography: "Malta and Gozo",
    cadence_minutes: 120,
    boundary: BOUNDARY,
    coverage_state: coverage.refusing.length || coverage.failing.length ? "partial" : "complete",
    coverage_warning_count: coverage.refusing.length + coverage.failing.length,
    coverage_note: coverage.refusing.length ? `${coverage.refusing.join(", ")} refuse automated collection, so their reporting is not in this feed.` : null
  };
  if (!run?.completed_at) return { ...base, state: "awaiting", checked_at: null, items: [] };
  const articles = await engineArticles(db, run.completed_at);
  const dataset = { generated_at: null, entities: [{ key: "malta", display_name: "Malta", region: "Mediterranean", stories: [] }] };
  const merged = mergeLiveNewsDataset(dataset, articles, run.completed_at, "TPN evidence engine", []);
  const malta = merged.entities.find((e) => e.key === "malta");
  const items = (malta?.stories || []).filter((s) => s.live_monitoring?.automated).slice(0, MAX_ITEMS).map((s) => ({
    headline: s.headline,
    theme: s.category,
    source_name: s.sources[0]?.name || null,
    source_url: s.sources[0]?.url || null,
    sources: s.sources.map((x) => ({ name: x.name, url: x.url })),
    published_at: s.live_monitoring.seen_at,
    observed_at: s.live_monitoring.seen_at,
    signal_label: s.live_monitoring.status === "cross-source" ? "Cross-source signal" : "Source signal"
  }));
  return {
    ...base,
    state: nowMs - Date.parse(run.completed_at) > STALE_AFTER_MS2 ? "delayed" : "current",
    checked_at: run.completed_at,
    items
  };
}
__name(buildTicker, "buildTicker");

// src/compare.js
var OBSERVER_EDITION_URL = "https://www.maltaobserver.com/api/edition";
var MALTA_LIST = 10;
function storyKey(s) {
  const url = s.sources?.[0]?.url || s.source_url || "";
  return { headline: normalizeHeadlineKey(s.headline || ""), url: url.replace(/^https?:\/\/(www\.)?/, "").replace(/[?#].*$/, "").replace(/\/$/, "") };
}
__name(storyKey, "storyKey");
function sameStory(a, b) {
  const x = storyKey(a), y = storyKey(b);
  return x.headline && x.headline === y.headline || x.url && x.url === y.url;
}
__name(sameStory, "sameStory");
var automated = /* @__PURE__ */ __name((entity) => (entity?.stories || []).filter((s) => s.live_monitoring?.automated), "automated");
var brief = /* @__PURE__ */ __name((s) => ({
  headline: s.headline,
  source: s.sources?.[0]?.name || s.source_name || null,
  url: s.sources?.[0]?.url || s.source_url || null,
  dated: s.live_monitoring?.seen_at || s.published_at || s.observed_at || null
}), "brief");
async function compareMeridian(env, { nowMs = Date.now() } = {}) {
  if (!env.LIVE_BRIEFING) return { available: false, reason: "The live Meridian store is not connected to this engine." };
  const object = await env.LIVE_BRIEFING.get("data.json");
  if (!object) return { available: false, reason: "The live Meridian has not published its briefing." };
  const live = await object.json();
  const { dataset: engine, error } = await engineBriefing(env, { nowMs });
  if (error) return { available: false, reason: "The engine view could not be built." };
  const liveBy = new Map((live.entities || []).map((e) => [e.key, e]));
  const desks = engine.entities.map((e) => {
    const l = automated(liveBy.get(e.key));
    const g = automated(e);
    const shared = g.filter((s) => l.some((x) => sameStory(s, x))).length;
    return { key: e.key, name: e.display_name, live: l.length, engine: g.length, shared };
  }).filter((d) => d.live || d.engine).sort((a, b) => Math.max(b.live, b.engine) - Math.max(a.live, a.engine) || a.name.localeCompare(b.name));
  const sum = /* @__PURE__ */ __name((k) => desks.reduce((n2, d) => n2 + d[k], 0), "sum");
  const maltaLive = automated(liveBy.get("malta"));
  const maltaEngine = automated(engine.entities.find((e) => e.key === "malta"));
  const lm = live.live_monitoring || {};
  const em = engine.live_monitoring || {};
  return {
    available: true,
    live: { signals: lm.signals ?? null, desks_with_signals: desks.filter((d) => d.live).length, last_collected: lm.last_success || null, state: lm.state || null, provider: lm.provider || null },
    engine: { signals: em.signals ?? null, desks_with_signals: desks.filter((d) => d.engine).length, last_collected: em.last_success || null, state: em.state || null },
    totals: { live: sum("live"), engine: sum("engine"), shared: sum("shared") },
    desks,
    malta: { live: maltaLive.slice(0, MALTA_LIST).map(brief), engine: maltaEngine.slice(0, MALTA_LIST).map(brief) }
  };
}
__name(compareMeridian, "compareMeridian");
async function compareObserver(env, { nowMs = Date.now(), fetchImpl = fetch } = {}) {
  const engine = await buildTicker(env.EVIDENCE_DB, { nowMs });
  let live = null;
  let reason = null;
  try {
    const r = await fetchImpl(OBSERVER_EDITION_URL, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(8e3) });
    if (!r.ok) reason = `The Observer answered ${r.status}.`;
    else live = (await r.json())?.meridian?.news_ticker || null;
    if (!live && !reason) reason = "The Observer's edition has no ticker.";
  } catch {
    reason = "The Observer could not be reached.";
  }
  const liveItems = live?.items || [];
  const shared = engine.items.filter((s) => liveItems.some((x) => sameStory(s, x))).length;
  return {
    live: live ? { available: true, checked_at: live.checked_at || null, state: live.state || null, items: liveItems.slice(0, 12).map(brief) } : { available: false, reason, items: [] },
    engine: { checked_at: engine.checked_at, state: engine.state, coverage_note: engine.coverage_note, items: engine.items.map(brief) },
    shared
  };
}
__name(compareObserver, "compareObserver");
async function compareReport(env, deps = {}) {
  const [meridian, observer] = await Promise.all([
    compareMeridian(env, deps).catch(() => ({ available: false, reason: "The Meridian comparison failed." })),
    compareObserver(env, deps).catch(() => ({ live: { available: false, reason: "The Observer comparison failed.", items: [] }, engine: { items: [] }, shared: 0 }))
  ]);
  return { generated_at: new Date(deps.nowMs ?? Date.now()).toISOString(), meridian, observer };
}
__name(compareReport, "compareReport");

// src/compare-page.js
var esc = /* @__PURE__ */ __name((v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]), "esc");
var fmt = new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Malta", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
var when = /* @__PURE__ */ __name((iso) => {
  const t = Date.parse(iso || "");
  return Number.isNaN(t) ? "\u2014" : fmt.format(t);
}, "when");
var safeUrl = /* @__PURE__ */ __name((u) => /^https?:\/\//i.test(String(u || "")) ? String(u) : null, "safeUrl");
var n = /* @__PURE__ */ __name((v) => v === null || v === void 0 ? "\u2014" : String(v), "n");
function storyList(items, empty) {
  if (!items?.length) return `<p class="note">${esc(empty)}</p>`;
  return `<ol class="list">${items.map((s) => {
    const url = safeUrl(s.url);
    const head = url ? `<a href="${esc(url)}" rel="noopener noreferrer" target="_blank">${esc(s.headline)}</a>` : esc(s.headline);
    return `<li>${head}<span class="meta">${esc(s.source || "")}${s.dated ? ` \xB7 ${esc(when(s.dated))}` : ""}</span></li>`;
  }).join("")}</ol>`;
}
__name(storyList, "storyList");
function meridianSection(m) {
  if (!m?.available) return `<section class="card"><h2>Meridian News Desk</h2><p class="note">${esc(m?.reason || "Not available.")}</p></section>`;
  const rows = m.desks.map((d) => `<tr><td>${esc(d.name)}</td><td class="num">${d.live}</td><td class="num">${d.engine}</td><td class="num">${d.shared}</td></tr>`).join("");
  return `<section class="card">
  <h2>Meridian News Desk</h2>
  <div class="pair">
    <div class="tile"><div class="k">Live Meridian</div><div class="v">${n(m.totals.live)}</div><div class="s">signals on ${n(m.live.desks_with_signals)} desks \xB7 collected ${esc(when(m.live.last_collected))}${m.live.state ? ` \xB7 ${esc(m.live.state)}` : ""}</div></div>
    <div class="tile accent"><div class="k">Engine</div><div class="v">${n(m.totals.engine)}</div><div class="s">signals on ${n(m.engine.desks_with_signals)} desks \xB7 collected ${esc(when(m.engine.last_collected))}${m.engine.state ? ` \xB7 ${esc(m.engine.state)}` : ""}</div></div>
    <div class="tile"><div class="k">In both</div><div class="v">${n(m.totals.shared)}</div><div class="s">same headline or same link</div></div>
  </div>
  <div class="table-wrap"><table><thead><tr><th>Desk</th><th class="num">Live</th><th class="num">Engine</th><th class="num">In both</th></tr></thead><tbody>${rows || `<tr><td colspan="4" class="note">No signals on either side.</td></tr>`}</tbody></table></div>
  <h3>Malta desk</h3>
  <div class="cols">
    <div><h4>Live Meridian</h4>${storyList(m.malta.live, "No live signals on the Malta desk.")}</div>
    <div><h4>Engine</h4>${storyList(m.malta.engine, "No engine signals on the Malta desk.")}</div>
  </div>
</section>`;
}
__name(meridianSection, "meridianSection");
function observerSection(o) {
  const live = o?.live || {};
  const engine = o?.engine || {};
  return `<section class="card">
  <h2>Malta Observer ticker</h2>
  <p class="note">What maltaobserver.com shows now ("Live from Meridian") against the engine's public Malta feed. ${o?.shared ?? 0} in both.</p>
  <div class="cols">
    <div><h4>Observer now${live.checked_at ? ` \xB7 checked ${esc(when(live.checked_at))}` : ""}</h4>${live.available ? storyList(live.items, "The Observer's ticker is empty.") : `<p class="note">${esc(live.reason || "Not available.")}</p>`}</div>
    <div><h4>Engine feed${engine.checked_at ? ` \xB7 collected ${esc(when(engine.checked_at))}` : ""}</h4>${storyList(engine.items, "The engine feed is empty.")}${engine.coverage_note ? `<p class="note">${esc(engine.coverage_note)}</p>` : ""}</div>
  </div>
</section>`;
}
__name(observerSection, "observerSection");
function renderComparePage(report) {
  return `<!doctype html>
<html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex, nofollow">
<title>Live vs engine \xB7 Trial</title>
<style>
:root{--navy:#0a1226;--gold:#c89244;--paper:#f6f1e6;--ink:#1d2433;--muted:#5b6272;--line:#ddd3bf;--card:#fffdf8}
@media (prefers-color-scheme:dark){:root{--paper:#0d1424;--ink:#ebe5d8;--muted:#a3a9b7;--line:#2a3550;--card:#131c31}}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header{background:var(--navy);color:#efe7d4;padding:18px 16px;border-bottom:3px solid var(--gold)}
header h1{margin:0;font-size:20px}header p{margin:4px 0 0;color:#c9c2b2;font-size:13px}
main{max-width:1100px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:0 0 16px}
h2{margin:0 0 10px;font-size:18px}h3{margin:18px 0 8px;font-size:16px}h4{margin:0 0 6px;font-size:14px;color:var(--muted)}
.pair{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin-bottom:12px}
.tile{border:1px solid var(--line);border-radius:8px;padding:10px}.tile.accent{border-color:var(--gold)}
.tile .k{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}.tile .v{font-size:26px;font-weight:700}.tile .s{font-size:12px;color:var(--muted)}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}
.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%}th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left}.num{text-align:right;font-variant-numeric:tabular-nums}
.list{margin:0;padding-left:20px}.list li{margin:0 0 8px}.list a{color:inherit}.meta{display:block;font-size:12px;color:var(--muted)}
.note{color:var(--muted);font-size:13px}a{color:var(--gold)}
</style></head><body>
<header><h1>Live vs engine</h1><p>Shadow trial \xB7 read-only \xB7 built ${esc(when(report.generated_at))} \xB7 nothing here changes the live tools</p></header>
<main>
${meridianSection(report.meridian)}
${observerSection(report.observer)}
<p class="note">"In both" means the same headline (ignoring punctuation and case) or the same link. Live counts are the live Meridian's own signals; engine counts use Meridian's own desk rules on the engine's evidence. <a href="/">Back to the trial copy</a></p>
</main></body></html>`;
}
__name(renderComparePage, "renderComparePage");

// src/index.js
var SECURITY = {
  // The live page loads its fonts and libraries from these CDNs and has inline script and
  // styles; data comes only from this site, and the page cannot be framed or leak a referrer.
  "content-security-policy": [
    "default-src 'none'",
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net",
    "font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net",
    "img-src 'self' data: blob: https://cdn.jsdelivr.net",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'"
  ].join("; "),
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-robots-tag": "noindex, nofollow"
};
var json = /* @__PURE__ */ __name((status, body) => new Response(JSON.stringify(body), {
  status,
  headers: { ...SECURITY, "content-type": "application/json; charset=utf-8", "cache-control": "no-store, private" }
}), "json");
var BANNER_STYLE = "position:sticky;top:0;z-index:9999;background:#0a1226;color:#efe7d4;font:600 13px/1.4 system-ui,-apple-system,Segoe UI,sans-serif;padding:8px 16px;text-align:center;border-bottom:2px solid #c89244";
var BANNER_TEXT = "Trial copy \xB7 News Desk signals from the TPN evidence engine \xB7 everything else as in the live Meridian \xB7 read-only \xB7 the live Meridian is unchanged";
var BANNER_LINK = '<a href="/trial/compare" style="color:#c89244;margin-left:8px">Live vs engine \u2192</a>';
var NO_HANDOFF = '<!doctype html><meta charset=utf-8><title>Not in the trial copy</title><body style="font:16px/1.5 system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem"><h1>Not available in the trial copy</h1><p>The research hand-off sends stories to the live ProMedia workspace, so it is switched off here. Use the live Meridian for research hand-offs.</p><p><a href="/">Back to the trial copy</a></p>';
async function liveDataset(env, key) {
  const object = await env.LIVE_BRIEFING.get(key);
  if (!object) return json(503, { error: "dataset_unavailable", message: "The requested briefing dataset has not been published yet." });
  return new Response(object.body, { status: 200, headers: { ...SECURITY, "content-type": "application/json; charset=utf-8", "cache-control": "no-store, private" } });
}
__name(liveDataset, "liveDataset");
async function handleApi(request, env, url, deps = {}) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return json(405, { error: "method_not_allowed", message: "This trial copy is read-only." });
  }
  const path = url.pathname;
  try {
    if (PASS_THROUGH.has(path)) return await liveDataset(env, PASS_THROUGH.get(path));
    if (path === "/api/trial-compare") return json(200, await compareReport(env, { nowMs: deps.nowMs, fetchImpl: deps.observerFetch || fetch }));
    if (path === "/api/briefing" || path === "/api/live-status") {
      const { dataset, error } = await engineBriefing(env, { nowMs: deps.nowMs });
      if (error) return json(503, { error, message: "The briefing dataset has not been published yet." });
      return json(200, path === "/api/briefing" ? dataset : dataset.live_monitoring);
    }
  } catch (error) {
    console.error(JSON.stringify({ event: "meridian_copy_read_failed", path, message: error instanceof Error ? error.message : String(error) }));
    return json(500, { error: "dataset_read_failed", message: "The briefing dataset could not be read." });
  }
  return json(404, { error: "not_found", message: "Unknown briefing endpoint." });
}
__name(handleApi, "handleApi");
function withBanner(response) {
  if (typeof HTMLRewriter === "undefined") return response;
  return new HTMLRewriter().on("title", { element(el) {
    el.prepend("Trial copy \xB7 ");
  } }).on("body", { element(el) {
    el.prepend(`<div role="note" style="${BANNER_STYLE}">${BANNER_TEXT}${BANNER_LINK}</div>`, { html: true });
  } }).transform(response);
}
__name(withBanner, "withBanner");
async function handleRequest(request, env, deps = {}) {
  const url = new URL(request.url);
  const access = await verifyAccess(request, env, deps);
  if (!access.ok) {
    const message = `Not available (${access.reason}). Sign in through tpnintel.com with a reader account.`;
    return url.pathname.startsWith("/api/") ? json(access.status, { message }) : new Response(message, { status: access.status, headers: { ...SECURITY, "content-type": "text/plain; charset=utf-8" } });
  }
  if (url.pathname.startsWith("/api/")) return handleApi(request, env, url, deps);
  if (request.method !== "GET" && request.method !== "HEAD") return new Response("Read-only.", { status: 405, headers: SECURITY });
  if (url.pathname === "/trial/compare") {
    const report = await compareReport(env, { nowMs: deps.nowMs, fetchImpl: deps.observerFetch || fetch });
    return new Response(renderComparePage(report), { status: 200, headers: { ...SECURITY, "content-type": "text/html; charset=utf-8", "cache-control": "no-store, private" } });
  }
  if (url.pathname.startsWith("/research-start")) {
    return new Response(NO_HANDOFF, { status: 403, headers: { ...SECURITY, "content-type": "text/html; charset=utf-8", "cache-control": "no-store, private" } });
  }
  const assetUrl = new URL(url);
  if (assetUrl.pathname.startsWith("/.yfl-nav/")) assetUrl.pathname = assetUrl.pathname.replace("/.yfl-nav/", "/yfl-nav/");
  const asset = await env.ASSETS.fetch(new Request(assetUrl, request));
  const headers = new Headers(asset.headers);
  for (const [k, v] of Object.entries(SECURITY)) headers.set(k, v);
  headers.set("cache-control", "no-store, private");
  const response = new Response(asset.body, { status: asset.status, headers });
  return (headers.get("content-type") || "").includes("text/html") ? withBanner(response) : response;
}
__name(handleRequest, "handleRequest");
var index_default = {
  fetch: /* @__PURE__ */ __name((request, env) => handleRequest(request, env), "fetch")
};
export {
  BANNER_TEXT,
  index_default as default,
  handleApi,
  handleRequest
};
//# sourceMappingURL=index.js.map
