// AI & Skills Watch: selection rules from the design note (17 October 2026).
// Pure functions only, so the rules can be tested without a database.

export const CONTRACT = "watch-edition-v1";
export const SECTION = "AI & Skills Watch";
export const WINDOW_DAYS = 7;
export const MAX_AGE_DAYS = 14;
export const MAX_RESEARCH = 5;
export const MAX_NEWS = 7;
export const MAX_ITEMS = 12;
export const CHAPTERS = ["Malta", "AI Skilling", "Skilling", "Education", "Work"];

const DAY_MS = 24 * 60 * 60 * 1e3;
const RESEARCH_REGISTER = "research-publishers";

// Rule 1: the headline pairs AI with skills, schools, jobs, workers, training, literacy or labour.
const AI = /\bAI\b|\bA\.I\.|\bGenAI\b|\bartificial intelligence\b|\bgenerative AI\b|\bChatGPT\b|\bLLMs?\b|\bAI[- ]powered\b/i;
const AI_CASE_SENSITIVE = /\bAI\b|\bA\.I\.|\bGenAI\b|\bChatGPT\b|\bLLMs?\b/;
const AI_WORDS = /\bartificial intelligence\b|\bgenerative AI\b/i;
const PAIRING = /\b(?:skills?|skilling|skilled|upskill\w*|reskill\w*|schools?|pupils?|students?|teachers?|teaching|universit(?:y|ies)|educat\w*|VET|vocational|apprentice\w*|curricul\w*|literacy|training|learners?|lifelong learning|work-based learning|jobs?|work|workers?|workforce|workplaces?|employ\w*|unemploy\w*|labou?r|wages?|hiring|layoffs?|talent|careers?|graduates?)\b/i;
// "Training" an AI model is about models, not people.
const MODEL_TRAINING = /\btrain(?:s|ed|ing)?\s+(?:(?:an?|the|its|their|our)\s+)?(?:AI|artificial intelligence|models?|LLMs?|chatbots?)\b|\bAI models?\b|\btraining (?:data|choices|runs?)\b/i;

// Rule 4: dropped topics. Each entry names the reason shown to Jes on the desk.
const EXCLUDE = [
  ["stocks and markets", /\b(?:stocks?|shares|share price|investors?|nasdaq|s&p 500|ipo|valuation|market cap|earnings|rally|sell-?off|bubble)\b/i],
  ["startup funding and fintech", /\b(?:raises?|raised|funding round|seed round|series [a-e]|venture capital|vc-backed|start-?ups?|fintech|unicorn)\b/i],
  ["AI safety and model behaviour", /\b(?:rogue|hallucinat\w*|alignment|jailbreak\w*|ai safety|safety institute|model behaviou?r|self-regulation|existential|ai risks?)\b/i],
  ["skill games", /\bskill[- ]games?\b/i],
  ["crime", /\b(?:crime|criminals?|scams?|scammers?|fraud\w*|police|arrest\w*|charged|court|prison|probation|deepfake porn)\b/i],
  ["live blog or entertainment", /\blive:|\bas it happened\b|\b(?:film|movie|box office)\b/i]
];

// Peer small states come first in the Education chapter and are preferred elsewhere.
const PEER_STATES = new Set(["cyprus", "luxembourg", "estonia", "latvia", "lithuania", "slovenia", "iceland", "ireland", "croatia", "montenegro", "portugal", "greece", "czechia", "slovakia", "hungary", "denmark", "finland"]);
const PEER_HEADLINE = /\b(?:Cyprus|Cypriot|Luxembourg|Estonia\w*|Latvia\w*|Lithuania\w*|Sloven\w*|Iceland\w*|Ireland|Irish|Croatia\w*|Montenegr\w*|Portug\w*|Greece|Greek|Czech\w*|Slovak\w*|Hungar\w*|Denmark|Danish|Finland|Finnish)\b/;
const MALTA_HEADLINE = /\b(?:Malta|Maltese|Gozo|MCAST|NSO Malta)\b/;
const INSTITUTIONS = /\b(?:Cedefop|Eurofound|JRC|OECD|ECB|IMF|World Bank|European Commission|ILO|UNESCO)\b/;

// Chapter rules, tried in order after Malta.
const CHAPTER_RULES = [
  ["Education", /\b(?:schools?|pupils?|students?|teachers?|teaching|universit(?:y|ies)|curricul\w*|classrooms?|theses|graduates?|education(?:al)?)\b/i],
  ["Skilling", /\b(?:skills anticipation|anticipat\w*|lifelong learning|apprentice\w*|work-based learning|upskill\w*|reskill\w*|VET|vocational)\b/i],
  ["AI Skilling", /\b(?:skills?|skilling|training|literacy|learners?|learning)\b/i],
  ["Work", /./]
];

// "Sources first" per chapter in the design note.
const SOURCES_FIRST = {
  "AI Skilling": /cedefop|jrc|oecd/i,
  Skilling: /cedefop|eurofound|jrc/i,
  Education: /cedefop/i,
  Work: /eurofound|oecd|ecb|imf/i,
  Malta: /./
};

const PUBLISHER_NAMES = [
  [/^JRC Publications Repository/i, "JRC (European Commission)"],
  [/^Cedefop\b/i, "Cedefop"],
  [/^Eurofound\b/i, "Eurofound"],
  [/^OECD\b/i, "OECD"],
  [/^ECB\b/i, "ECB"],
  [/^IMF\b/i, "IMF"]
];

const STOP = new Set("the a an and or of to in on for with as by at from that this is are was were be been has have had after over into about amid says said will would could new more than its it his her their our not but also how why what who".split(" "));

export function headlineTokens(headline) {
  return [...new Set(String(headline || "").toLowerCase().normalize("NFKD").replace(/\p{M}/gu, "").split(/[^\p{L}\p{N}]+/u).filter((t) => t.length >= 3 && !STOP.has(t)))];
}

function jaccard(a, b) {
  const B = new Set(b);
  const shared = a.filter((t) => B.has(t)).length;
  const union = a.length + B.size - shared;
  return { shared, score: union ? shared / union : 0 };
}

function hasAi(headline) {
  return AI_CASE_SENSITIVE.test(headline) || AI_WORDS.test(headline);
}

export function exclusionReason(headline) {
  const h = String(headline || "");
  if (!hasAi(h)) return "no AI in the headline";
  // Ignore the AI phrases themselves when looking for the pairing ("machine learning" is not people learning).
  const rest = h.replace(/\bmachine learning\b|\bdeep learning\b/gi, " ");
  const withoutModelTraining = rest.replace(MODEL_TRAINING, " ");
  if (!PAIRING.test(withoutModelTraining)) return MODEL_TRAINING.test(rest) ? "AI model training, not people" : "AI without skills, schools, jobs or work";
  for (const [reason, pattern] of EXCLUDE) if (pattern.test(h)) return reason;
  return null;
}

export function chapterFor({ headline, malta }) {
  if (malta || MALTA_HEADLINE.test(headline)) return "Malta";
  const h = String(headline).replace(/\bmachine learning\b|\bdeep learning\b/gi, " ");
  return CHAPTER_RULES.find(([, pattern]) => pattern.test(h))[0];
}

export function publisherName(row) {
  if (row.research && row.research_channel) {
    for (const [pattern, name] of PUBLISHER_NAMES) if (pattern.test(row.research_channel)) return name;
    return String(row.research_channel).split(" · ")[0].trim();
  }
  return String(row.publisher_domain || "").replace(/^www\./i, "");
}

function httpsUrl(value) {
  try {
    const url = new URL(String(value || ""));
    return url.protocol === "https:" ? url.href : null;
  } catch {
    return null;
  }
}

// Rule 3: one link per story; the original publisher wins.
function preferred(a, b) {
  const brand = (row) => String(row.publisher_domain || "").replace(/^www\./, "").split(".")[0].toLowerCase();
  const rank = (row, other) => [
    row.research ? 1 : 0,
    brand(row).length >= 3 && other.headline.toLowerCase().includes(brand(row)) ? 1 : 0,
    row.register === "insights" ? 1 : 0,
    -Date.parse(row.published_at)
  ];
  const ra = rank(a, b), rb = rank(b, a);
  for (let i = 0; i < ra.length; i += 1) if (ra[i] !== rb[i]) return ra[i] > rb[i] ? a : b;
  return a.item_id < b.item_id ? a : b;
}

function sameStory(a, b) {
  if (a.cluster_id && a.cluster_id === b.cluster_id) return true;
  const { shared, score } = jaccard(a.tokens, b.tokens);
  return (shared >= 3 && score >= 0.5) || (shared >= 4 && score >= 0.2);
}

function score(row) {
  let s = 0;
  if (row.chapter === "Malta") s += 100;
  // A named institution in the headline counts too: the note wants the ECB and IMF stories even via secondary outlets.
  if (SOURCES_FIRST[row.chapter]?.test(`${row.publisher} ${row.research_channel || ""} ${row.headline}`)) s += 4;
  if (row.peer) s += row.chapter === "Education" ? 4 : 3;
  if (INSTITUTIONS.test(row.headline)) s += 2;
  if (["eu-affairs", "geopolitical", "malta", "home-newsrooms"].includes(row.register)) s += 1;
  return s;
}

function byScoreThenDate(a, b) {
  return b.score - a.score || Date.parse(b.published_at) - Date.parse(a.published_at) || (a.item_id < b.item_id ? -1 : 1);
}

// rows: items first seen in the 7-day window, with fields from the evidence engine
// (item_id, headline, canonical_url, publisher_domain, published_at, cluster_id, registers, research_channel, malta, countries).
export function selectWatchItems(rows, { nowMs }) {
  const oldest = nowMs - MAX_AGE_DAYS * DAY_MS;
  const leftOut = [];
  const kept = [];
  for (const raw of rows) {
    const published = Date.parse(raw.published_at || "");
    const url = httpsUrl(raw.canonical_url);
    const registers = String(raw.registers || "").split(",").filter(Boolean);
    const countries = String(raw.countries || "").split(",").filter(Boolean);
    const row = {
      ...raw,
      headline: String(raw.headline || "").replace(/\s+/g, " ").trim(),
      research: registers.includes(RESEARCH_REGISTER),
      register: registers.includes(RESEARCH_REGISTER) ? RESEARCH_REGISTER : registers.includes("malta") ? "malta" : registers[0] || null,
      malta: Boolean(raw.malta) || registers.includes("malta")
    };
    // Rule 2: published in the last 14 days, by the publisher's own date.
    if (!Number.isFinite(published) || published < oldest || published > nowMs + 5 * 60 * 1e3) { leftOut.push({ item_id: row.item_id, reason: "published more than 14 days ago" }); continue; }
    if (!url) { leftOut.push({ item_id: row.item_id, reason: "no https link" }); continue; }
    const reason = exclusionReason(row.headline);
    if (reason) { leftOut.push({ item_id: row.item_id, reason }); continue; }
    row.url = url;
    row.chapter = chapterFor(row);
    row.publisher = publisherName(row);
    row.peerKey = countries.find((c) => PEER_STATES.has(c)) || row.headline.match(PEER_HEADLINE)?.[0].toLowerCase().slice(0, 5) || null;
    row.peer = Boolean(row.peerKey);
    row.tokens = headlineTokens(row.headline);
    row.score = score(row);
    kept.push(row);
  }

  // Rule 3: collapse duplicates of the same story.
  const stories = [];
  for (const row of kept) {
    const index = stories.findIndex((s) => sameStory(s, row));
    if (index === -1) { stories.push(row); continue; }
    const winner = preferred(stories[index], row);
    leftOut.push({ item_id: (winner === row ? stories[index] : row).item_id, reason: "same story from another publisher" });
    stories[index] = winner;
  }

  // Rule 5: at most 12 items, up to 5 research and 7 news, Malta always first.
  // First pass takes the best item from each chapter so one busy chapter cannot crowd out the rest.
  const ordered = [...stories].sort(byScoreThenDate);
  const chosen = [];
  const counts = { research: 0, news: 0 };
  // One news item per peer country and chapter: three Portuguese schools stories are one story for this section.
  const peerSlots = new Set();
  const fits = (row) => chosen.length < MAX_ITEMS && (row.research ? counts.research < MAX_RESEARCH : counts.news < MAX_NEWS) && !(row.peerKey && !row.research && peerSlots.has(`${row.peerKey}|${row.chapter}`));
  const take = (row) => {
    chosen.push(row);
    counts[row.research ? "research" : "news"] += 1;
    if (row.peerKey && !row.research) peerSlots.add(`${row.peerKey}|${row.chapter}`);
  };
  for (const chapter of CHAPTERS) {
    const best = ordered.find((row) => row.chapter === chapter && !chosen.includes(row) && fits(row));
    if (best) take(best);
  }
  for (const row of ordered) {
    if (row.chapter === "Malta" && !chosen.includes(row) && fits(row)) take(row);
  }
  for (const row of ordered) if (!chosen.includes(row) && fits(row)) take(row);
  for (const row of ordered) if (!chosen.includes(row)) leftOut.push({ item_id: row.item_id, reason: "edition full" });

  // Grouped by chapter, Malta first; research before news within a chapter, newest first.
  chosen.sort((a, b) => CHAPTERS.indexOf(a.chapter) - CHAPTERS.indexOf(b.chapter) || Number(b.research) - Number(a.research) || Date.parse(b.published_at) - Date.parse(a.published_at) || (a.item_id < b.item_id ? -1 : 1));
  return {
    items: chosen.map((row) => ({
      id: String(row.item_id),
      chapter: row.chapter,
      kind: row.research ? "research" : "news",
      headline: row.headline,
      publisher: row.publisher,
      published_at: new Date(Date.parse(row.published_at)).toISOString(),
      url: row.url
    })),
    left_out: leftOut
  };
}

export function buildWatchEdition(rows, { nowMs }) {
  const windowEnd = new Date(nowMs).toISOString();
  const windowStart = new Date(nowMs - WINDOW_DAYS * DAY_MS).toISOString();
  const { items, left_out } = selectWatchItems(rows, { nowMs });
  return {
    contract_version: CONTRACT,
    section: SECTION,
    label: "source signal",
    boundary: "Points readers to sources. Not PFRI evidence; never changes an Index score.",
    window: { start: windowStart, end: windowEnd, published_within_days: MAX_AGE_DAYS },
    considered: rows.length,
    left_out: left_out.length,
    items
  };
}

export function watchEditionIsValid(edition, { nowMs = Date.now() } = {}) {
  if (!edition || edition.contract_version !== CONTRACT || edition.section !== SECTION || edition.label !== "source signal") return false;
  const start = Date.parse(edition.window?.start || "");
  const end = Date.parse(edition.window?.end || "");
  if (!Number.isFinite(start) || !Number.isFinite(end) || end - start !== WINDOW_DAYS * DAY_MS || end > nowMs + 5 * 60 * 1e3) return false;
  const items = edition.items;
  if (!Array.isArray(items) || items.length < 1 || items.length > MAX_ITEMS) return false;
  if (items.filter((i) => i?.kind === "research").length > MAX_RESEARCH || items.filter((i) => i?.kind === "news").length > MAX_NEWS) return false;
  if (new Set(items.map((i) => i?.id)).size !== items.length || new Set(items.map((i) => i?.url)).size !== items.length) return false;
  let lastChapter = 0;
  for (const item of items) {
    const chapter = CHAPTERS.indexOf(item?.chapter);
    if (chapter < lastChapter) return false;
    lastChapter = chapter;
    if (!item.id || !["research", "news"].includes(item.kind) || !item.headline || !item.publisher) return false;
    if (!httpsUrl(item.url)) return false;
    const published = Date.parse(item.published_at || "");
    if (!Number.isFinite(published) || published < end - MAX_AGE_DAYS * DAY_MS || published > end + 5 * 60 * 1e3) return false;
    if (exclusionReason(item.headline)) return false;
  }
  return true;
}
