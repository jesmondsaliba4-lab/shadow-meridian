import test from "node:test";
import assert from "node:assert/strict";
import { buildWatchEdition, chapterFor, exclusionReason, selectWatchItems, watchEditionIsValid } from "../src/watch/select.js";

const NOW = Date.parse("2026-10-18T18:00:00Z"); // a Sunday evening
const daysAgo = (n) => new Date(NOW - n * 864e5).toISOString();
let n = 0;
const row = (headline, extra = {}) => ({
  item_id: `it_${++n}`,
  headline,
  canonical_url: `https://example.org/${n}`,
  publisher_domain: "example.org",
  published_at: daysAgo(2),
  registers: "eu-affairs",
  ...extra
});

test("rule 1: the headline must pair AI with skills, schools, jobs, workers, training, literacy or labour", () => {
  assert.equal(exclusionReason("AI literacy course opens for teachers"), null);
  assert.equal(exclusionReason("IMF warns AI could hit 60 per cent of jobs"), null);
  assert.equal(exclusionReason("New AI chip unveiled in Taipei"), "AI without skills, schools, jobs or work");
  assert.equal(exclusionReason("Skills shortage hits construction"), "no AI in the headline");
  assert.equal(exclusionReason("Officials said the plan works"), "no AI in the headline", "'said' is not AI");
});

test("rule 1: training an AI model is not training people", () => {
  assert.equal(exclusionReason("Bank becomes first to train AI model on sovereign cloud"), "AI model training, not people");
  assert.equal(exclusionReason("How books are scanned to train artificial intelligence"), "AI model training, not people");
  assert.equal(exclusionReason("Subsidised AI training programme for small firms"), null);
  assert.equal(exclusionReason("Machine learning gets faster with AI chips"), "AI without skills, schools, jobs or work");
});

test("rule 4: dropped topics", () => {
  assert.equal(exclusionReason("AI jobs fears send tech stocks lower"), "stocks and markets");
  assert.equal(exclusionReason("AI training startup raises funding round for workers"), "startup funding and fintech");
  assert.equal(exclusionReason("AI agents are going rogue, workers warn"), "AI safety and model behaviour");
  assert.equal(exclusionReason("AI skill games craze among students"), "skill games");
  assert.equal(exclusionReason("Police arrest workers over AI scam"), "crime");
  assert.equal(exclusionReason("Politics live: Labor warns about AI in voting"), "live blog or entertainment");
});

test("chapters follow the note's table, Malta first", () => {
  assert.equal(chapterFor({ headline: "MCAST turns to AI to tackle skills gap", malta: false }), "Malta");
  assert.equal(chapterFor({ headline: "Teachers get AI skills", malta: true }), "Malta");
  assert.equal(chapterFor({ headline: "Portugal confirms AI guidelines for schools" }), "Education");
  assert.equal(chapterFor({ headline: "Italy steps up skills anticipation for the age of AI" }), "Skilling");
  assert.equal(chapterFor({ headline: "AI and Skills" }), "AI Skilling");
  assert.equal(chapterFor({ headline: "ECB says AI weakens workers' bargaining power" }), "Work");
});

test("rule 2: only items published in the last 14 days", () => {
  const { items, left_out } = selectWatchItems([
    row("AI skills plan for workers", { published_at: daysAgo(3) }),
    row("Old AI jobs essay resurfaces", { published_at: daysAgo(15) }),
    row("AI training event for teachers next month", { published_at: daysAgo(-10) })
  ], { nowMs: NOW });
  assert.deepEqual(items.map((i) => i.headline), ["AI skills plan for workers"]);
  assert.equal(left_out.filter((l) => l.reason === "published more than 14 days ago").length, 2);
});

test("rule 3: one link per story, and the original publisher wins", () => {
  const headline = "McKinsey research shows AI creating more jobs than automation displaces";
  const { items, left_out } = selectWatchItems([
    row(headline, { publisher_domain: "fortune.com", registers: "corporate", published_at: daysAgo(2), cluster_id: "cl_a" }),
    row(headline, { publisher_domain: "mckinsey.com", registers: "insights", published_at: daysAgo(2), cluster_id: "cl_b" })
  ], { nowMs: NOW });
  assert.equal(items.length, 1);
  assert.equal(items[0].publisher, "mckinsey.com");
  assert.equal(left_out[0].reason, "same story from another publisher");
});

test("rule 3: research publishers win a shared cluster and keep their own name", () => {
  const { items } = selectWatchItems([
    row("Cedefop: Hungary makes AI a VET subject", { publisher_domain: "hungarytoday.hu", cluster_id: "cl_h" }),
    row("Hungary: AI becomes a new subject in VET schools", { publisher_domain: "cedefop.europa.eu", registers: "research-publishers", research_channel: "Cedefop · news", cluster_id: "cl_h" })
  ], { nowMs: NOW });
  assert.equal(items.length, 1);
  assert.equal(items[0].publisher, "Cedefop");
  assert.equal(items[0].kind, "research");
});

test("rule 5: at most 12 items, 5 research and 7 news, Malta first", () => {
  const research = ["Algorithmic management and AI in European workplaces", "AI literacy among adult learners", "Teachers and generative AI in vocational schools", "AI exposure across regional labour markets", "Apprenticeships in the age of AI", "Platform work, AI and wages", "AI adoption and training in SMEs", "Graduate employment after AI"];
  const news = ["Bank retrains tellers for AI jobs", "Airline pilots AI rostering with unions", "Dublin hospital trains nurses on AI triage", "Warsaw coders face AI hiring freeze", "Lisbon port workers learn AI cranes", "Tallinn schools add AI lessons", "Vienna civil servants get AI courses", "Madrid call centres cut jobs over AI", "Riga students build AI tutors", "Oslo welders upskill with AI helmets", "Athens tour guides fear AI apps replacing work", "Sofia factory pairs AI with apprentices"];
  const rows = [
    ...research.map((h) => row(h, { registers: "research-publishers", research_channel: "Eurofound \u00B7 current news", publisher_domain: "europa.eu" })),
    ...news.map((h) => row(h)),
    row("Gozo school pilots AI literacy lessons", { published_at: daysAgo(6), registers: "malta" })
  ];
  const { items } = selectWatchItems(rows, { nowMs: NOW });
  assert.equal(items.length, 12);
  assert.equal(items.filter((i) => i.kind === "research").length, 5);
  assert.equal(items.filter((i) => i.kind === "news").length, 7);
  assert.equal(items[0].chapter, "Malta");
});

test("one news item per peer country and chapter", () => {
  const { items } = selectWatchItems([
    row("Portugal confirms flexible AI guidelines for schools", { countries: "portugal" }),
    row("Portugal opens public consultation on AI use in schools", { countries: "portugal" }),
    row("Cyprus businesses invited to subsidised AI training programme", { countries: "cyprus" })
  ], { nowMs: NOW });
  assert.equal(items.filter((i) => /Portugal/.test(i.headline)).length, 1);
  assert.equal(items.length, 2);
});

test("an edition passes its own checks, and tampering fails them", () => {
  const edition = buildWatchEdition([
    row("MCAST turns to AI to tackle Malta's skills gap", { registers: "malta" }),
    row("ECB says AI is weakening workers' bargaining power")
  ], { nowMs: NOW });
  assert.equal(watchEditionIsValid(edition, { nowMs: NOW }), true);
  assert.equal(edition.items[0].chapter, "Malta");
  assert.deepEqual(Object.keys(edition.items[0]).sort(), ["chapter", "headline", "id", "kind", "published_at", "publisher", "url"]);
  assert.equal(watchEditionIsValid({ ...edition, items: [] }, { nowMs: NOW }), false);
  assert.equal(watchEditionIsValid({ ...edition, items: [...edition.items].reverse() }, { nowMs: NOW }), false, "Malta must come first");
  assert.equal(watchEditionIsValid({ ...edition, items: [{ ...edition.items[0], url: "http://example.org" }, edition.items[1]] }, { nowMs: NOW }), false);
  assert.equal(watchEditionIsValid({ ...edition, items: [{ ...edition.items[0], headline: "AI stocks rally on jobs data" }, edition.items[1]] }, { nowMs: NOW }), false);
});
