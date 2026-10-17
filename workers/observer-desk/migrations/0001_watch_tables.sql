-- AI & Skills Watch: the same three-step structure as the Malta Observer.
-- watch_editions holds each prepared edition (content-addressed, like observer_editions),
-- watch_candidates queues it for the desk, and watch_approvals records Jes's Publish.
--
-- Per-item drops: Jes may drop single items before publishing. The edition body stays
-- unchanged (its id is the SHA-256 of the body); the approval records which items were
-- dropped, as a JSON array of item ids. The site shows the latest approval's edition
-- without those items.
--
-- Not applied by this pull request. Apply to the EU evidence database (tpn-evidence)
-- on purpose, after review, with:
--   wrangler d1 execute tpn-evidence --remote --file workers/observer-desk/migrations/0001_watch_tables.sql

CREATE TABLE IF NOT EXISTS watch_editions (
  edition_id    TEXT PRIMARY KEY,
  body          TEXT NOT NULL,
  prepared_at   TEXT NOT NULL,
  window_start  TEXT NOT NULL,
  window_end    TEXT NOT NULL,
  valid         INTEGER NOT NULL CHECK (valid IN (0, 1))
);
CREATE INDEX IF NOT EXISTS watch_editions_by_time ON watch_editions(prepared_at);

CREATE TABLE IF NOT EXISTS watch_candidates (
  candidate_id  INTEGER PRIMARY KEY AUTOINCREMENT,
  edition_id    TEXT NOT NULL REFERENCES watch_editions(edition_id),
  prepared_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS watch_approvals (
  approval_id   INTEGER PRIMARY KEY AUTOINCREMENT,
  edition_id    TEXT NOT NULL REFERENCES watch_editions(edition_id),
  approved_at   TEXT NOT NULL,
  approved_by   TEXT NOT NULL,
  dropped       TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(dropped) AND json_type(dropped) = 'array')
);
CREATE INDEX IF NOT EXISTS watch_approvals_by_time ON watch_approvals(approved_at);
