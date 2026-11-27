-- Task 88.5: per-source sync state and persisted rejected/failed records.
-- Plain SQL that is valid on SQLite and PostgreSQL (TEXT timestamps like the other tables).

-- One row per source. cursor is the opaque JSON checkpoint of connectors with a single cursor
-- (nvd, ghsa). totals are cumulative record counters over all runs; last_report is the JSON
-- report of the latest run. last_status: running | success | partial | bounded | failed.
CREATE TABLE sync_state(
  source TEXT PRIMARY KEY,
  last_attempt_at TEXT,
  last_success_at TEXT,
  last_status TEXT,
  last_error TEXT,
  cursor TEXT,
  totals TEXT,
  last_report TEXT,
  last_run_id INTEGER);

-- Keyed checkpoints for connectors with one cursor per key (osv: key = ecosystem).
CREATE TABLE sync_checkpoint(
  source TEXT NOT NULL,
  key TEXT NOT NULL,
  cursor TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(source, key));

-- Every record that was rejected (validation) or failed (fetch/store) is kept here.
-- Idempotency: one row per (source, record_id, reason, raw_ref) across runs. A repeat of the same
-- problem updates run_id, kind, last_seen_at and occurrences instead of adding a row. A record
-- that later ingests successfully has its rows deleted. record_id and raw_ref use '' for "none".
CREATE TABLE rejected_record(
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL,
  source TEXT NOT NULL,
  record_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  reason TEXT NOT NULL,
  raw_ref TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  occurrences INTEGER NOT NULL);
CREATE UNIQUE INDEX rejected_record_key ON rejected_record(source, record_id, reason, raw_ref);
CREATE INDEX rejected_record_run ON rejected_record(run_id);
