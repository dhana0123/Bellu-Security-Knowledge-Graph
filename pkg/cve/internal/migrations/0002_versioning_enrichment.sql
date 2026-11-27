ALTER TABLE raw_record ADD COLUMN status TEXT NOT NULL DEFAULT 'ok';
ALTER TABLE raw_record ADD COLUMN error TEXT;
ALTER TABLE kev ADD COLUMN status TEXT NOT NULL DEFAULT 'linked';
CREATE TABLE source_record_version(
  source TEXT NOT NULL, external_id TEXT NOT NULL, version INTEGER NOT NULL,
  content_hash TEXT NOT NULL, json TEXT NOT NULL,
  event_time TEXT, recorded_at TEXT NOT NULL, state TEXT NOT NULL,
  PRIMARY KEY(source, external_id, version));
CREATE TABLE severity_assessment(
  source TEXT NOT NULL, record_id TEXT NOT NULL, type TEXT NOT NULL, vector TEXT NOT NULL,
  version TEXT, score REAL, rating TEXT, published_at TEXT, ingested_at TEXT NOT NULL,
  validation TEXT NOT NULL CHECK(validation IN ('valid','mismatch','computed','unverified')),
  reason TEXT,
  PRIMARY KEY(source, record_id, type, vector));
CREATE TABLE epss_history(
  cve TEXT NOT NULL, score_date TEXT NOT NULL, score REAL, percentile REAL,
  status TEXT NOT NULL, recorded_at TEXT NOT NULL, PRIMARY KEY(cve, score_date));
CREATE TABLE weakness_link(
  vulnerability_id TEXT NOT NULL, cwe_id TEXT NOT NULL, PRIMARY KEY(vulnerability_id, cwe_id));
CREATE TABLE patch(
  vulnerability_id TEXT NOT NULL, url TEXT NOT NULL, source TEXT NOT NULL, fixed_version TEXT,
  PRIMARY KEY(vulnerability_id, url, source));
CREATE TABLE exploit_ref(
  vulnerability_id TEXT NOT NULL, url TEXT NOT NULL, source TEXT NOT NULL,
  PRIMARY KEY(vulnerability_id, url, source));
CREATE TABLE fact_version(
  fact_id TEXT NOT NULL, version INTEGER NOT NULL,
  layer TEXT NOT NULL CHECK(layer IN ('raw','resolved','inferred','validated')),
  kind TEXT NOT NULL, subject TEXT NOT NULL, payload TEXT NOT NULL,
  source TEXT NOT NULL, direction TEXT NOT NULL CHECK(direction IN ('direct','inferred')),
  publish_time TEXT, event_time TEXT, recorded_at TEXT NOT NULL,
  confidence REAL CHECK(confidence IS NULL OR (confidence>=0 AND confidence<=1)), rule_id TEXT,
  trust_state TEXT NOT NULL CHECK(trust_state IN ('verified','corroborated','predicted')),
  state TEXT NOT NULL DEFAULT 'active',
  PRIMARY KEY(fact_id, version));
CREATE TABLE change_history(
  id INTEGER PRIMARY KEY, fact TEXT NOT NULL, old_value TEXT, new_value TEXT,
  cause TEXT NOT NULL, changed_at TEXT NOT NULL);
CREATE TABLE job(
  id INTEGER PRIMARY KEY, source TEXT, mode TEXT, started_at TEXT, finished_at TEXT,
  status TEXT, detail TEXT);
CREATE TABLE candidate_pair(
  left_id TEXT NOT NULL, right_id TEXT NOT NULL, score REAL, PRIMARY KEY(left_id, right_id));
