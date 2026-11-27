CREATE TABLE IF NOT EXISTS raw_record(
  source TEXT NOT NULL, external_id TEXT NOT NULL, payload_hash TEXT NOT NULL,
  payload_uri TEXT NOT NULL, fetched_at TEXT NOT NULL,
  PRIMARY KEY(source, external_id, payload_hash));
CREATE TABLE IF NOT EXISTS source_record(
  source TEXT NOT NULL, external_id TEXT NOT NULL, content_hash TEXT NOT NULL,
  aliases TEXT NOT NULL, json TEXT NOT NULL, modified TEXT, withdrawn TEXT,
  first_seen_at TEXT NOT NULL, recorded_at TEXT NOT NULL,
  PRIMARY KEY(source, external_id));
CREATE TABLE IF NOT EXISTS kev(cve TEXT PRIMARY KEY, json TEXT NOT NULL, recorded_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS epss(cve TEXT PRIMARY KEY, json TEXT NOT NULL, recorded_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS graph_event(
  id INTEGER PRIMARY KEY AUTOINCREMENT, entity_id TEXT NOT NULL, event_type TEXT NOT NULL,
  event_time TEXT, recorded_at TEXT NOT NULL, detail TEXT);
CREATE INDEX IF NOT EXISTS graph_event_entity ON graph_event(entity_id, recorded_at);
CREATE TABLE IF NOT EXISTS vulnerability(id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS vulnerability_identifier(
  value TEXT NOT NULL, vulnerability_id TEXT NOT NULL, PRIMARY KEY(value, vulnerability_id));
CREATE TABLE IF NOT EXISTS record_vulnerability(
  source TEXT NOT NULL, external_id TEXT NOT NULL, vulnerability_id TEXT NOT NULL,
  method TEXT NOT NULL, PRIMARY KEY(source, external_id, vulnerability_id));
CREATE INDEX IF NOT EXISTS record_vulnerability_v ON record_vulnerability(vulnerability_id);
CREATE TABLE IF NOT EXISTS entity_resolution(
  left_id TEXT NOT NULL, right_id TEXT NOT NULL, decision TEXT NOT NULL,
  confidence REAL NOT NULL, method TEXT NOT NULL, recorded_at TEXT NOT NULL,
  PRIMARY KEY(left_id, right_id, method));
