-- Task 88.6: resolution at scale. Plain SQL valid on SQLite and PostgreSQL.
-- record_identifier: one row per (record, trimmed identifier), id and aliases. It lets Resolve
-- stream compact id data without reading JSON payloads, find the records that share an
-- identifier, and lets KEV/EPSS linking test "is this CVE known" with an index lookup.
-- Maintained by UpsertRecord; Resolve and Open adopt records that have no rows yet.
CREATE TABLE record_identifier(
  source TEXT NOT NULL, external_id TEXT NOT NULL, value TEXT NOT NULL,
  PRIMARY KEY(source, external_id, value));
CREATE INDEX record_identifier_value ON record_identifier(value);
-- resolve_dirty: records whose content changed since the last resolve (content_hash is the hash
-- at marking time, so a record changed again during a run stays marked).
CREATE TABLE resolve_dirty(
  source TEXT NOT NULL, external_id TEXT NOT NULL, content_hash TEXT NOT NULL,
  PRIMARY KEY(source, external_id));
-- Indexes used to diff and sweep resolution output per component.
CREATE INDEX vulnerability_identifier_v ON vulnerability_identifier(vulnerability_id);
CREATE INDEX entity_resolution_method ON entity_resolution(method, left_id);
CREATE INDEX entity_resolution_right ON entity_resolution(right_id, method);
-- KEV and EPSS rows point at the resolved vulnerability once it exists (NULL while pending).
ALTER TABLE kev ADD COLUMN vulnerability_id TEXT;
ALTER TABLE epss_history ADD COLUMN vulnerability_id TEXT;
CREATE INDEX kev_status ON kev(status);
CREATE INDEX kev_vulnerability ON kev(vulnerability_id);
CREATE INDEX epss_history_status ON epss_history(status);
CREATE INDEX epss_history_vulnerability ON epss_history(vulnerability_id);
