-- Task 88.7: change tracking for incremental projection. SQLite only (triggers).
--
-- projection_touch is a change feed. Every write that can alter the graph of a vulnerability
-- records one row; the row's seq (AUTOINCREMENT) orders changes, and re-touching the same
-- subject replaces its row, so the table holds at most one row per subject. A projection stores
-- the highest seq it saw (its watermark) and later re-projects only subjects touched after it.
--
--   kind 'v': a = vulnerability id (the vulnerability itself, its identifiers or its members changed)
--   kind 'r': a = source, b = external_id (a source record, or its severity rows, changed);
--             resolved at projection time through record_vulnerability
--   kind 'k': a = identifier key (a KEV, EPSS, weakness, patch or exploit row keyed by that id);
--             resolved at projection time to every vulnerability that has the key as id,
--             identifier or member record id
--
-- Triggers use DELETE then INSERT rather than INSERT OR REPLACE: a conflict clause on the statement
-- that fires a trigger overrides the clause inside the trigger.
--
-- Unlinked (pending) KEV and EPSS rows never reach the graph and do not touch anything, so the
-- 400k-row EPSS feed does not flood the table.
CREATE TABLE projection_touch(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL, a TEXT NOT NULL, b TEXT NOT NULL DEFAULT '',
  UNIQUE(kind, a, b));
-- epoch identifies this canonical database. A projection state from another database is ignored.
CREATE TABLE projection_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO projection_meta(key, value) VALUES('epoch', lower(hex(randomblob(16))));

CREATE TRIGGER pt_vuln_ins AFTER INSERT ON vulnerability BEGIN
  DELETE FROM projection_touch WHERE kind='v' AND a=NEW.id AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('v', NEW.id); END;
CREATE TRIGGER pt_vuln_del AFTER DELETE ON vulnerability BEGIN
  DELETE FROM projection_touch WHERE kind='v' AND a=OLD.id AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('v', OLD.id); END;

CREATE TRIGGER pt_vi_ins AFTER INSERT ON vulnerability_identifier BEGIN
  DELETE FROM projection_touch WHERE kind='v' AND a=NEW.vulnerability_id AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('v', NEW.vulnerability_id); END;
CREATE TRIGGER pt_vi_del AFTER DELETE ON vulnerability_identifier BEGIN
  DELETE FROM projection_touch WHERE kind='v' AND a=OLD.vulnerability_id AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('v', OLD.vulnerability_id); END;

CREATE TRIGGER pt_rv_ins AFTER INSERT ON record_vulnerability BEGIN
  DELETE FROM projection_touch WHERE kind='v' AND a=NEW.vulnerability_id AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('v', NEW.vulnerability_id); END;
CREATE TRIGGER pt_rv_del AFTER DELETE ON record_vulnerability BEGIN
  DELETE FROM projection_touch WHERE kind='v' AND a=OLD.vulnerability_id AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('v', OLD.vulnerability_id); END;
CREATE TRIGGER pt_rv_upd AFTER UPDATE ON record_vulnerability BEGIN
  DELETE FROM projection_touch WHERE kind='v' AND a=OLD.vulnerability_id AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('v', OLD.vulnerability_id);
  DELETE FROM projection_touch WHERE kind='v' AND a=NEW.vulnerability_id AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('v', NEW.vulnerability_id); END;

CREATE TRIGGER pt_sr_ins AFTER INSERT ON source_record BEGIN
  DELETE FROM projection_touch WHERE kind='r' AND a=NEW.source AND b=NEW.external_id;
  INSERT INTO projection_touch(kind,a,b) VALUES('r', NEW.source, NEW.external_id); END;
CREATE TRIGGER pt_sr_upd AFTER UPDATE ON source_record BEGIN
  DELETE FROM projection_touch WHERE kind='r' AND a=NEW.source AND b=NEW.external_id;
  INSERT INTO projection_touch(kind,a,b) VALUES('r', NEW.source, NEW.external_id); END;
CREATE TRIGGER pt_sr_del AFTER DELETE ON source_record BEGIN
  DELETE FROM projection_touch WHERE kind='r' AND a=OLD.source AND b=OLD.external_id;
  INSERT INTO projection_touch(kind,a,b) VALUES('r', OLD.source, OLD.external_id); END;

CREATE TRIGGER pt_sev_ins AFTER INSERT ON severity_assessment BEGIN
  DELETE FROM projection_touch WHERE kind='r' AND a=NEW.source AND b=NEW.record_id;
  INSERT INTO projection_touch(kind,a,b) VALUES('r', NEW.source, NEW.record_id); END;
CREATE TRIGGER pt_sev_upd AFTER UPDATE ON severity_assessment BEGIN
  DELETE FROM projection_touch WHERE kind='r' AND a=NEW.source AND b=NEW.record_id;
  INSERT INTO projection_touch(kind,a,b) VALUES('r', NEW.source, NEW.record_id); END;
CREATE TRIGGER pt_sev_del AFTER DELETE ON severity_assessment BEGIN
  DELETE FROM projection_touch WHERE kind='r' AND a=OLD.source AND b=OLD.record_id;
  INSERT INTO projection_touch(kind,a,b) VALUES('r', OLD.source, OLD.record_id); END;

CREATE TRIGGER pt_wl_ins AFTER INSERT ON weakness_link BEGIN
  DELETE FROM projection_touch WHERE kind='k' AND a=NEW.vulnerability_id AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('k', NEW.vulnerability_id); END;
CREATE TRIGGER pt_wl_del AFTER DELETE ON weakness_link BEGIN
  DELETE FROM projection_touch WHERE kind='k' AND a=OLD.vulnerability_id AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('k', OLD.vulnerability_id); END;
CREATE TRIGGER pt_patch_ins AFTER INSERT ON patch BEGIN
  DELETE FROM projection_touch WHERE kind='k' AND a=NEW.vulnerability_id AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('k', NEW.vulnerability_id); END;
CREATE TRIGGER pt_patch_upd AFTER UPDATE ON patch BEGIN
  DELETE FROM projection_touch WHERE kind='k' AND a=NEW.vulnerability_id AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('k', NEW.vulnerability_id); END;
CREATE TRIGGER pt_patch_del AFTER DELETE ON patch BEGIN
  DELETE FROM projection_touch WHERE kind='k' AND a=OLD.vulnerability_id AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('k', OLD.vulnerability_id); END;
CREATE TRIGGER pt_exp_ins AFTER INSERT ON exploit_ref BEGIN
  DELETE FROM projection_touch WHERE kind='k' AND a=NEW.vulnerability_id AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('k', NEW.vulnerability_id); END;
CREATE TRIGGER pt_exp_del AFTER DELETE ON exploit_ref BEGIN
  DELETE FROM projection_touch WHERE kind='k' AND a=OLD.vulnerability_id AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('k', OLD.vulnerability_id); END;

-- KEV and EPSS: only linked rows are projected, so only changes that involve a linked row count.
CREATE TRIGGER pt_kev_ins AFTER INSERT ON kev WHEN NEW.status='linked' BEGIN
  DELETE FROM projection_touch WHERE kind='k' AND a=NEW.cve AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('k', NEW.cve); END;
CREATE TRIGGER pt_kev_upd AFTER UPDATE ON kev
WHEN (OLD.status='linked' OR NEW.status='linked')
 AND (OLD.status IS NOT NEW.status OR OLD.json IS NOT NEW.json) BEGIN
  DELETE FROM projection_touch WHERE kind='k' AND a=NEW.cve AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('k', NEW.cve); END;
CREATE TRIGGER pt_kev_del AFTER DELETE ON kev WHEN OLD.status='linked' BEGIN
  DELETE FROM projection_touch WHERE kind='k' AND a=OLD.cve AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('k', OLD.cve); END;

CREATE TRIGGER pt_epss_ins AFTER INSERT ON epss_history WHEN NEW.status='linked' BEGIN
  DELETE FROM projection_touch WHERE kind='k' AND a=NEW.cve AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('k', NEW.cve); END;
CREATE TRIGGER pt_epss_upd AFTER UPDATE ON epss_history
WHEN (OLD.status='linked' OR NEW.status='linked')
 AND (OLD.status IS NOT NEW.status OR OLD.score IS NOT NEW.score OR OLD.percentile IS NOT NEW.percentile) BEGIN
  DELETE FROM projection_touch WHERE kind='k' AND a=NEW.cve AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('k', NEW.cve); END;
CREATE TRIGGER pt_epss_del AFTER DELETE ON epss_history WHEN OLD.status='linked' BEGIN
  DELETE FROM projection_touch WHERE kind='k' AND a=OLD.cve AND b='';
  INSERT INTO projection_touch(kind,a) VALUES('k', OLD.cve); END;
