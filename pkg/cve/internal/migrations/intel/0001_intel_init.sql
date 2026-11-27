-- intel.db schema (design: "Intel_Store schema"). SQLite dialect, plain SQL.
--
-- Layers follow canonical fact_version: raw, resolved, inferred, validated.
-- trust_state follows internal/trust. A predicted row can only live in the
-- resolved or inferred layer; the CHECK is a backstop for the Go-level check
-- that returns ErrLayerRejectsPredictions.

CREATE TABLE intel_node(
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  props TEXT NOT NULL DEFAULT '{}',
  layer TEXT NOT NULL CHECK(layer IN ('raw','resolved','inferred','validated')),
  trust_state TEXT NOT NULL CHECK(trust_state IN ('verified','corroborated','predicted')),
  confidence REAL CHECK(confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
  rule_id TEXT NOT NULL DEFAULT '',
  content_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK(trust_state <> 'predicted' OR layer IN ('resolved','inferred')));
CREATE INDEX intel_node_type ON intel_node(type, id);

CREATE TABLE intel_edge(
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  src TEXT NOT NULL,
  dst TEXT NOT NULL,
  props TEXT NOT NULL DEFAULT '{}',
  layer TEXT NOT NULL CHECK(layer IN ('raw','resolved','inferred','validated')),
  trust_state TEXT NOT NULL CHECK(trust_state IN ('verified','corroborated','predicted')),
  confidence REAL CHECK(confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
  rule_id TEXT NOT NULL DEFAULT '',
  content_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK(trust_state <> 'predicted' OR layer IN ('resolved','inferred')));
CREATE INDEX intel_edge_type ON intel_edge(type, id);
CREATE INDEX intel_edge_src ON intel_edge(src, type);
CREATE INDEX intel_edge_dst ON intel_edge(dst, type);

-- owner_id is a node id, an edge id or an attack path id.
CREATE TABLE intel_evidence(
  owner_id TEXT NOT NULL,
  source TEXT NOT NULL,
  source_record_id TEXT NOT NULL DEFAULT '',
  collected_at TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  direct INTEGER NOT NULL DEFAULT 1,
  derived_from TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(owner_id, source, source_record_id));

CREATE TABLE attack_path(
  id TEXT PRIMARY KEY,
  cve_id TEXT NOT NULL,
  steps TEXT NOT NULL,
  layer TEXT NOT NULL DEFAULT 'inferred' CHECK(layer = 'inferred'),
  trust_state TEXT NOT NULL CHECK(trust_state = 'predicted'),
  confidence REAL CHECK(confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
  rule_id TEXT NOT NULL DEFAULT '',
  content_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL);
CREATE INDEX attack_path_cve ON attack_path(cve_id, id);

-- reason: missing-evidence:<node>, cvss-only or chain-limit.
CREATE TABLE path_rejection(
  cve_id TEXT NOT NULL,
  candidate_hash TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(cve_id, candidate_hash, reason));

CREATE TABLE model_version(
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  features TEXT NOT NULL DEFAULT '{}',
  params TEXT NOT NULL DEFAULT '{}',
  train_snapshot TEXT NOT NULL DEFAULT '',
  trained_at TEXT NOT NULL,
  precision REAL NOT NULL DEFAULT 0,
  recall REAL NOT NULL DEFAULT 0,
  precision_at_k REAL NOT NULL DEFAULT 0,
  heldout_size INTEGER NOT NULL DEFAULT 0,
  threshold REAL NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 0 CHECK(active IN (0,1)),
  content_hash TEXT NOT NULL);
-- At most one active model per kind.
CREATE UNIQUE INDEX model_version_active ON model_version(kind) WHERE active = 1;

CREATE TABLE prediction(
  cve_id TEXT NOT NULL,
  product_id TEXT NOT NULL,
  model_version TEXT NOT NULL,
  confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 1),
  top_features TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL CHECK(status IN ('predicted','confirmed','retracted')),
  content_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(cve_id, product_id, model_version));
CREATE INDEX prediction_product ON prediction(product_id, cve_id);

CREATE TABLE coexploit(
  cve_a TEXT NOT NULL,
  cve_b TEXT NOT NULL,
  source TEXT NOT NULL,
  observation_id TEXT NOT NULL,
  PRIMARY KEY(cve_a, cve_b, source, observation_id),
  CHECK(cve_a < cve_b));
CREATE INDEX coexploit_b ON coexploit(cve_b, cve_a);

-- Job queue (task 1.2 builds the queue on job_batch and job_state).
-- status: pending, leased, done, failed. lease_expires_at doubles as the
-- retry backoff time of a pending batch. payload is the batch input.
CREATE TABLE job_batch(
  job TEXT NOT NULL,
  batch_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  lease_owner TEXT NOT NULL DEFAULT '',
  lease_expires_at TEXT NOT NULL DEFAULT '',
  last_error TEXT NOT NULL DEFAULT '',
  stats TEXT NOT NULL DEFAULT '{}',
  payload TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(job, batch_key));
CREATE INDEX job_batch_status ON job_batch(job, status, batch_key);

CREATE TABLE job_state(
  job TEXT PRIMARY KEY,
  watermark TEXT NOT NULL DEFAULT '',
  last_success_at TEXT NOT NULL DEFAULT '',
  last_attempt_at TEXT NOT NULL DEFAULT '',
  cursor TEXT NOT NULL DEFAULT '');

-- Append-only history (guarded by 0002). old and new are NULL when absent.
CREATE TABLE intel_change(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id TEXT NOT NULL,
  field TEXT NOT NULL,
  old TEXT,
  new TEXT,
  changed_at TEXT NOT NULL,
  rule_or_source TEXT NOT NULL DEFAULT '');
CREATE INDEX intel_change_owner ON intel_change(owner_id, seq);

-- Same shape as the canonical table.
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
