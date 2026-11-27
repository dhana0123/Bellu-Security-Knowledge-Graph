// Package canonical is the system of record: raw-record index, normalized source records,
// resolution decisions and change events. The graph is a rebuildable projection of it.
//
// The reference implementation uses SQLite so the whole pipeline runs without services.
// The schema is plain SQL and maps 1:1 onto PostgreSQL for the AWS deployment (see
// migrations/pg/).
package canonical

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/rawstore"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/migrations"
	_ "modernc.org/sqlite"
)

// Clock supplies the current time; injected for deterministic tests.
type Clock interface{ Now() time.Time }

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

type Store struct {
	DB    *sql.DB
	clock Clock

	stmtMu sync.Mutex
	stmts  map[string]*sql.Stmt // see QueryCached
}

// SetClock replaces the store clock (nil restores the wall clock).
func (s *Store) SetClock(c Clock) {
	if c == nil {
		c = wallClock{}
	}
	s.clock = c
}

func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: single writer; keeps tx semantics simple
	st := &Store{DB: db, clock: wallClock{}}
	if err := st.Migrate(context.Background(), migrations.FS); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := st.indexMissingRecords(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("index record identifiers: %w", err)
	}
	return st, nil
}

// Migrate applies, in filename order, every not-yet-applied *.sql file in the root of fsys.
// The version is the file name. Each file and its schema_migrations row commit atomically.
func (s *Store) Migrate(ctx context.Context, fsys fs.FS) error {
	if _, err := s.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(
  version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		var n int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version=?`, name).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)`, name, s.now()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Close() error {
	s.closeStmts()
	return s.DB.Close()
}

func ts(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func (s *Store) now() string {
	return s.clock.Now().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

// RecordRaw indexes a stored raw payload.
func (s *Store) RecordRaw(ctx context.Context, source, id, hash, uri string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO raw_record(source,external_id,payload_hash,payload_uri,fetched_at) VALUES(?,?,?,?,?)
ON CONFLICT DO NOTHING`, source, id, hash, uri, s.now())
	return err
}

// UpsertRecord stores a normalized record. It returns changed=false when the content is
// identical to what is stored (idempotent re-ingestion) or when the incoming record is
// older than the stored one.
func (s *Store) UpsertRecord(ctx context.Context, rec *model.Record) (bool, error) {
	o, err := s.UpsertRecordOutcome(ctx, rec)
	return o != Unchanged, err
}

// Outcome tells what an upsert did to the stored record.
type Outcome int

const (
	Unchanged Outcome = iota // identical content, or the incoming record is older
	Inserted                 // first time this (source, id) was stored
	Updated                  // content of an existing record changed
)

// UpsertRecordOutcome is UpsertRecord that also tells new from updated.
func (s *Store) UpsertRecordOutcome(ctx context.Context, rec *model.Record) (Outcome, error) {
	body, err := json.Marshal(rec)
	if err != nil {
		return Unchanged, err
	}
	hash := rawstore.Hash(body)
	aliases, _ := json.Marshal(append([]string{rec.ID}, rec.Aliases...))

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Unchanged, err
	}
	defer tx.Rollback()

	var oldHash string
	var oldMod sql.NullString
	var firstSeen, oldJSON string
	err = tx.QueryRowContext(ctx, `SELECT content_hash, modified, first_seen_at, json FROM source_record WHERE source=? AND external_id=?`,
		rec.Source, rec.ID).Scan(&oldHash, &oldMod, &firstSeen, &oldJSON)
	exists := err == nil
	if err != nil && err != sql.ErrNoRows {
		return Unchanged, err
	}
	if exists {
		if oldHash == hash {
			return Unchanged, nil
		}
		if oldMod.Valid && !rec.Modified.IsZero() {
			if om := model.ParseTime(oldMod.String); om.After(rec.Modified) {
				return Unchanged, nil
			}
		}
	} else {
		firstSeen = s.now()
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO source_record(source,external_id,content_hash,aliases,json,modified,withdrawn,first_seen_at,recorded_at)
VALUES(?,?,?,?,?,?,?,?,?)
ON CONFLICT(source,external_id) DO UPDATE SET content_hash=excluded.content_hash, aliases=excluded.aliases,
 json=excluded.json, modified=excluded.modified, withdrawn=excluded.withdrawn, recorded_at=excluded.recorded_at`,
		rec.Source, rec.ID, hash, string(aliases), string(body), ts(rec.Modified), ts(rec.Withdrawn), firstSeen, s.now())
	if err != nil {
		return Unchanged, err
	}
	if err = s.appendVersionAndHistory(ctx, tx, rec, hash, string(body), oldJSON); err != nil {
		return Unchanged, err
	}
	if err = s.indexRecord(ctx, tx, rec.Source, rec.ID, append([]string{rec.ID}, rec.Aliases...), hash); err != nil {
		return Unchanged, err
	}
	if err = s.storeSeverities(ctx, tx, rec); err != nil {
		return Unchanged, err
	}
	if _, err = s.storeEnrichment(ctx, tx, rec); err != nil {
		return Unchanged, err
	}
	evt := "record_created"
	if exists {
		evt = "record_modified"
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO graph_event(entity_id,event_type,event_time,recorded_at,detail) VALUES(?,?,?,?,?)`,
		rec.Source+":"+rec.ID, evt, ts(rec.Modified), s.now(), hash); err != nil {
		return Unchanged, err
	}
	if !rec.Withdrawn.IsZero() && (!exists || true) {
		if _, err = tx.ExecContext(ctx, `INSERT INTO graph_event(entity_id,event_type,event_time,recorded_at,detail) VALUES(?,?,?,?,?)`,
			rec.Source+":"+rec.ID, "record_withdrawn", ts(rec.Withdrawn), s.now(), hash); err != nil {
			return Unchanged, err
		}
	}
	if err = tx.Commit(); err != nil {
		return Unchanged, err
	}
	if exists {
		return Updated, nil
	}
	return Inserted, nil
}

func (s *Store) UpsertKEV(ctx context.Context, k model.KEV) (bool, error) {
	return s.upsertKEV(ctx, k)
}

func (s *Store) UpsertEPSS(ctx context.Context, e model.EPSS) (bool, error) {
	return s.upsertEPSS(ctx, e)
}

func (s *Store) upsertJSON(ctx context.Context, table, cve string, v any) (bool, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return false, err
	}
	var old string
	err = s.DB.QueryRowContext(ctx, `SELECT json FROM `+table+` WHERE cve=?`, cve).Scan(&old)
	if err == nil && old == string(b) {
		return false, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO `+table+`(cve,json,recorded_at) VALUES(?,?,?)
ON CONFLICT(cve) DO UPDATE SET json=excluded.json, recorded_at=excluded.recorded_at`, cve, string(b), s.now())
	if err != nil {
		return false, err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO graph_event(entity_id,event_type,event_time,recorded_at,detail) VALUES(?,?,?,?,?)`,
		cve, table+"_updated", nil, s.now(), string(b))
	return true, err
}

func (s *Store) GetKEV(ctx context.Context, cve string) (*model.KEV, error) {
	var j string
	err := s.DB.QueryRowContext(ctx, `SELECT json FROM kev WHERE cve=?`, cve).Scan(&j)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var k model.KEV
	return &k, json.Unmarshal([]byte(j), &k)
}

func (s *Store) GetEPSS(ctx context.Context, cve string) (*model.EPSS, error) {
	var j string
	err := s.DB.QueryRowContext(ctx, `SELECT json FROM epss WHERE cve=?`, cve).Scan(&j)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var e model.EPSS
	return &e, json.Unmarshal([]byte(j), &e)
}
