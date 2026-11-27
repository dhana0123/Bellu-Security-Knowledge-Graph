package graph

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite" // pure Go driver, name "sqlite"
)

// SchemaVersion is the Graph_DB_File schema version written to meta.schema_version.
const SchemaVersion = "1"

// Engine identifies the SQLite engine written to meta.engine.
const Engine = "sqlite-modernc"

const sqliteDDL = `
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE nodes(id TEXT PRIMARY KEY, type TEXT NOT NULL, props TEXT NOT NULL, h TEXT NOT NULL);
CREATE TABLE edges(id TEXT PRIMARY KEY, type TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL,
                   props TEXT NOT NULL, h TEXT NOT NULL);
CREATE INDEX edges_dst ON edges(dst, type);
CREATE INDEX edges_src_type ON edges(src, type);
CREATE INDEX nodes_type ON nodes(type);`

const sqliteHistoryDDL = `
CREATE TABLE history(entity_id TEXT, version INTEGER, event_time TEXT, recorded_at TEXT, state TEXT, payload TEXT);
CREATE INDEX history_entity ON history(entity_id, recorded_at);`

// HistoryRow is one row of the optional history table.
type HistoryRow struct {
	EntityID   string
	Version    int
	EventTime  string
	RecordedAt string
	State      string
	Payload    string
}

// SQLiteSink writes a graph.db file. Output is built in a temp file in the
// target directory and renamed on Commit.
type SQLiteSink struct {
	path string

	tmp     string
	db      *sql.DB
	tx      *sql.Tx
	insNode *sql.Stmt
	insEdge *sql.Stmt
	insHist *sql.Stmt
	history bool
	done    bool
	pending int // writes in the open transaction
	ctx     context.Context
}

// sqliteBatch is the number of rows written per transaction. The temp file is invisible until
// Commit renames it, so intermediate commits keep memory and the rollback journal small without
// weakening the atomic swap.
const sqliteBatch = 20000

var _ Sink = (*SQLiteSink)(nil)

// NewSQLiteSink returns a sink that will produce the file at path.
func NewSQLiteSink(path string) *SQLiteSink { return &SQLiteSink{path: path} }

// Begin creates the temp database, schema and meta rows and opens the transaction.
func (s *SQLiteSink) Begin(ctx context.Context, m SinkMeta) (err error) {
	if s.db != nil || s.done {
		return errors.New("graph: sqlite sink already started")
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(s.path)+".*.tmp")
	if err != nil {
		return err
	}
	s.tmp = f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(s.tmp)
		return err
	}
	defer func() {
		if err != nil {
			_ = s.Abort()
		}
	}()

	db, err := sql.Open("sqlite", s.tmp)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1) // pragmas and the transaction must share one connection
	s.db = db
	if _, err = db.ExecContext(ctx, "PRAGMA journal_mode=DELETE"); err != nil {
		return err
	}
	if _, err = db.ExecContext(ctx, "PRAGMA synchronous=OFF"); err != nil { // temp file; fsynced before rename
		return err
	}
	var engineVersion string
	if err = db.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&engineVersion); err != nil || engineVersion == "" {
		engineVersion = "unknown"
		err = nil
	}
	s.tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err = s.tx.ExecContext(ctx, sqliteDDL); err != nil {
		return err
	}
	s.history = m.HasHistory
	if s.history {
		if _, err = s.tx.ExecContext(ctx, sqliteHistoryDDL); err != nil {
			return err
		}
	}
	if err = s.prepare(ctx); err != nil {
		return err
	}
	s.ctx = ctx

	schema := m.SchemaVersion
	if schema == "" {
		schema = SchemaVersion
	}
	engine := m.Engine
	if engine == "" {
		engine = Engine
	}
	ev := m.EngineVersion
	if ev == "" {
		ev = engineVersion
	}
	eco := append([]string(nil), m.Ecosystems...)
	rows := [][2]string{
		{"schema_version", schema},
		{"level", string(m.Level)},
		{"ecosystems", strings.Join(eco, ",")},
		{"engine", engine},
		{"engine_version", ev},
		{"has_history", strconv.FormatBool(m.HasHistory)},
		{"created_at", m.CreatedAt},
	}
	if m.Token != "" {
		rows = append(rows, [2]string{"projection_token", m.Token})
	}
	for _, r := range rows {
		if _, err = s.tx.ExecContext(ctx, `INSERT INTO meta(key,value) VALUES(?,?)`, r[0], r[1]); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteSink) prepare(ctx context.Context) (err error) {
	if s.insNode, err = s.tx.PrepareContext(ctx, `INSERT INTO nodes(id,type,props,h) VALUES(?,?,?,?)`); err != nil {
		return err
	}
	if s.insEdge, err = s.tx.PrepareContext(ctx, `INSERT INTO edges(id,type,src,dst,props,h) VALUES(?,?,?,?,?,?)`); err != nil {
		return err
	}
	if s.history {
		if s.insHist, err = s.tx.PrepareContext(ctx, `INSERT INTO history(entity_id,version,event_time,recorded_at,state,payload) VALUES(?,?,?,?,?,?)`); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteSink) closeStmts() {
	if s.insNode != nil {
		_ = s.insNode.Close()
	}
	if s.insEdge != nil {
		_ = s.insEdge.Close()
	}
	if s.insHist != nil {
		_ = s.insHist.Close()
	}
	s.insNode, s.insEdge, s.insHist = nil, nil, nil
}

func (s *SQLiteSink) active() error {
	if s.tx == nil || s.done {
		return errors.New("graph: sqlite sink not active")
	}
	return nil
}

// WriteNode inserts a node, rejecting empty and duplicate ids.
func (s *SQLiteSink) WriteNode(n Node) error {
	if err := s.active(); err != nil {
		return err
	}
	if err := CheckID(n.ID); err != nil {
		return err
	}
	props, err := CanonicalProps(n.Props)
	if err != nil {
		return fmt.Errorf("graph: node %s props: %w", n.ID, err)
	}
	h := nodeHashFromProps(n.Type, n.ID, props)
	if _, err = s.insNode.Exec(n.ID, n.Type, string(props), h); err != nil {
		return dupErr(n.ID, err)
	}
	return s.wrote()
}

// dupErr maps a primary key violation to ErrDuplicateID. The table's primary key is the
// uniqueness check, so the sink keeps no in-memory id set.
func dupErr(id string, err error) error {
	if strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "PRIMARY KEY") {
		return fmt.Errorf("%w: %s", ErrDuplicateID, id)
	}
	return err
}

// wrote counts a write and rotates the transaction every sqliteBatch rows.
func (s *SQLiteSink) wrote() error {
	if s.pending++; s.pending < sqliteBatch {
		return nil
	}
	return s.rotate()
}

func (s *SQLiteSink) rotate() error {
	s.closeStmts()
	if err := s.tx.Commit(); err != nil {
		s.tx = nil
		return err
	}
	tx, err := s.db.BeginTx(s.ctx, nil)
	if err != nil {
		s.tx = nil
		return err
	}
	s.tx = tx
	s.pending = 0
	return s.prepare(s.ctx)
}

// WriteEdge inserts an edge, rejecting empty and duplicate ids.
func (s *SQLiteSink) WriteEdge(e Edge) error {
	if err := s.active(); err != nil {
		return err
	}
	if err := CheckID(e.ID); err != nil {
		return err
	}
	props, err := CanonicalProps(e.Props)
	if err != nil {
		return fmt.Errorf("graph: edge %s props: %w", e.ID, err)
	}
	h := edgeHashFromProps(e, props)
	if _, err = s.insEdge.Exec(e.ID, e.Type, e.Src, e.Dst, string(props), h); err != nil {
		return dupErr(e.ID, err)
	}
	return s.wrote()
}

// WriteHistory inserts a history row. It fails unless Begin was given HasHistory.
func (s *SQLiteSink) WriteHistory(r HistoryRow) error {
	if err := s.active(); err != nil {
		return err
	}
	if !s.history {
		return errors.New("graph: history not enabled")
	}
	if _, err := s.insHist.Exec(r.EntityID, r.Version, r.EventTime, r.RecordedAt, r.State, r.Payload); err != nil {
		return err
	}
	return s.wrote()
}

func (s *SQLiteSink) closeDB() error {
	s.closeStmts()
	var err error
	if s.db != nil {
		err = s.db.Close()
	}
	s.db, s.tx = nil, nil
	return err
}

// Commit commits the transaction and atomically renames the temp file to the final path.
func (s *SQLiteSink) Commit() error {
	if err := s.active(); err != nil {
		return err
	}
	s.closeStmts()
	if err := s.tx.Commit(); err != nil {
		_ = s.Abort()
		return err
	}
	s.tx = nil
	if _, err := s.db.Exec("PRAGMA journal_mode=DELETE"); err != nil {
		_ = s.Abort()
		return err
	}
	if err := s.closeDB(); err != nil {
		_ = s.Abort()
		return err
	}
	if err := syncPath(s.tmp); err != nil {
		_ = s.Abort()
		return err
	}
	if err := os.Rename(s.tmp, s.path); err != nil {
		_ = s.Abort()
		return err
	}
	s.done = true
	s.tmp = ""
	if d, err := os.Open(filepath.Dir(s.path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Abort discards the temp file; an existing final file is left untouched.
func (s *SQLiteSink) Abort() error {
	if s.done && s.tmp == "" {
		return nil
	}
	if s.tx != nil {
		_ = s.tx.Rollback()
	}
	_ = s.closeDB()
	s.done = true
	if s.tmp == "" {
		return nil
	}
	tmp := s.tmp
	s.tmp = ""
	var err error
	for _, p := range []string{tmp, tmp + "-journal", tmp + "-wal", tmp + "-shm"} {
		if e := os.Remove(p); e != nil && !os.IsNotExist(e) {
			err = e
		}
	}
	return err
}

func syncPath(p string) error {
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
