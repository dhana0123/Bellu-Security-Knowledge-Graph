package graph

import (
	"database/sql"
	"fmt"
	"os"
)

// IDTracker answers "is this the first time this id was emitted" for shared nodes and edges.
// kind is 'n' for nodes and 'e' for edges.
type IDTracker interface {
	First(kind byte, id string) (bool, error)
	Close() error
}

type memTracker struct{ seen map[string]struct{} }

// NewMemTracker returns a tracker that keeps every id in memory.
func NewMemTracker() IDTracker { return &memTracker{seen: map[string]struct{}{}} }

func (m *memTracker) First(kind byte, id string) (bool, error) {
	k := string(kind) + id
	if _, ok := m.seen[k]; ok {
		return false, nil
	}
	m.seen[k] = struct{}{}
	return true, nil
}

func (m *memTracker) Close() error { return nil }

// diskTracker keeps the ids in a scratch SQLite file so memory does not grow with the number of
// shared nodes. The file is deleted by Close.
type diskTracker struct {
	dir  string
	path string
	db   *sql.DB
	tx   *sql.Tx
	ins  *sql.Stmt
	n    int
}

const diskTrackerBatch = 20000

// NewDiskTracker creates a scratch file under dir ("" means os.TempDir()).
func NewDiskTracker(dir string) (IDTracker, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, ".graph-seen-*.tmp")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	t := &diskTracker{dir: dir, path: path}
	fail := func(err error) (IDTracker, error) {
		_ = t.Close()
		return nil, err
	}
	if t.db, err = sql.Open("sqlite", path); err != nil {
		return fail(err)
	}
	t.db.SetMaxOpenConns(1)
	for _, q := range []string{
		`PRAGMA journal_mode=OFF`, `PRAGMA synchronous=OFF`, `PRAGMA cache_size=-16384`,
		`CREATE TABLE ids(k TEXT PRIMARY KEY) WITHOUT ROWID`,
	} {
		if _, err := t.db.Exec(q); err != nil {
			return fail(err)
		}
	}
	if err := t.begin(); err != nil {
		return fail(err)
	}
	return t, nil
}

func (t *diskTracker) begin() error {
	tx, err := t.db.Begin()
	if err != nil {
		return err
	}
	ins, err := tx.Prepare(`INSERT OR IGNORE INTO ids(k) VALUES(?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	t.tx, t.ins, t.n = tx, ins, 0
	return nil
}

func (t *diskTracker) First(kind byte, id string) (bool, error) {
	if t.ins == nil {
		return false, fmt.Errorf("graph: tracker closed")
	}
	res, err := t.ins.Exec(string(kind) + id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if t.n++; t.n >= diskTrackerBatch {
		if err := t.ins.Close(); err != nil {
			return false, err
		}
		if err := t.tx.Commit(); err != nil {
			return false, err
		}
		if err := t.begin(); err != nil {
			return false, err
		}
	}
	return n == 1, nil
}

func (t *diskTracker) Close() error {
	var first error
	if t.ins != nil {
		_ = t.ins.Close()
		t.ins = nil
	}
	if t.tx != nil {
		_ = t.tx.Rollback()
		t.tx = nil
	}
	if t.db != nil {
		first = t.db.Close()
		t.db = nil
	}
	for _, p := range []string{t.path, t.path + "-journal", t.path + "-wal", t.path + "-shm"} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	return first
}
