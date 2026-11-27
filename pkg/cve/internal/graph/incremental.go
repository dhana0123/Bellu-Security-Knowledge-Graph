package graph

// Incremental projection (task 88.7).
//
// The canonical store keeps a change feed (projection_touch, migration 0006) written by triggers:
// every change that can alter the graph of a vulnerability records a row with a rising seq. An
// incremental projection stores the highest seq it saw, the watermark, and on the next run
// re-projects only the vulnerabilities touched after it.
//
// State lives in a sidecar file next to graph.db (graph.db.state, SQLite) so the graph.db schema
// stays unchanged:
//
//	state(key, value)   token, epoch (canonical database id), watermark, level, ecosystems
//	owner(vuln, kind, id)  every node ('n') and edge ('e') id each vulnerability produced,
//	                       including shared ones another vulnerability emitted first
//
// graph.db carries meta.projection_token. The two files belong together only if the tokens
// match, so a crash between the two renames, a full non-incremental rebuild, or a hand-replaced
// file all lead to a full rebuild on the next run instead of a wrong graph.
//
// An incremental run copies graph.db and the state file, and for each changed vulnerability:
//
//  1. deletes the nodes and edges it owned that no other vulnerability owns,
//  2. re-projects it (if it still exists) with the same builder a full build uses, skipping shared
//     nodes that are already present, and records its owners.
//
// then updates the watermark, fsyncs and renames graph.db and the state file into place. The
// previous files stay untouched until the renames, so a failure leaves them intact.
//
// Equality with a full build: node and edge ids, edge properties and every vulnerability-private
// node are identical. A shared node (Package, Version, Weakness, SourceRecord, ...) keeps the
// properties of the first vulnerability that emitted it. A full build picks the lowest vulnerability
// id; an incremental run keeps whichever emitter came first historically. Both agree whenever a
// shared node's properties depend only on its id, which holds for every shared type except that
// Package.mapped and Weakness.cwe_id can differ between records that spell the same package or
// CWE differently.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
)

// StatePath returns the state file that belongs to the graph.db at path.
func StatePath(graphPath string) string { return graphPath + ".state" }

const (
	incrBatch = 500 // vulnerabilities per transaction
	ownerDDL  = `
CREATE TABLE state(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE owner(vuln TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL, PRIMARY KEY(vuln, kind, id)) WITHOUT ROWID;`
	ownerIndexDDL = `CREATE INDEX IF NOT EXISTS owner_id ON owner(kind, id)`
)

// testFailpoint, when set by a test, is called at named stages and may return an error to
// simulate a failure there.
var testFailpoint func(stage string) error

func failpoint(stage string) error {
	if testFailpoint != nil {
		return testFailpoint(stage)
	}
	return nil
}

// ErrNoChangeFeed means the canonical store predates migration 0006.
var ErrNoChangeFeed = errors.New("graph: canonical store has no change feed (projection_touch); open it with a write command such as `resolve` once to migrate it")

func newToken() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type feedPosition struct {
	epoch string
	seq   int64
}

// readFeed returns the canonical database id and the newest change seq.
func readFeed(ctx context.Context, store *canonical.Store) (feedPosition, error) {
	var n int
	if err := store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('projection_touch','projection_meta')`).Scan(&n); err != nil {
		return feedPosition{}, err
	}
	if n != 2 {
		return feedPosition{}, ErrNoChangeFeed
	}
	var f feedPosition
	if err := store.DB.QueryRowContext(ctx, `SELECT value FROM projection_meta WHERE key='epoch'`).Scan(&f.epoch); err != nil {
		return f, err
	}
	var seq sql.NullInt64
	if err := store.DB.QueryRowContext(ctx, `SELECT seq FROM sqlite_sequence WHERE name='projection_touch'`).Scan(&seq); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return f, err
	}
	f.seq = seq.Int64
	return f, nil
}

func (p *Projector) incrementalSink() (*SQLiteSink, error) {
	if len(p.Sinks) != 1 {
		return nil, errors.New("graph: incremental projection supports exactly one sink, sqlite")
	}
	sq, ok := p.Sinks[0].Sink.(*SQLiteSink)
	if !ok {
		return nil, errors.New("graph: incremental projection supports the sqlite sink only; use a full build for jsonl and cypher")
	}
	if p.History {
		return nil, errors.New("graph: incremental projection does not support --history")
	}
	return sq, nil
}

// prior is the validated previous projection.
type prior struct {
	watermark int64
}

func policyKey(pol Policy) (string, string) {
	return string(pol.Level), strings.Join(pol.Ecosystems, ",")
}

// loadPrior returns the previous projection, or a reason why a full build is needed.
func (p *Projector) loadPrior(graphPath string, feed feedPosition) (*prior, string) {
	statePath := StatePath(graphPath)
	if _, err := os.Stat(graphPath); err != nil {
		return nil, "no previous graph.db"
	}
	if _, err := os.Stat(statePath); err != nil {
		return nil, "no projection state file"
	}
	sdb, err := sql.Open("sqlite", roDSN(statePath))
	if err != nil {
		return nil, "state file unreadable"
	}
	defer sdb.Close()
	st := map[string]string{}
	rows, err := sdb.Query(`SELECT key, value FROM state`)
	if err != nil {
		return nil, "state file unreadable"
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return nil, "state file unreadable"
		}
		st[k] = v
	}
	rows.Close()
	gdb, err := sql.Open("sqlite", roDSN(graphPath))
	if err != nil {
		return nil, "previous graph.db unreadable"
	}
	defer gdb.Close()
	meta := map[string]string{}
	mrows, err := gdb.Query(`SELECT key, value FROM meta`)
	if err != nil {
		return nil, "previous graph.db unreadable"
	}
	for mrows.Next() {
		var k, v string
		if err := mrows.Scan(&k, &v); err != nil {
			mrows.Close()
			return nil, "previous graph.db unreadable"
		}
		meta[k] = v
	}
	mrows.Close()
	level, eco := policyKey(p.Policy)
	switch {
	case st["token"] == "" || st["token"] != meta["projection_token"]:
		return nil, "graph.db and state file do not belong together"
	case st["epoch"] != feed.epoch:
		return nil, "canonical store changed identity"
	case st["level"] != level || st["ecosystems"] != eco:
		return nil, "level or ecosystems changed"
	case meta["schema_version"] != SchemaVersion:
		return nil, "graph schema version changed"
	}
	w, err := strconv.ParseInt(st["watermark"], 10, 64)
	if err != nil || w > feed.seq {
		return nil, "watermark is ahead of the change feed"
	}
	return &prior{watermark: w}, ""
}

func (p *Projector) runIncremental(ctx context.Context, store *canonical.Store, clk Clock) (Stats, error) {
	sq, err := p.incrementalSink()
	if err != nil {
		return Stats{}, err
	}
	feed, err := readFeed(ctx, store) // read before any canonical data: later changes are picked up next run
	if err != nil {
		return Stats{}, err
	}
	pr, reason := p.loadPrior(sq.path, feed)
	if pr == nil {
		return p.incrementalFull(ctx, store, clk, sq, feed, reason)
	}
	return p.incrementalApply(ctx, store, clk, sq, feed, pr)
}

// ---- full build that records the state ----

func (p *Projector) incrementalFull(ctx context.Context, store *canonical.Store, clk Clock, sq *SQLiteSink, feed feedPosition, reason string) (Stats, error) {
	token, err := newToken()
	if err != nil {
		return Stats{}, err
	}
	dir := filepath.Dir(sq.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Stats{}, err
	}
	tmpState, err := tempFile(dir, "."+filepath.Base(StatePath(sq.path)))
	if err != nil {
		return Stats{}, err
	}
	cleanup := func() {
		for _, s := range []string{"", "-journal"} {
			_ = os.Remove(tmpState + s)
		}
	}
	sdb, err := sql.Open("sqlite", tmpState)
	if err != nil {
		cleanup()
		return Stats{}, err
	}
	sdb.SetMaxOpenConns(1)
	var tx *sql.Tx
	var ins *sql.Stmt
	closeState := func() {
		if ins != nil {
			_ = ins.Close()
			ins = nil
		}
		if tx != nil {
			_ = tx.Rollback()
			tx = nil
		}
		_ = sdb.Close()
	}
	pending := 0
	begin := func() error {
		var err error
		if tx, err = sdb.BeginTx(ctx, nil); err != nil {
			return err
		}
		ins, err = tx.PrepareContext(ctx, `INSERT OR IGNORE INTO owner(vuln,kind,id) VALUES(?,?,?)`)
		pending = 0
		return err
	}
	for _, q := range []string{`PRAGMA journal_mode=DELETE`, `PRAGMA synchronous=OFF`, ownerDDL} {
		if _, err := sdb.ExecContext(ctx, q); err != nil {
			closeState()
			cleanup()
			return Stats{}, err
		}
	}
	if err := begin(); err != nil {
		closeState()
		cleanup()
		return Stats{}, err
	}
	hooks := &fullHooks{
		token: token,
		owner: func(vuln string, kind byte, id string) error {
			if _, err := ins.Exec(vuln, string(kind), id); err != nil {
				return err
			}
			if pending++; pending >= 50000 {
				_ = ins.Close()
				if err := tx.Commit(); err != nil {
					return err
				}
				return begin()
			}
			return nil
		},
		before: func() error {
			if err := failpoint("full-before-commit"); err != nil {
				return err
			}
			level, eco := policyKey(p.Policy)
			for k, v := range map[string]string{"token": token, "epoch": feed.epoch,
				"watermark": strconv.FormatInt(feed.seq, 10), "level": level, "ecosystems": eco} {
				if _, err := tx.ExecContext(ctx, `INSERT INTO state(key,value) VALUES(?,?)`, k, v); err != nil {
					return err
				}
			}
			_ = ins.Close()
			ins = nil
			if err := tx.Commit(); err != nil {
				return err
			}
			tx = nil
			if _, err := sdb.ExecContext(ctx, ownerIndexDDL); err != nil {
				return err
			}
			if err := sdb.Close(); err != nil {
				return err
			}
			return syncPath(tmpState)
		},
		after: func() error {
			// graph.db is in place. If this rename fails the tokens differ and the next run rebuilds.
			return os.Rename(tmpState, StatePath(sq.path))
		},
		abort: func() {
			closeState()
			cleanup()
		},
	}
	st, err := p.runStreaming(ctx, store, clk, hooks)
	if err != nil {
		return Stats{}, err
	}
	st.Watermark, st.FullReason = feed.seq, reason
	return st, nil
}

func tempFile(dir, pattern string) (string, error) {
	f, err := os.CreateTemp(dir, pattern+".*.tmp")
	if err != nil {
		return "", err
	}
	name := f.Name()
	return name, f.Close()
}

// ---- incremental apply ----

// changedQuery lists the vulnerabilities touched after a watermark. Every ? is the watermark.
const changedQuery = `
SELECT a FROM projection_touch WHERE seq>? AND kind='v'
UNION SELECT rv.vulnerability_id FROM projection_touch t JOIN record_vulnerability rv ON rv.source=t.a AND rv.external_id=t.b WHERE t.seq>? AND t.kind='r'
UNION SELECT v.id FROM projection_touch t JOIN vulnerability v ON v.id=t.a WHERE t.seq>? AND t.kind='k'
UNION SELECT vi.vulnerability_id FROM projection_touch t JOIN vulnerability_identifier vi ON vi.value=t.a WHERE t.seq>? AND t.kind='k'
UNION SELECT rv.vulnerability_id FROM projection_touch t JOIN record_identifier ri ON ri.value=t.a
  JOIN record_vulnerability rv ON rv.source=ri.source AND rv.external_id=ri.external_id WHERE t.seq>? AND t.kind='k'`

func (p *Projector) incrementalApply(ctx context.Context, store *canonical.Store, clk Clock, sq *SQLiteSink, feed feedPosition, pr *prior) (Stats, error) {
	statePath := StatePath(sq.path)
	// Nothing touched since the watermark: the graph is current.
	if feed.seq == pr.watermark {
		return p.graphStats(ctx, store, sq.path, "unchanged", 0, feed.seq)
	}
	dir := filepath.Dir(sq.path)
	tmpGraph, err := tempFile(dir, "."+filepath.Base(sq.path))
	if err != nil {
		return Stats{}, err
	}
	tmpState, err := tempFile(dir, "."+filepath.Base(statePath))
	if err != nil {
		_ = os.Remove(tmpGraph)
		return Stats{}, err
	}
	var gdb *sql.DB
	done := false
	defer func() {
		if done {
			return
		}
		if gdb != nil {
			_ = gdb.Close()
		}
		for _, f := range []string{tmpGraph, tmpState} {
			_ = os.Remove(f)
			_ = os.Remove(f + "-journal")
		}
	}()
	if err := copyFile(sq.path, tmpGraph); err != nil {
		return Stats{}, err
	}
	if err := copyFile(statePath, tmpState); err != nil {
		return Stats{}, err
	}
	gdb, err = sql.Open("sqlite", tmpGraph)
	if err != nil {
		return Stats{}, err
	}
	gdb.SetMaxOpenConns(1) // ATTACH, pragmas and the transaction share one connection
	for _, q := range []string{`PRAGMA journal_mode=DELETE`, `PRAGMA synchronous=OFF`,
		`ATTACH DATABASE '` + strings.ReplaceAll(tmpState, "'", "''") + `' AS s`,
		`CREATE TABLE s.changed(id TEXT PRIMARY KEY) WITHOUT ROWID`} {
		if _, err := gdb.ExecContext(ctx, q); err != nil {
			return Stats{}, fmt.Errorf("graph: incremental setup: %w", err)
		}
	}
	// 1. collect the changed vulnerability ids on disk.
	n, err := collectChanged(ctx, store, gdb, pr.watermark)
	if err != nil {
		return Stats{}, err
	}
	if n == 0 {
		// Touched subjects that map to no vulnerability (for example records not yet resolved).
		done = true
		_ = gdb.Close()
		_ = os.Remove(tmpGraph)
		_ = os.Remove(tmpState)
		if err := setWatermark(ctx, statePath, feed.seq); err != nil {
			return Stats{}, err
		}
		return p.graphStats(ctx, store, sq.path, "unchanged", 0, feed.seq)
	}
	// 2. apply in batches.
	if err := p.applyChanged(ctx, store, gdb); err != nil {
		return Stats{}, err
	}
	// 3. new token and watermark, then swap.
	token, err := newToken()
	if err != nil {
		return Stats{}, err
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT OR REPLACE INTO s.state(key,value) VALUES('token',?)`, []any{token}},
		{`INSERT OR REPLACE INTO s.state(key,value) VALUES('watermark',?)`, []any{strconv.FormatInt(feed.seq, 10)}},
		{`UPDATE meta SET value=? WHERE key='projection_token'`, []any{token}},
		{`UPDATE meta SET value=? WHERE key='created_at'`, []any{clk.Now().UTC().Format("2006-01-02T15:04:05Z")}},
		{`DROP TABLE s.changed`, nil},
	} {
		if _, err := gdb.ExecContext(ctx, q.sql, q.args...); err != nil {
			return Stats{}, err
		}
	}
	if err := gdb.Close(); err != nil {
		return Stats{}, err
	}
	gdb = nil
	for _, f := range []string{tmpGraph, tmpState} {
		if err := syncPath(f); err != nil {
			return Stats{}, err
		}
	}
	done = true // the temp files are renamed (or removed below) from here on
	if err := os.Rename(tmpGraph, sq.path); err != nil {
		_ = os.Remove(tmpGraph)
		_ = os.Remove(tmpState)
		return Stats{}, err
	}
	if err := os.Rename(tmpState, statePath); err != nil {
		_ = os.Remove(tmpState)
		return Stats{}, err // tokens differ: the next run rebuilds
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return p.graphStats(ctx, store, sq.path, "incremental", n, feed.seq)
}

// collectChanged writes the ids touched after watermark into s.changed and returns their number.
func collectChanged(ctx context.Context, store *canonical.Store, gdb *sql.DB, watermark int64) (int, error) {
	rows, err := store.DB.QueryContext(ctx, changedQuery, watermark, watermark, watermark, watermark, watermark)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	tx, err := gdb.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO s.changed(id) VALUES(?)`)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	n := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		if _, err := stmt.ExecContext(ctx, id); err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		n++
	}
	if err := rows.Err(); err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	_ = stmt.Close()
	return n, tx.Commit()
}

// graphTracker answers "is this shared id new" from the graph being edited.
type graphTracker struct {
	node, edge *sql.Stmt
}

func (g *graphTracker) First(kind byte, id string) (bool, error) {
	st := g.node
	if kind == 'e' {
		st = g.edge
	}
	var one int
	err := st.QueryRow(id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	return false, err
}

func (g *graphTracker) Close() error { return nil }

func (p *Projector) applyChanged(ctx context.Context, store *canonical.Store, gdb *sql.DB) error {
	last := ""
	for {
		ids, err := pageChanged(ctx, gdb, last, incrBatch)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		if err := p.applyBatch(ctx, store, gdb, ids); err != nil {
			return err
		}
		if err := failpoint("apply-batch"); err != nil {
			return err
		}
		last = ids[len(ids)-1]
	}
}

func pageChanged(ctx context.Context, gdb *sql.DB, after string, n int) ([]string, error) {
	rows, err := gdb.QueryContext(ctx, `SELECT id FROM s.changed WHERE id>? ORDER BY id LIMIT ?`, after, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (p *Projector) applyBatch(ctx context.Context, store *canonical.Store, gdb *sql.DB, ids []string) (err error) {
	tx, err := gdb.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	prep := func(q string) (*sql.Stmt, error) { return tx.PrepareContext(ctx, q) }
	var delNode, delEdge, delOwner, insNode, insEdge, insOwner, hasNode, hasEdge *sql.Stmt
	for _, x := range []struct {
		dst **sql.Stmt
		q   string
	}{
		{&delNode, `DELETE FROM nodes WHERE id IN (SELECT id FROM s.owner WHERE vuln=?1 AND kind='n')
 AND NOT EXISTS (SELECT 1 FROM s.owner o WHERE o.kind='n' AND o.id=nodes.id AND o.vuln<>?1)`},
		{&delEdge, `DELETE FROM edges WHERE id IN (SELECT id FROM s.owner WHERE vuln=?1 AND kind='e')
 AND NOT EXISTS (SELECT 1 FROM s.owner o WHERE o.kind='e' AND o.id=edges.id AND o.vuln<>?1)`},
		{&delOwner, `DELETE FROM s.owner WHERE vuln=?`},
		{&insNode, `INSERT INTO nodes(id,type,props,h) VALUES(?,?,?,?)`},
		{&insEdge, `INSERT INTO edges(id,type,src,dst,props,h) VALUES(?,?,?,?,?,?)`},
		{&insOwner, `INSERT OR IGNORE INTO s.owner(vuln,kind,id) VALUES(?,?,?)`},
		{&hasNode, `SELECT 1 FROM nodes WHERE id=?`},
		{&hasEdge, `SELECT 1 FROM edges WHERE id=?`},
	} {
		if *x.dst, err = prep(x.q); err != nil {
			return err
		}
		defer (*x.dst).Close()
	}
	emitNode := func(n Node) error {
		props, err := CanonicalProps(n.Props)
		if err != nil {
			return fmt.Errorf("graph: node %s props: %w", n.ID, err)
		}
		_, err = insNode.Exec(n.ID, n.Type, string(props), nodeHashFromProps(n.Type, n.ID, props))
		return err
	}
	emitEdge := func(e Edge) error {
		props, err := CanonicalProps(e.Props)
		if err != nil {
			return fmt.Errorf("graph: edge %s props: %w", e.ID, err)
		}
		_, err = insEdge.Exec(e.ID, e.Type, e.Src, e.Dst, string(props), edgeHashFromProps(e, props))
		return err
	}
	var scratch Stats
	scratch.Nodes, scratch.Edges = map[string]int{}, map[string]int{}
	b, err := newBuilder(store, p.Policy, BuildOptions{
		Seen: &graphTracker{node: hasNode, edge: hasEdge},
		Owner: func(vuln string, kind byte, id string) error {
			_, err := insOwner.Exec(vuln, string(kind), id)
			return err
		},
	}, emitNode, emitEdge, &scratch)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err = ctx.Err(); err != nil {
			return err
		}
		if _, err = delNode.Exec(id); err != nil {
			return err
		}
		if _, err = delEdge.Exec(id); err != nil {
			return err
		}
		if _, err = delOwner.Exec(id); err != nil {
			return err
		}
		var exists int
		qerr := store.DB.QueryRowContext(ctx, `SELECT 1 FROM vulnerability WHERE id=?`, id).Scan(&exists)
		if errors.Is(qerr, sql.ErrNoRows) {
			continue // merged away or deleted: its graph elements are gone
		}
		if qerr != nil {
			err = qerr
			return err
		}
		if err = b.vulnerability(ctx, id); err != nil {
			return fmt.Errorf("graph: vulnerability %s: %w", id, err)
		}
	}
	return tx.Commit()
}

// graphStats counts the finished graph.db.
func (p *Projector) graphStats(ctx context.Context, store *canonical.Store, path, mode string, changed int, watermark int64) (Stats, error) {
	db, err := sql.Open("sqlite", roDSN(path))
	if err != nil {
		return Stats{}, err
	}
	defer db.Close()
	st := Stats{Nodes: map[string]int{}, Edges: map[string]int{}, Mode: mode, Changed: changed, Watermark: watermark}
	for _, x := range []struct {
		q string
		m map[string]int
	}{{`SELECT type, COUNT(*) FROM nodes GROUP BY type`, st.Nodes}, {`SELECT type, COUNT(*) FROM edges GROUP BY type`, st.Edges}} {
		rows, err := db.QueryContext(ctx, x.q)
		if err != nil {
			return st, err
		}
		for rows.Next() {
			var t string
			var c int
			if err := rows.Scan(&t, &c); err != nil {
				rows.Close()
				return st, err
			}
			x.m[t] = c
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return st, err
		}
		rows.Close()
	}
	st.Vulnerabilities = st.Nodes[NodeVulnerability]
	var total int
	if err := store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerability`).Scan(&total); err != nil {
		return st, err
	}
	st.SkippedVulnerabilities = total - st.Vulnerabilities
	return st, nil
}

func setWatermark(ctx context.Context, statePath string, seq int64) error {
	db, err := sql.Open("sqlite", statePath)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.ExecContext(ctx, `INSERT OR REPLACE INTO state(key,value) VALUES('watermark',?)`, strconv.FormatInt(seq, 10))
	return err
}

func roDSN(path string) string {
	u := url.URL{Scheme: "file", Opaque: (&url.URL{Path: path}).EscapedPath(), RawQuery: "mode=ro"}
	return u.String()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
