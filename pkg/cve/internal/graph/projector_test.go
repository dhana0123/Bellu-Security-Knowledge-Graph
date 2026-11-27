package graph

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC) }

type failNodeSink struct{ Sink }

func (failNodeSink) WriteNode(Node) error { return errors.New("boom") }

func canonFile(t *testing.T) string {
	t.Helper()
	st := buildFixtureStore(t)
	p := filepath.Join(t.TempDir(), "canonical.db")
	if _, err := st.DB.Exec(`VACUUM INTO ?`, p); err != nil {
		t.Fatal(err)
	}
	return p
}

type outPaths struct{ db, jsonl, cypher string }

func newProj(canon, dir string, history bool) (*Projector, outPaths) {
	o := outPaths{filepath.Join(dir, "graph.db"), filepath.Join(dir, "jsonl"), filepath.Join(dir, "graph.cypher")}
	return &Projector{
		CanonicalPath: canon, Clock: fixedClock{}, History: history,
		Sinks: []NamedSink{{"sqlite", NewSQLiteSink(o.db)}, {"jsonl", NewJSONLSink(o.jsonl)}, {"cypher", NewCypherSink(o.cypher)}},
	}, o
}

func sqliteCounts(t *testing.T, path, table string) map[string]int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT type, COUNT(*) FROM " + table + " GROUP BY type")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	m := map[string]int{}
	for rows.Next() {
		var ty string
		var n int
		rows.Scan(&ty, &n)
		m[ty] = n
	}
	return m
}

func TestProjectorSinksAgree(t *testing.T) {
	canon := canonFile(t)
	p, o := newProj(canon, t.TempDir(), false)
	stats, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	nodes, edges := sqliteCounts(t, o.db, "nodes"), sqliteCounts(t, o.db, "edges")
	for _, ty := range AllNodeTypes {
		if nodes[ty] != stats.Nodes[ty] {
			t.Errorf("sqlite node %s: %d vs stats %d", ty, nodes[ty], stats.Nodes[ty])
		}
		if nodes[ty] > 0 {
			if got := countLines(t, filepath.Join(o.jsonl, jsonlNodeFile(ty))) - 1; got != nodes[ty] {
				t.Errorf("jsonl node %s: %d vs %d", ty, got, nodes[ty])
			}
		}
	}
	for _, ty := range AllEdgeTypes {
		if edges[ty] != stats.Edges[ty] {
			t.Errorf("sqlite edge %s: %d vs stats %d", ty, edges[ty], stats.Edges[ty])
		}
		if edges[ty] > 0 {
			if got := countLines(t, filepath.Join(o.jsonl, jsonlEdgeFile(ty))) - 1; got != edges[ty] {
				t.Errorf("jsonl edge %s: %d vs %d", ty, got, edges[ty])
			}
		}
	}
	b, err := os.ReadFile(o.cypher)
	if err != nil {
		t.Fatal(err)
	}
	cy := string(b)
	for _, ty := range AllNodeTypes {
		if got := strings.Count(cy, "MERGE (n:"+ty+" {"); got != nodes[ty] {
			t.Errorf("cypher node %s: %d vs %d", ty, got, nodes[ty])
		}
	}
	for _, ty := range AllEdgeTypes {
		if got := strings.Count(cy, "MERGE (a)-[r:"+ty+" {"); got != edges[ty] {
			t.Errorf("cypher edge %s: %d vs %d", ty, got, edges[ty])
		}
	}
	if len(nodes) == 0 || len(edges) == 0 {
		t.Fatal("empty projection")
	}
}

func countLines(t *testing.T, p string) int {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "\n")
}

func TestProjectorRebuildIdentical(t *testing.T) {
	canon := canonFile(t)
	dir := t.TempDir()
	p, o := newProj(canon, dir, false)
	if _, err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(t.TempDir(), "first.db")
	b, _ := os.ReadFile(o.db)
	os.WriteFile(first, b, 0o644)

	p2, _ := newProj(canon, dir, false)
	if _, err := p2.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := CompareDBs(first, o.db); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if err := os.Remove(o.db); err != nil {
		t.Fatal(err)
	}
	p3, _ := newProj(canon, dir, false)
	if _, err := p3.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := CompareDBs(first, o.db); err != nil {
		t.Fatalf("after delete: %v", err)
	}
}

func TestProjectorUnknownLevelNoFiles(t *testing.T) {
	canon := canonFile(t)
	dir := t.TempDir()
	p, _ := newProj(canon, dir, false)
	p.Policy.Level = "bogus"
	if _, err := p.Run(context.Background()); !errors.Is(err, ErrUnknownLevel) {
		t.Fatalf("err = %v", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("files created: %v", ents)
	}
}

func TestProjectorMissingCanonicalLeavesOutputs(t *testing.T) {
	dir := t.TempDir()
	p, o := newProj(filepath.Join(dir, "nope.db"), dir, false)
	os.WriteFile(o.db, []byte("old"), 0o644)
	if _, err := p.Run(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if b, _ := os.ReadFile(o.db); string(b) != "old" {
		t.Fatal("existing output modified")
	}
	if _, err := os.Stat(o.db + ".tmp"); err == nil {
		t.Fatal("tmp created")
	}
	if _, err := os.Stat(filepath.Join(dir, "nope.db")); err == nil {
		t.Fatal("canonical file created")
	}
}

func TestProjectorFailingSink(t *testing.T) {
	canon := canonFile(t)
	dir := t.TempDir()
	p, o := newProj(canon, dir, false)
	os.WriteFile(o.db, []byte("old-db"), 0o644)
	os.WriteFile(o.cypher, []byte("old-cy"), 0o644)
	p.Sinks[1] = NamedSink{"bad", failNodeSink{p.Sinks[1].Sink}}
	_, err := p.Run(context.Background())
	var se *SinkError
	if !errors.As(err, &se) || se.Sink != "bad" {
		t.Fatalf("err = %v", err)
	}
	for path, want := range map[string]string{o.db: "old-db", o.cypher: "old-cy"} {
		if b, _ := os.ReadFile(path); string(b) != want {
			t.Errorf("%s modified", path)
		}
	}
	if _, err := os.Stat(o.jsonl); err == nil {
		t.Error("jsonl output created")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2 {
		t.Errorf("leftover temp files: %v", ents)
	}
}

func TestProjectorHistory(t *testing.T) {
	canon := canonFile(t)
	p, o := newProj(canon, t.TempDir(), true)
	if _, err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", o.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM history WHERE entity_id LIKE 'src:%' AND payload<>'' AND state<>''`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	src, _ := sql.Open("sqlite", canon)
	defer src.Close()
	var want int
	src.QueryRow(`SELECT COUNT(*) FROM source_record_version`).Scan(&want)
	if n == 0 || n != want {
		t.Fatalf("history rows %d, want %d", n, want)
	}
}
