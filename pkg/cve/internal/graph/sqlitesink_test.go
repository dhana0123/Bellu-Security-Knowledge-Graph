package graph

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeSample(t *testing.T, path string, hist bool) *SQLiteSink {
	t.Helper()
	s := NewSQLiteSink(path)
	err := s.Begin(context.Background(), SinkMeta{Level: LevelCore, Ecosystems: []string{"npm", "pypi"}, HasHistory: hist, CreatedAt: "2024-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	a := Node{ID: VulnerabilityID("CVE-1"), Type: NodeVulnerability, Props: map[string]any{"b": 1, "a": "x"}}
	b := Node{ID: KEVID("CVE-1"), Type: NodeKEVEntry}
	for _, n := range []Node{a, b} {
		if err := s.WriteNode(n); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.WriteEdge(NewEdge(EdgeListedInKEV, a.ID, b.ID, nil)); err != nil {
		t.Fatal(err)
	}
	return s
}

func count(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSQLiteSinkCommitReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "graph.db")
	s := writeSample(t, path, true)
	if err := s.WriteHistory(HistoryRow{EntityID: "vuln:CVE-1", Version: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("final file visible before commit")
	}
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "graph.db" {
		t.Fatalf("want single file, got %v", entries)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if count(t, db, "nodes") != 2 || count(t, db, "edges") != 1 || count(t, db, "history") != 1 {
		t.Fatal("unexpected counts")
	}
	meta := map[string]string{}
	rows, _ := db.Query("SELECT key,value FROM meta")
	for rows.Next() {
		var k, v string
		_ = rows.Scan(&k, &v)
		meta[k] = v
	}
	rows.Close()
	want := map[string]string{"schema_version": SchemaVersion, "level": "core", "ecosystems": "npm,pypi", "engine": Engine, "has_history": "true", "created_at": "2024-01-01T00:00:00Z"}
	for k, v := range want {
		if meta[k] != v {
			t.Errorf("meta[%s]=%q want %q", k, meta[k], v)
		}
	}
	if meta["engine_version"] == "" {
		t.Error("engine_version empty")
	}
	var props, h string
	if err := db.QueryRow("SELECT props,h FROM nodes WHERE id='vuln:CVE-1'").Scan(&props, &h); err != nil {
		t.Fatal(err)
	}
	wantH, _ := NodeHash(Node{ID: "vuln:CVE-1", Type: NodeVulnerability, Props: map[string]any{"b": 1, "a": "x"}})
	if props != `{"a":"x","b":1}` || h != wantH {
		t.Errorf("props=%s h=%s", props, h)
	}
	var idx int
	_ = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('edges_dst','edges_src_type','nodes_type')").Scan(&idx)
	if idx != 3 {
		t.Errorf("indexes=%d", idx)
	}
}

func TestSQLiteSinkAbortKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "graph.db")
	if err := os.WriteFile(path, []byte("previous"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := writeSample(t, path, false)
	if err := s.Abort(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "previous" {
		t.Fatal("existing file modified")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftovers: %v", entries)
	}
	if err := s.WriteNode(Node{ID: "x"}); err == nil {
		t.Fatal("write after abort should fail")
	}
}

func TestSQLiteSinkRejectsDuplicateAndEmpty(t *testing.T) {
	s := writeSample(t, filepath.Join(t.TempDir(), "graph.db"), false)
	defer s.Abort()
	if err := s.WriteNode(Node{ID: VulnerabilityID("CVE-1"), Type: NodeVulnerability}); !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("want duplicate, got %v", err)
	}
	if err := s.WriteNode(Node{ID: "", Type: NodeVulnerability}); !errors.Is(err, ErrEmptyID) {
		t.Fatalf("want empty, got %v", err)
	}
	if err := s.WriteEdge(Edge{ID: "", Type: EdgeAliasOf}); !errors.Is(err, ErrEmptyID) {
		t.Fatalf("want empty, got %v", err)
	}
	if err := s.WriteHistory(HistoryRow{}); err == nil {
		t.Fatal("history without HasHistory should fail")
	}
}
