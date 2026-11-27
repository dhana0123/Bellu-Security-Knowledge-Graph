package graph

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCypher(t *testing.T, path string, nodes []Node, edges []Edge) string {
	t.Helper()
	s := NewCypherSink(path)
	if err := s.Begin(context.Background(), SinkMeta{}); err != nil {
		t.Fatal(err)
	}
	for _, e := range edges { // edges first on purpose: nodes must still precede them
		if err := s.WriteEdge(e); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range nodes {
		if err := s.WriteNode(n); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCypherSinkGolden(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "graph.cypher")
	out := runCypher(t, p,
		[]Node{{ID: "vuln:CVE-1", Type: NodeVulnerability, Props: map[string]any{
			"b": 2, "a": "x", "gone": nil, "tags": []any{"q", nil}, "m": map[string]any{"z": 1.5, "y": true}}}},
		[]Edge{{ID: "e1", Type: EdgeAliasOf, Src: "src:a", Dst: "vuln:CVE-1", Props: map[string]any{"k": nil}}})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != len(AllNodeTypes)+2 {
		t.Fatalf("lines=%d", len(lines))
	}
	if lines[0] != "CREATE INDEX ON :Vulnerability(id);" {
		t.Fatal(lines[0])
	}
	wantN := `MERGE (n:Vulnerability {id: "vuln:CVE-1"}) SET n += {a: "x", b: 2, m: {y: true, z: 1.5}, tags: ["q", null]};`
	wantE := `MATCH (a {id: "src:a"}), (b {id: "vuln:CVE-1"}) MERGE (a)-[r:ALIAS_OF {id: "e1"}]->(b) SET r += {};`
	if lines[len(lines)-2] != wantN || lines[len(lines)-1] != wantE {
		t.Fatalf("got:\n%s\n%s", lines[len(lines)-2], lines[len(lines)-1])
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("tmp left behind")
	}
	if _, err := os.Stat(p + ".edges.tmp"); !os.IsNotExist(err) {
		t.Fatal("edge tmp left behind")
	}
}

func TestCypherSinkHostileStrings(t *testing.T) {
	hostile := "\"; MATCH (n) DETACH DELETE n; //"
	out := runCypher(t, filepath.Join(t.TempDir(), "g.cypher"),
		[]Node{{ID: hostile, Type: NodeProduct, Props: map[string]any{
			"v": hostile + "\nline2\r\t\\ \x01 end", "k`ey\n": "x"}}}, nil)
	if got := strings.Count(out, "\n"); got != len(AllNodeTypes)+1 {
		t.Fatalf("injected newline: %d lines", got)
	}
	want := `MERGE (n:Product {id: "\"; MATCH (n) DETACH DELETE n; //"}) SET n += {` + "`k``ey_`" +
		`: "x", v: "\"; MATCH (n) DETACH DELETE n; //\nline2\r\t\\ \u0001 end"};`
	if !strings.Contains(out, want) {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestCypherSinkInvalidLabel(t *testing.T) {
	s := NewCypherSink(filepath.Join(t.TempDir(), "g.cypher"))
	_ = s.Begin(context.Background(), SinkMeta{})
	defer s.Abort()
	if err := s.WriteNode(Node{ID: "a", Type: "X) DETACH DELETE n //"}); err == nil {
		t.Fatal("expected error")
	}
	if err := s.WriteEdge(Edge{ID: "a", Type: "X]-()"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCypherSinkAbort(t *testing.T) {
	p := filepath.Join(t.TempDir(), "g.cypher")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewCypherSink(p)
	_ = s.Begin(context.Background(), SinkMeta{})
	_ = s.WriteNode(Node{ID: "a", Type: NodeVendor})
	if err := s.Abort(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "old" {
		t.Fatal("final file changed")
	}
	for _, x := range []string{".tmp", ".edges.tmp"} {
		if _, err := os.Stat(p + x); !os.IsNotExist(err) {
			t.Fatalf("%s remains", x)
		}
	}
}

func TestCypherSinkDeterministic(t *testing.T) {
	props := map[string]any{}
	for _, k := range []string{"q", "a", "m", "z", "b", "c", "d"} {
		props[k] = map[string]any{"y": 1, "x": []string{"b", "a"}}
	}
	n := []Node{{ID: "a", Type: NodeVendor, Props: props}}
	d := t.TempDir()
	first := runCypher(t, filepath.Join(d, "1"), n, nil)
	for i := 0; i < 20; i++ {
		if runCypher(t, filepath.Join(d, "2"), n, nil) != first {
			t.Fatal("non-deterministic")
		}
	}
}
