package graph

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

var jctx = context.Background()
var jmeta = SinkMeta{Level: LevelComplete, CreatedAt: "2024-01-01T00:00:00Z"}

func writeAll(t testing.TB, s Sink, nodes []Node, edges []Edge) {
	t.Helper()
	if err := s.Begin(jctx, jmeta); err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if err := s.WriteNode(n); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range edges {
		if err := s.WriteEdge(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
}

func sampleGraph() ([]Node, []Edge) {
	a := Node{ID: VulnerabilityID("CVE-1"), Type: NodeVulnerability, Props: map[string]any{"n": 3, "f": 1.5, "s": "a<b>&\"\n\u00e9", "l": []any{1, nil, "x"}, "m": map[string]any{"z": true}}}
	b := Node{ID: KEVID("CVE-1"), Type: NodeKEVEntry}
	return []Node{a, b}, []Edge{NewEdge(EdgeListedInKEV, a.ID, b.ID, map[string]any{"w": 2})}
}

func TestJSONLSinkLayout(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "export")
	nodes, edges := sampleGraph()
	writeAll(t, NewJSONLSink(dir), nodes, edges)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := len(AllNodeTypes) + len(AllEdgeTypes); len(entries) != want {
		t.Fatalf("files = %d, want %d", len(entries), want)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "nodes-Package.jsonl"))
	if string(b) != `{"schema_version":"1","kind":"nodes","type":"Package"}`+"\n" {
		t.Fatalf("empty-type file: %q", b)
	}
	b, _ = os.ReadFile(filepath.Join(dir, "edges-LISTED_IN_KEV.jsonl"))
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[1], `"src":"vuln:CVE-1"`) || !strings.Contains(lines[1], `"dst":"kev:CVE-1"`) {
		t.Fatalf("edge file: %q", b)
	}
	if _, err := os.Stat(dir + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp dir left behind")
	}
}

func TestJSONLSinkAbortAndErrorsLeaveNothing(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "export")
	s := NewJSONLSink(dir)
	if err := s.Begin(jctx, jmeta); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteNode(Node{ID: "x", Type: "Bogus"}); err == nil {
		t.Fatal("unknown type accepted")
	}
	if err := s.WriteNode(Node{ID: "a", Type: NodePackage}); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteNode(Node{ID: "a", Type: NodePackage}); !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("dup err = %v", err)
	}
	if err := s.Abort(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatalf("leftovers: %v", entries)
	}
}

func TestJSONLSinkReplacesExisting(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "export")
	nodes, edges := sampleGraph()
	writeAll(t, NewJSONLSink(dir), nodes, edges)
	writeAll(t, NewJSONLSink(dir), nil, nil)
	b, _ := os.ReadFile(filepath.Join(dir, "nodes-Vulnerability.jsonl"))
	if strings.Count(string(b), "\n") != 1 {
		t.Fatalf("old content survived: %q", b)
	}
}

func TestLoadJSONLRoundTrip(t *testing.T) {
	root := t.TempDir()
	nodes, edges := sampleGraph()
	writeAll(t, NewJSONLSink(filepath.Join(root, "x")), nodes, edges)
	writeAll(t, NewSQLiteSink(filepath.Join(root, "direct.db")), nodes, edges)
	if err := LoadJSONL(jctx, filepath.Join(root, "x"), filepath.Join(root, "loaded.db"), jmeta); err != nil {
		t.Fatal(err)
	}
	if err := CompareDBs(filepath.Join(root, "direct.db"), filepath.Join(root, "loaded.db")); err != nil {
		t.Fatal(err)
	}
}

func TestLoadJSONLRejections(t *testing.T) {
	nodes, edges := sampleGraph()
	hdr := `{"schema_version":"1","kind":"nodes","type":"Vulnerability"}` + "\n"
	cases := []struct {
		name, file, content string
		line                int
		check               func(error) bool
	}{
		{"bad schema", "nodes-Vulnerability.jsonl", `{"schema_version":"2","kind":"nodes","type":"Vulnerability"}` + "\n", 1, func(e error) bool { return errors.Is(e, ErrUnsupportedSchema) }},
		{"malformed json", "nodes-Vulnerability.jsonl", hdr + `{"id":"a",` + "\n", 2, nil},
		{"unknown field", "nodes-Vulnerability.jsonl", hdr + `{"id":"a","type":"Vulnerability","props":{},"zz":1}` + "\n", 2, nil},
		{"type mismatch", "nodes-Vulnerability.jsonl", hdr + `{"id":"a","type":"Package","props":{}}` + "\n", 2, nil},
		{"empty id", "nodes-Vulnerability.jsonl", hdr + `{"id":"","type":"Vulnerability","props":{}}` + "\n", 2, func(e error) bool { return errors.Is(e, ErrEmptyID) }},
		{"duplicate id", "nodes-Vulnerability.jsonl", hdr + strings.Repeat(`{"id":"a","type":"Vulnerability","props":{}}`+"\n", 2), 3, func(e error) bool { return errors.Is(e, ErrDuplicateID) }},
		{"unknown type file", "nodes-Bogus.jsonl", `{"schema_version":"1","kind":"nodes","type":"Bogus"}` + "\n", 0, nil},
		{"empty file", "nodes-Package.jsonl", "", 0, nil},
		{"header kind mismatch", "nodes-Package.jsonl", `{"schema_version":"1","kind":"edges","type":"Package"}` + "\n", 1, nil},
		{"missing endpoint", "edges-ALIAS_OF.jsonl", `{"schema_version":"1","kind":"edges","type":"ALIAS_OF"}` + "\n" + `{"id":"e","type":"ALIAS_OF","src":"nope","dst":"vuln:CVE-1","props":{}}` + "\n", 2, func(e error) bool { return errors.Is(e, ErrMissingNode) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "x")
			writeAll(t, NewJSONLSink(dir), nodes, edges)
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, "out", "graph.db")
			err := LoadJSONL(jctx, dir, target, jmeta)
			var le *LoadError
			if !errors.As(err, &le) {
				t.Fatalf("err = %v, want *LoadError", err)
			}
			if le.File != tc.file || le.Line != tc.line {
				t.Fatalf("got %s:%d, want %s:%d (%v)", le.File, le.Line, tc.file, tc.line, le.Err)
			}
			if tc.check != nil && !tc.check(err) {
				t.Fatalf("unexpected cause: %v", err)
			}
			if entries, _ := os.ReadDir(filepath.Dir(target)); len(entries) != 0 {
				t.Fatalf("target dir not empty: %v", entries)
			}
		})
	}
}

func TestLoadJSONLMissingDir(t *testing.T) {
	var le *LoadError
	if err := LoadJSONL(jctx, filepath.Join(t.TempDir(), "none"), filepath.Join(t.TempDir(), "g.db"), jmeta); !errors.As(err, &le) {
		t.Fatalf("err = %v", err)
	}
}

func propValue() *rapid.Generator[any] {
	return rapid.OneOf(
		rapid.Just[any](nil),
		rapid.Map(rapid.Bool(), func(b bool) any { return b }),
		rapid.Map(rapid.Int64(), func(i int64) any { return i }),
		rapid.Map(rapid.Float64(), func(f float64) any { return f }),
		rapid.Map(rapid.String(), func(s string) any { return s }),
		rapid.Map(rapid.SliceOfN(rapid.String(), 0, 3), func(s []string) any { return s }),
	)
}

func genGraph(t *rapid.T) ([]Node, []Edge) { return genGraphMin(t, 0) }

// genGraphMin generates a graph with at least minNodes nodes.
func genGraphMin(t *rapid.T, minNodes int) ([]Node, []Edge) {
	props := rapid.MapOfN(rapid.String(), propValue(), 0, 4)
	nn := rapid.IntRange(minNodes, 12).Draw(t, "nn")
	var nodes []Node
	for i := 0; i < nn; i++ {
		nodes = append(nodes, Node{ID: fmt.Sprintf("n%d", i), Type: rapid.SampledFrom(AllNodeTypes).Draw(t, "nt"), Props: props.Draw(t, "np")})
	}
	var edges []Edge
	if nn > 0 {
		ne := rapid.IntRange(0, 12).Draw(t, "ne")
		for i := 0; i < ne; i++ {
			edges = append(edges, Edge{ID: fmt.Sprintf("e%d", i), Type: rapid.SampledFrom(AllEdgeTypes).Draw(t, "et"),
				Src: nodes[rapid.IntRange(0, nn-1).Draw(t, "s")].ID, Dst: nodes[rapid.IntRange(0, nn-1).Draw(t, "d")].ID, Props: props.Draw(t, "ep")})
		}
	}
	return nodes, edges
}

// Feature: bellu-security-knowledge-graph, Property 30: JSONL round trip and malformed-input rejection
// **Validates: Requirements 14.1, 14.2, 14.3, 14.4, 14.5**
func TestPropertyJSONLRoundTrip(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		root := t.TempDir()
		nodes, edges := genGraph(rt)
		writeAll(t, NewJSONLSink(filepath.Join(root, "x")), nodes, edges)
		writeAll(t, NewSQLiteSink(filepath.Join(root, "direct.db")), nodes, edges)
		if err := LoadJSONL(jctx, filepath.Join(root, "x"), filepath.Join(root, "loaded.db"), jmeta); err != nil {
			rt.Fatal(err)
		}
		if err := CompareDBs(filepath.Join(root, "direct.db"), filepath.Join(root, "loaded.db")); err != nil {
			rt.Fatal(err)
		}
	})
}

// Corrupting any one record line makes the load fail naming that file and line.
func TestPropertyJSONLCorruptLineRejected(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		root := t.TempDir()
		nodes, edges := genGraphMin(rt, 1)
		dir := filepath.Join(root, "x")
		writeAll(t, NewJSONLSink(dir), nodes, edges)
		files, _ := os.ReadDir(dir)
		var cands []string
		for _, f := range files {
			b, _ := os.ReadFile(filepath.Join(dir, f.Name()))
			if strings.Count(string(b), "\n") > 1 {
				cands = append(cands, f.Name())
			}
		}
		if len(cands) == 0 {
			rt.Fatal("a graph with a node must produce a multi-line file")
		}
		name := rapid.SampledFrom(cands).Draw(rt, "file")
		b, _ := os.ReadFile(filepath.Join(dir, name))
		lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
		li := rapid.IntRange(1, len(lines)-1).Draw(rt, "line")
		lines[li] = lines[li][:len(lines[li])/2]
		if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			rt.Fatal(err)
		}
		target := filepath.Join(root, "t", "graph.db")
		err := LoadJSONL(jctx, dir, target, jmeta)
		var le *LoadError
		if !errors.As(err, &le) || le.File != name || le.Line != li+1 {
			rt.Fatalf("err = %v, want %s:%d", err, name, li+1)
		}
		if entries, _ := os.ReadDir(filepath.Dir(target)); len(entries) != 0 {
			rt.Fatalf("target not empty: %v", entries)
		}
	})
}
