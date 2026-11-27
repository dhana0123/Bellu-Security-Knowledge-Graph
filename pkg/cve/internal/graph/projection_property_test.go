package graph

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// Feature: bellu-security-knowledge-graph, Property 26: Projection determinism, stable ids and rebuild
// Feature: bellu-security-knowledge-graph, Property 27: Projection conforms to type and level rules
// Feature: bellu-security-knowledge-graph, Property 28: AFFECTS properties and status
// Feature: bellu-security-knowledge-graph, Property 29: Sinks agree

var projEpoch = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func drawAffected(t *rapid.T) model.Affected {
	vers := rapid.SampledFrom([]string{"0", "1.0.0", "1.2.0", "2.0.0"})
	if rapid.IntRange(0, 5).Draw(t, "prodk") == 0 {
		a := model.Affected{
			Kind: "product", Vendor: rapid.SampledFrom([]string{"acme", "Globex"}).Draw(t, "vendor"),
			Name: rapid.SampledFrom([]string{"widget", "Gadget"}).Draw(t, "product"),
		}
		a.Bounds = []model.Bound{{StartIncl: vers.Draw(t, "bs"), EndExcl: vers.Draw(t, "be")}}
		return a
	}
	a := model.Affected{
		Kind:      "package",
		Ecosystem: rapid.SampledFrom([]string{"npm", "PyPI", "Go"}).Draw(t, "eco"),
		Name:      rapid.SampledFrom([]string{"alpha", "beta", "gamma"}).Draw(t, "pkg"),
	}
	if rapid.Bool().Draw(t, "hasrange") {
		var evs []model.Event
		evs = append(evs, model.Event{Introduced: vers.Draw(t, "intro")})
		if rapid.Bool().Draw(t, "hasfixed") {
			evs = append(evs, model.Event{Fixed: vers.Draw(t, "fixed")})
		}
		a.Ranges = []model.Range{{Type: rapid.SampledFrom([]string{"SEMVER", "ECOSYSTEM"}).Draw(t, "rt"), Events: evs}}
	}
	if rapid.Bool().Draw(t, "hasver") {
		a.Versions = []string{vers.Draw(t, "ver")}
	}
	return a
}

// drawRecords returns a small random record set with distinct (source, id) keys.
func drawRecords(t *rapid.T) []*model.Record {
	srcs := []string{"osv", "nvd", "ghsa"}
	ids := []string{"CVE-2024-0001", "CVE-2024-0002", "GHSA-aaaa-0001", "GHSA-aaaa-0002"}
	type key struct{ s, i string }
	keys := rapid.SliceOfNDistinct(rapid.Custom(func(t *rapid.T) key {
		return key{rapid.SampledFrom(srcs).Draw(t, "src"), rapid.SampledFrom(ids).Draw(t, "id")}
	}), 1, 6, func(k key) key { return k }).Draw(t, "keys")
	var out []*model.Record
	for n, k := range keys {
		r := &model.Record{
			Source: k.s, ID: k.i, Summary: fmt.Sprintf("s%d", n),
			Published: projEpoch, Modified: projEpoch.Add(time.Duration(n) * time.Hour),
		}
		if rapid.IntRange(0, 6).Draw(t, "wd") == 0 {
			r.Withdrawn = projEpoch.Add(100 * time.Hour)
		}
		r.Aliases = rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"CVE-2024-0001", "CVE-2024-0002", "GHSA-aaaa-0001"}),
			0, 2, func(s string) string { return s }).Draw(t, "aliases")
		r.Weaknesses = rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"CWE-79", "CWE-89"}),
			0, 2, func(s string) string { return s }).Draw(t, "cwes")
		for _, u := range rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"a", "b"}), 0, 2, func(s string) string { return s }).Draw(t, "fix") {
			r.References = append(r.References, model.Reference{Type: "FIX", URL: "https://x/fix/" + u})
		}
		for _, u := range rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"a", "b"}), 0, 2, func(s string) string { return s }).Draw(t, "exp") {
			r.References = append(r.References, model.Reference{Type: "EXPLOIT", URL: "https://x/exp/" + u})
		}
		for i, c := 0, rapid.IntRange(0, 3).Draw(t, "naff"); i < c; i++ {
			r.Affected = append(r.Affected, drawAffected(t))
		}
		out = append(out, r)
	}
	return out
}

func newProjStore(t *rapid.T, recs []*model.Record) *canonical.Store {
	st, err := canonical.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	st.SetClock(fixedClock{})
	ctx := context.Background()
	for _, r := range recs {
		if _, err := st.UpsertRecord(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Resolve(ctx, canonical.ResolveOptions{}); err != nil {
		t.Fatal(err)
	}
	if rapid.Bool().Draw(t, "kev") {
		if _, err := st.UpsertKEV(ctx, model.KEV{CVE: "CVE-2024-0001", DateAdded: "2024-03-01"}); err != nil {
			t.Fatal(err)
		}
	}
	if rapid.Bool().Draw(t, "epss") {
		if _, err := st.UpsertEPSS(ctx, model.EPSS{CVE: "CVE-2024-0002", Score: 0.5, Percentile: 0.9, Date: "2024-03-01"}); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

func drawPolicy(t *rapid.T) Policy {
	p := Policy{Level: rapid.SampledFrom([]Level{"", LevelCore, LevelEcosystem, LevelComplete}).Draw(t, "level")}
	if rapid.Bool().Draw(t, "filter") {
		p.Ecosystems = rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"npm", "PyPI", "Go"}), 1, 2,
			func(s string) string { return s }).Draw(t, "ecos")
	}
	return p
}

type collected struct {
	nodes []Node
	edges []Edge
	stats Stats
}

func collect(t *rapid.T, st *canonical.Store, p Policy) collected {
	var c collected
	var err error
	c.stats, err = Build(context.Background(), st, p,
		func(n Node) error { c.nodes = append(c.nodes, n); return nil },
		func(e Edge) error { c.edges = append(c.edges, e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func tempDir(t *rapid.T) (string, func()) {
	d, err := os.MkdirTemp("", "projprop")
	if err != nil {
		t.Fatal(err)
	}
	return d, func() { os.RemoveAll(d) }
}

// Validates: Requirements 9.2, 9.3, 14.1, 23.1
func TestPropertyProjectionDeterminismAndRebuild(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		recs := drawRecords(t)
		st := newProjStore(t, recs)
		defer st.Close()
		pol := drawPolicy(t)

		a, b := collect(t, st, pol), collect(t, st, pol)
		if !reflect.DeepEqual(a.nodes, b.nodes) || !reflect.DeepEqual(a.edges, b.edges) {
			t.Fatal("two builds of the same canonical store differ")
		}
		ids := map[string]bool{}
		for _, n := range a.nodes {
			if n.ID == "" || ids[n.ID] {
				t.Fatalf("node id empty or duplicate: %q", n.ID)
			}
			ids[n.ID] = true
		}
		eids := map[string]bool{}
		for _, e := range a.edges {
			if e.ID == "" || eids[e.ID] {
				t.Fatalf("edge id empty or duplicate: %q", e.ID)
			}
			if e.ID != EdgeID(e.Type, e.Src, e.Dst) {
				t.Fatalf("edge id %q is not derived from type/endpoints", e.ID)
			}
			eids[e.ID] = true
		}

		dir, cleanup := tempDir(t)
		defer cleanup()
		canon := filepath.Join(dir, "canonical.db")
		if _, err := st.DB.Exec(`VACUUM INTO ?`, canon); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "graph.db")
		run := func() {
			p := &Projector{CanonicalPath: canon, Policy: pol, Clock: fixedClock{}, Sinks: []NamedSink{{"sqlite", NewSQLiteSink(out)}}}
			if _, err := p.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		run()
		first := filepath.Join(dir, "first.db")
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(first, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(out); err != nil {
			t.Fatal(err)
		}
		run()
		if err := CompareDBs(first, out); err != nil {
			t.Fatalf("rebuild after deleting graph.db differs: %v", err)
		}
	})
}

// Validates: Requirements 9.4, 9.5, 9.6, 9.7, 14.4
func TestPropertyProjectionConformsToLevel(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		st := newProjStore(t, drawRecords(t))
		defer st.Close()
		pol := drawPolicy(t)
		c := collect(t, st, pol)
		nodeType := map[string]string{}
		for _, n := range c.nodes {
			if !pol.AllowsNode(n.Type) {
				t.Fatalf("node type %s outside level %q", n.Type, pol.Level)
			}
			nodeType[n.ID] = n.Type
		}
		for _, e := range c.edges {
			if !pol.AllowsEdge(e.Type) {
				t.Fatalf("edge type %s outside level %q", e.Type, pol.Level)
			}
			ep, ok := EdgeEndpoints[e.Type]
			if !ok {
				t.Fatalf("unknown edge type %s", e.Type)
			}
			st, sok := nodeType[e.Src]
			dt, dok := nodeType[e.Dst]
			if !sok || !dok {
				t.Fatalf("edge %s endpoint not emitted (src %v dst %v)", e.ID, sok, dok)
			}
			if !contains(ep.Src, st) || !contains(ep.Dst, dt) {
				t.Fatalf("edge %s %s->%s has invalid endpoint types %s,%s", e.Type, e.Src, e.Dst, st, dt)
			}
			if !pol.AllowsNode(st) || !pol.AllowsNode(dt) {
				t.Fatalf("edge %s has out-of-level endpoint", e.ID)
			}
		}
		if pol.Level == LevelCore {
			for _, n := range c.nodes {
				if n.Type == NodePackage || n.Type == NodeProduct || n.Type == NodeVersion {
					t.Fatalf("core level emitted %s", n.Type)
				}
			}
		}
	})
}

// Validates: Requirements 9.8, 9.9, 14.5
func TestPropertyAffectsPropertiesAndStatus(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		st := newProjStore(t, drawRecords(t))
		defer st.Close()
		pol := Policy{Level: rapid.SampledFrom([]Level{"", LevelEcosystem, LevelComplete}).Draw(t, "level")}
		c := collect(t, st, pol)
		for _, e := range c.edges {
			if e.Type != EdgeAffects {
				continue
			}
			for _, k := range []string{"introduced", "fixed", "scheme", "source", "status"} {
				if _, ok := e.Props[k]; !ok {
					t.Fatalf("AFFECTS %s missing property %s", e.ID, k)
				}
			}
			srcs, ok := e.Props["sources"].([]any)
			if !ok || len(srcs) == 0 {
				t.Fatalf("AFFECTS %s has no sources: %v", e.ID, e.Props["sources"])
			}
			distinct := map[any]bool{}
			for _, s := range srcs {
				distinct[s] = true
			}
			want := "corroborated"
			if len(distinct) == 1 {
				want = "verified"
			}
			if e.Props["status"] != want {
				t.Fatalf("AFFECTS %s status %v with %d distinct sources, want %s", e.ID, e.Props["status"], len(distinct), want)
			}
			if s, _ := e.Props["scheme"].(string); s == "" {
				t.Fatalf("AFFECTS %s empty scheme", e.ID)
			}
			if s, _ := e.Props["source"].(string); s == "" {
				t.Fatalf("AFFECTS %s empty source", e.ID)
			}
		}
	})
}

// Validates: Requirements 9.2, 9.3, 14.2
func TestPropertySinksAgree(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		st := newProjStore(t, drawRecords(t))
		defer st.Close()
		pol := drawPolicy(t)
		dir, cleanup := tempDir(t)
		defer cleanup()
		canon := filepath.Join(dir, "canonical.db")
		if _, err := st.DB.Exec(`VACUUM INTO ?`, canon); err != nil {
			t.Fatal(err)
		}
		p, o := newProj(canon, dir, false)
		p.Policy = pol
		stats, err := p.Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		nodes, edges := dbCounts(t, o.db, "nodes"), dbCounts(t, o.db, "edges")
		cy, err := os.ReadFile(o.cypher)
		if err != nil {
			t.Fatal(err)
		}
		for _, ty := range AllNodeTypes {
			want := stats.Nodes[ty]
			if nodes[ty] != want {
				t.Fatalf("sqlite node %s: %d, stats %d", ty, nodes[ty], want)
			}
			if got := jsonlCount(t, filepath.Join(o.jsonl, jsonlNodeFile(ty))); got != want {
				t.Fatalf("jsonl node %s: %d, want %d", ty, got, want)
			}
			if got := strings.Count(string(cy), "MERGE (n:"+ty+" {"); got != want {
				t.Fatalf("cypher node %s: %d, want %d", ty, got, want)
			}
		}
		for _, ty := range AllEdgeTypes {
			want := stats.Edges[ty]
			if edges[ty] != want {
				t.Fatalf("sqlite edge %s: %d, stats %d", ty, edges[ty], want)
			}
			if got := jsonlCount(t, filepath.Join(o.jsonl, jsonlEdgeFile(ty))); got != want {
				t.Fatalf("jsonl edge %s: %d, want %d", ty, got, want)
			}
			if got := strings.Count(string(cy), "MERGE (a)-[r:"+ty+" {"); got != want {
				t.Fatalf("cypher edge %s: %d, want %d", ty, got, want)
			}
		}
	})
}

func dbCounts(t *rapid.T, path, table string) map[string]int {
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
		if err := rows.Scan(&ty, &n); err != nil {
			t.Fatal(err)
		}
		m[ty] = n
	}
	return m
}

// jsonlCount returns the number of records in a JSONL file (header line excluded);
// a missing file means zero records.
func jsonlCount(t *rapid.T, path string) int {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "\n") - 1
}

// Validates: Requirements 9.1, 9.2
func TestProjectorIgnoresExistingOutputs(t *testing.T) {
	canon := canonFile(t)
	dir := t.TempDir()
	p, o := newProj(canon, dir, false)
	// Pre-place corrupt prior outputs; the projector must not read them.
	if err := os.WriteFile(o.db, []byte("not a database"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(o.jsonl, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(o.jsonl, jsonlNodeFile(NodeVulnerability)), []byte("{garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.cypher, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Run(context.Background()); err != nil {
		t.Fatalf("run with corrupt prior outputs: %v", err)
	}
	ref := filepath.Join(t.TempDir(), "ref.db")
	pr := &Projector{CanonicalPath: canon, Clock: fixedClock{}, Sinks: []NamedSink{{"sqlite", NewSQLiteSink(ref)}}}
	if _, err := pr.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := CompareDBs(ref, o.db); err != nil {
		t.Fatalf("output depends on prior graph.db: %v", err)
	}
	if b, _ := os.ReadFile(o.cypher); strings.Contains(string(b), "garbage") {
		t.Fatal("cypher output not overwritten")
	}
}

// R23.1 at projection level: duplicate ingestion yields identical node and edge sets.
// Validates: Requirements 23.1
func TestDuplicateIngestionProjectionUnchanged(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		recs := drawRecords(t)
		st := newProjStore(t, recs)
		defer st.Close()
		pol := drawPolicy(t)
		before := collect(t, st, pol)
		ctx := context.Background()
		for _, r := range recs {
			if ch, err := st.UpsertRecord(ctx, r); err != nil || ch {
				t.Fatalf("duplicate ingest changed=%v err=%v", ch, err)
			}
		}
		if _, err := st.Resolve(ctx, canonical.ResolveOptions{}); err != nil {
			t.Fatal(err)
		}
		after := collect(t, st, pol)
		key := func(c collected) []string {
			var out []string
			for _, n := range c.nodes {
				h, _ := NodeHash(n)
				out = append(out, "n:"+n.ID+":"+h)
			}
			for _, e := range c.edges {
				h, _ := EdgeHash(e)
				out = append(out, "e:"+e.ID+":"+h)
			}
			sort.Strings(out)
			return out
		}
		if !reflect.DeepEqual(key(before), key(after)) {
			t.Fatal("duplicate ingestion changed the projection")
		}
	})
}
