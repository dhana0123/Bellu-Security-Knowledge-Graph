package api

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bellu/bskg/internal/model"
)

func fp(f float64) *float64 { return &f }

func TestRankSeeds(t *testing.T) {
	in := []overviewSeed{
		{CVE: "CVE-9", V3: fp(10)},                       // no exploitability: after all scored
		{CVE: "CVE-5", Exploitability: fp(0), V3: fp(9)}, //
		{CVE: "CVE-4", Exploitability: fp(1)},            // v3 missing: after CVE-2/CVE-3
		{CVE: "CVE-3", Exploitability: fp(1), V3: fp(7), V2: fp(1)},
		{CVE: "CVE-2", Exploitability: fp(1), V3: fp(7), V2: fp(5)}, // v2 breaks the tie
		{CVE: "CVE-1", Exploitability: fp(1), V3: fp(7), V2: fp(5)}, // cveID breaks the tie
		{CVE: "CVE-0", Exploitability: fp(1), V3: fp(9.8)},
	}
	var got []string
	for _, s := range rankSeeds(in) {
		got = append(got, s.CVE)
	}
	want := []string{"CVE-0", "CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5", "CVE-9"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if in[0].CVE != "CVE-9" {
		t.Fatal("input was reordered")
	}
}

func TestSelectOverview(t *testing.T) {
	seeds := []overviewSeed{{CVE: "CVE-1", Exploitability: fp(0)}, {CVE: "CVE-2", Exploitability: fp(1)}}
	shared := nodeRef{"Weakness", "CWE-1"}
	nbrs := map[string][]nodeRef{
		"CVE-2": {{"Product", "b"}, shared, {"Product", "a"}},
		"CVE-1": {shared, {"Domain", "d"}},
	}
	ids := func(ns []nodeRef) []string {
		var out []string
		for _, n := range ns {
			out = append(out, n.ID())
		}
		return out
	}
	got := ids(selectOverview(seeds, nbrs, 100))
	want := []string{"Vulnerability:CVE-2", "Product:a", "Product:b", "Weakness:CWE-1", "Vulnerability:CVE-1", "Domain:d"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
	// The cap cuts in selection order, the shared node is counted once.
	if got := ids(selectOverview(seeds, nbrs, 5)); !slices.Equal(got, want[:5]) {
		t.Fatalf("cap 5: %v", got)
	}
	if got := ids(selectOverview(seeds, nbrs, 1)); !slices.Equal(got, want[:1]) {
		t.Fatalf("cap 1: %v", got)
	}
	if got := selectOverview(nil, nbrs, 10); len(got) != 0 {
		t.Fatalf("no seeds: %v", got)
	}
}

type fakeRel struct {
	typ      string
	from, to any
	viewID   any
	removed  bool
}

// fakeGraph answers the overview queries from memory. It deliberately returns
// seeds in reverse rank order so the test shows ranking happens in Go.
type fakeGraph struct {
	nodes map[string]map[any]map[string]any // label -> key -> props
	rels  []fakeRel
	calls atomic.Int32
	limit []int64 // every $limit seen
}

func newFakeGraph() *fakeGraph {
	g := &fakeGraph{nodes: map[string]map[any]map[string]any{}}
	add := func(l string, k any, p map[string]any) {
		if g.nodes[l] == nil {
			g.nodes[l] = map[any]map[string]any{}
		}
		g.nodes[l][k] = p
	}
	add("Vulnerability", "CVE-1", map[string]any{"cveID": "CVE-1", "exploitability": int64(1), "v3baseScore": 5.0, "sources": []any{"nvd"}})
	add("Vulnerability", "CVE-2", map[string]any{"cveID": "CVE-2", "exploitability": int64(1), "v3baseScore": 9.8, "description": "d"})
	add("Vulnerability", "CVE-3", map[string]any{"cveID": "CVE-3", "v3baseScore": 10.0})
	add("Vulnerability", "CVE-4", map[string]any{"cveID": "CVE-4", "exploitability": int64(0)})
	add("Weakness", "CWE-79", map[string]any{"cweID": "CWE-79"})
	add("Product", "p1", map[string]any{"productName": "p1"})
	add("Vendor", "v1", map[string]any{"vendorName": "v1"})
	add("Exploit", int64(42), map[string]any{"eid": int64(42)})
	add("Author", "a1", map[string]any{"authorName": "a1"})
	g.rels = []fakeRel{
		{typ: "EXAMPLE_OF", from: "CVE-2", to: "CWE-79"},
		{typ: "AFFECTS", from: "CVE-2", to: "p1"},
		{typ: "BELONGS_TO", from: "p1", to: "v1"},
		{typ: "EXPLOITS", from: int64(42), to: "CVE-1"},
		{typ: "WRITES", from: "a1", to: int64(42)},
		{typ: "AFFECTS", from: "CVE-3", to: "p1", removed: true},
		{typ: "CHILD_OF", from: "CWE-79", to: "CWE-79", viewID: "1000"},
	}
	return g
}

func (g *fakeGraph) relLabels(r fakeRel) (string, string) {
	rt, _ := model.RelByName(r.typ)
	return rt.From, rt.To
}

func (g *fakeGraph) run(_ context.Context, q string, p map[string]any) ([]Row, error) {
	g.calls.Add(1)
	if l, ok := p["limit"].(int64); ok {
		g.limit = append(g.limit, l)
	}
	for name, cq := range labelCountQueries {
		if q == cq {
			return []Row{{"n": int64(len(g.nodes[name]))}}, nil
		}
	}
	for name, cq := range relCountQueries {
		if q == cq {
			n := 0
			for _, r := range g.rels {
				if r.typ == name {
					n++
				}
			}
			return []Row{{"n": int64(n)}}, nil
		}
	}
	for name, nq := range overviewNodeQueries {
		if q == nq {
			var rows []Row
			for k, props := range g.nodes[name] {
				rows = append(rows, Row{"key": k, "props": props})
			}
			return rows, nil
		}
	}
	for name, pq := range overviewPropsQueries {
		if q == pq {
			var rows []Row
			for _, k := range p["keys"].([]any) {
				if props, ok := g.nodes[name][k]; ok {
					rows = append(rows, Row{"key": k, "props": props})
				}
			}
			return rows, nil
		}
	}
	for name, eq := range overviewEdgeQueries {
		if q == eq {
			from, to := p["fromKeys"].([]any), p["toKeys"].([]any)
			var rows []Row
			for _, r := range g.rels {
				if r.typ == name && !r.removed && slices.Contains(from, r.from) && slices.Contains(to, r.to) {
					rows = append(rows, Row{"src": r.from, "dst": r.to, "viewID": r.viewID})
				}
			}
			return rows, nil
		}
	}
	switch q {
	case cypherOverviewSeeds:
		var cves []string
		for k := range g.nodes["Vulnerability"] {
			cves = append(cves, k.(string))
		}
		slices.Sort(cves)
		slices.Reverse(cves)
		var rows []Row
		for _, c := range cves {
			pr := g.nodes["Vulnerability"][c]
			rows = append(rows, Row{"cveID": c, "exploitability": pr["exploitability"], "v3baseScore": pr["v3baseScore"], "v2baseScore": pr["v2baseScore"]})
		}
		return rows, nil
	case cypherOverviewNeighbours:
		var rows []Row
		for _, c := range p["cves"].([]string) {
			for _, r := range g.rels {
				if r.removed {
					continue
				}
				fl, tl := g.relLabels(r)
				if fl == "Vulnerability" && r.from == c {
					rows = append(rows, Row{"cve": c, "label": tl, "key": r.to})
				}
				if tl == "Vulnerability" && r.to == c {
					rows = append(rows, Row{"cve": c, "label": fl, "key": r.from})
				}
			}
		}
		return rows, nil
	}
	return nil, fmt.Errorf("unexpected query %q", q)
}

func nodeIDs(r *overviewResult) []string {
	var out []string
	for _, n := range r.Nodes {
		out = append(out, n.ID)
	}
	return out
}

func TestComputeOverviewWholeGraph(t *testing.T) {
	g := newFakeGraph()
	res, err := computeOverview(context.Background(), g.run, 5000, 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated || len(res.Nodes) != 9 {
		t.Fatalf("truncated=%v nodes=%v", res.Truncated, nodeIDs(res))
	}
	var edgeIDs []string
	for _, e := range res.Edges {
		edgeIDs = append(edgeIDs, e.ID)
	}
	want := []string{
		"Author:a1|WRITES|Exploit:42",
		"Exploit:42|EXPLOITS|Vulnerability:CVE-1",
		"Product:p1|BELONGS_TO|Vendor:v1",
		"Vulnerability:CVE-2|AFFECTS|Product:p1",
		"Vulnerability:CVE-2|EXAMPLE_OF|Weakness:CWE-79",
		"Weakness:CWE-79|CHILD_OF|Weakness:CWE-79|1000",
	}
	if !slices.Equal(edgeIDs, want) { // removed CVE-3 -> p1 is excluded
		t.Fatalf("edges %v", edgeIDs)
	}
	if res.TotalNodes != 9 || res.TotalRels != 6 {
		t.Fatalf("totals %d %d", res.TotalNodes, res.TotalRels)
	}
	// Scalar props only, ids and labels as in the neighborhood endpoint.
	v := res.Nodes[slices.Index(nodeIDs(res), "Vulnerability:CVE-1")]
	if v.Type != "Vulnerability" || v.Key != "CVE-1" || v.Label != "CVE-1" || v.Properties["sources"] != nil || v.Properties["v3baseScore"] != 5.0 {
		t.Fatalf("%+v", v)
	}
	// Every query is bounded.
	for _, l := range g.limit {
		if l <= 0 {
			t.Fatalf("limit %d", l)
		}
	}
}

func TestComputeOverviewRankedSubset(t *testing.T) {
	g := newFakeGraph()
	// 9 nodes, limit 8: ranked mode. Seeds CVE-2, CVE-1, CVE-4, CVE-3 and their direct neighbours only.
	res, err := computeOverview(context.Background(), g.run, 8, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Exploit:42", "Product:p1", "Vulnerability:CVE-1", "Vulnerability:CVE-2", "Vulnerability:CVE-3", "Vulnerability:CVE-4", "Weakness:CWE-79"}
	if !res.Truncated || !slices.Equal(nodeIDs(res), want) {
		t.Fatalf("truncated=%v nodes=%v", res.Truncated, nodeIDs(res))
	}
	if len(res.Edges) != 4 || res.TotalNodes != 9 || res.TotalRels != 7 {
		t.Fatalf("edges=%d totals %d %d", len(res.Edges), res.TotalNodes, res.TotalRels)
	}
	// A small cap keeps the top-ranked vulnerability and its neighbours first.
	res, err = computeOverview(context.Background(), g.run, 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Product:p1", "Vulnerability:CVE-2", "Weakness:CWE-79"}; !slices.Equal(nodeIDs(res), want) || len(res.Edges) != 3 {
		t.Fatalf("cap 3: %v %d", nodeIDs(res), len(res.Edges))
	}
}

func TestComputeOverviewEdgeCapTruncates(t *testing.T) {
	g := newFakeGraph()
	// limit 1 in whole-graph mode is impossible (9 nodes), so use the edge cap
	// with a direct call: 2 nodes, 2 parallel CHILD_OF views, cap = 2*5.
	g.nodes = map[string]map[any]map[string]any{"Weakness": {"W1": {"cweID": "W1"}, "W2": {"cweID": "W2"}}}
	g.rels = nil
	for i := 0; i < 12; i++ {
		g.rels = append(g.rels, fakeRel{typ: "CHILD_OF", from: "W1", to: "W2", viewID: fmt.Sprint(i)})
	}
	res, err := computeOverview(context.Background(), g.run, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Edges) != 10 || res.TotalRels != 12 {
		t.Fatalf("truncated=%v edges=%d total=%d", res.Truncated, len(res.Edges), res.TotalRels)
	}
}

func TestOverviewEndpoint(t *testing.T) {
	g := newFakeGraph()
	e := opsEnv(t, g.run, nil, nil)
	code, body := getJSON(t, e, "/v1/graph/overview")
	if code != 200 {
		t.Fatalf("%d %v", code, body)
	}
	nodes, _ := body["nodes"].([]any)
	edges, _ := body["edges"].([]any)
	total, _ := body["total"].(map[string]any)
	if len(nodes) != 9 || len(edges) != 6 || body["truncated"] != false || total["nodes"] != float64(9) || total["relationships"] != float64(6) || body["graph"] == nil {
		t.Fatalf("%v", body)
	}
	n0 := nodes[0].(map[string]any)
	for _, k := range []string{"id", "type", "key", "label", "properties"} {
		if _, ok := n0[k]; !ok {
			t.Fatalf("node lacks %s: %v", k, n0)
		}
	}
	// Cached: a second identical request runs no queries, another limit does.
	before := g.calls.Load()
	getJSON(t, e, "/v1/graph/overview?limit=5000")
	if g.calls.Load() != before {
		t.Fatal("same limit not served from cache")
	}
	code, body = getJSON(t, e, "/v1/graph/overview?limit=4")
	if code != 200 || body["truncated"] != true || len(body["nodes"].([]any)) != 4 || g.calls.Load() == before {
		t.Fatalf("%d %v", code, body)
	}
}

func TestOverviewLimitValidation(t *testing.T) {
	e := opsEnv(t, newFakeGraph().run, nil, nil)
	for _, l := range []string{"0", "-1", "5001", "abc", "1.5"} {
		code, body := getJSON(t, e, "/v1/graph/overview?limit="+l)
		er, _ := body["error"].(map[string]any)
		if code != 400 || er["code"] != "invalid_parameter" || er["parameter"] != "limit" {
			t.Errorf("limit=%s: %d %v", l, code, body)
		}
	}
	for _, l := range []string{"1", "5000"} {
		if code, _ := getJSON(t, e, "/v1/graph/overview?limit="+l); code != 200 {
			t.Errorf("limit=%s: %d", l, code)
		}
	}
}

func TestOverviewRequiresAuth(t *testing.T) {
	e := opsEnv(t, newFakeGraph().run, nil, nil)
	if rec := e.do("/v1/graph/overview", ""); rec.Code != 401 {
		t.Fatalf("%d", rec.Code)
	}
}

func TestOverviewFailureStatus(t *testing.T) {
	e := opsEnv(t, func(context.Context, string, map[string]any) ([]Row, error) { return nil, context.DeadlineExceeded }, nil, nil)
	if code, _ := getJSON(t, e, "/v1/graph/overview"); code != 504 {
		t.Fatalf("timeout: %d", code)
	}
	e = opsEnv(t, func(context.Context, string, map[string]any) ([]Row, error) { return nil, errors.New("x") }, nil, nil)
	if code, _ := getJSON(t, e, "/v1/graph/overview"); code != 500 {
		t.Fatalf("failure: %d", code)
	}
}

func TestOverviewCachesPerLimitStaleAndEviction(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	var fail atomic.Bool
	var runs atomic.Int32
	c := &overviewCaches{ttl: time.Minute, timeout: time.Second, now: func() time.Time { return now },
		compute: func(_ context.Context, limit int) (*overviewResult, error) {
			runs.Add(1)
			if fail.Load() {
				return nil, errors.New("down")
			}
			return &overviewResult{TotalNodes: int64(limit)}, nil
		}}
	ctx := context.Background()
	a, _, err := c.forLimit(10).get(ctx)
	if err != nil || a.TotalNodes != 10 {
		t.Fatalf("%v %v", a, err)
	}
	if b, _, _ := c.forLimit(20).get(ctx); b.TotalNodes != 20 {
		t.Fatal("limits share a cache entry")
	}
	c.forLimit(10).get(ctx)
	if runs.Load() != 2 {
		t.Fatalf("runs %d", runs.Load())
	}
	// Past the TTL a failing computation serves the previous result.
	now = now.Add(2 * time.Minute)
	fail.Store(true)
	v, stale, err := c.forLimit(10).get(ctx)
	if err != nil || !stale || v.TotalNodes != 10 {
		t.Fatalf("stale: %v %v %v", v, stale, err)
	}
	// A limit that never succeeded reports the error.
	if _, _, err := c.forLimit(30).get(ctx); err == nil {
		t.Fatal("expected error")
	}
	// The number of cached limits is bounded.
	for i := 100; i < 100+3*overviewMaxCached; i++ {
		c.forLimit(i)
	}
	if len(c.m) != overviewMaxCached || len(c.order) != overviewMaxCached {
		t.Fatalf("cache size %d/%d", len(c.m), len(c.order))
	}
}

func TestOverviewQueriesRegistered(t *testing.T) {
	for _, q := range append([]string{cypherOverviewSeeds, cypherOverviewNeighbours}, collectOverviewQueries()...) {
		if !slices.Contains(allQueries, q) {
			t.Errorf("not registered: %s", q)
		}
		if !containsLimit(q) {
			t.Errorf("unbounded query: %s", q)
		}
	}
}

func collectOverviewQueries() []string {
	var out []string
	for _, m := range []map[string]string{overviewNodeQueries, overviewPropsQueries, overviewEdgeQueries} {
		for _, q := range m {
			out = append(out, q)
		}
	}
	return out
}

func containsLimit(q string) bool {
	return strings.Contains(q, "LIMIT $limit") || strings.Contains(q, "LIMIT $rowCap")
}
