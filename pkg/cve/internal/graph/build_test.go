package graph

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/osv"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

func buildFixtureStore(t *testing.T) *canonical.Store {
	t.Helper()
	return buildFixtureStoreAt(t, ":memory:")
}

// buildFixtureStoreAt builds the fixture store at path (":memory:" or a file).
func buildFixtureStoreAt(t *testing.T, path string) *canonical.Store {
	t.Helper()
	ctx := context.Background()
	st, err := canonical.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "graph", "snapshot_U.json"))
	if err != nil {
		t.Fatal(err)
	}
	var docs []json.RawMessage
	if err := json.Unmarshal(data, &docs); err != nil {
		t.Fatal(err)
	}
	for _, d := range docs {
		rec, err := osv.Parse("osv", d)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.UpsertRecord(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	mod := time.Date(2024, 2, 11, 0, 0, 0, 0, time.UTC)
	// A second, independent source for CVE-2024-1000 with a product and references.
	nvd := &model.Record{
		Source: "nvd", ID: "CVE-2024-1000", Summary: "fixture nvd", Published: mod, Modified: mod,
		Weaknesses: []string{"CWE-79"},
		Affected: []model.Affected{
			{Kind: "package", Ecosystem: "npm", Name: "fix-pkg", Ranges: []model.Range{{Type: "SEMVER", Events: []model.Event{{Introduced: "0.5.0"}, {Fixed: "1.0.1"}}}}},
			{Kind: "package", Ecosystem: "PyPI", Name: "fix-py", Versions: []string{"2.0.0"}},
			{Kind: "product", Vendor: "Acme", Name: "Widget", Bounds: []model.Bound{{StartIncl: "1.0", EndExcl: "1.5"}}},
		},
		References: []model.Reference{{Type: "FIX", URL: "https://example.test/fix"}, {Type: "EXPLOIT", URL: "https://example.test/exp"}},
	}
	if _, err := st.UpsertRecord(ctx, nvd); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Resolve(ctx, canonical.ResolveOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertKEV(ctx, model.KEV{CVE: "CVE-2024-1000", DateAdded: "2024-03-01", DueDate: "2024-03-22", Ransomware: "known"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertEPSS(ctx, model.EPSS{CVE: "CVE-2024-1000", Score: 0.5, Percentile: 0.9, Date: "2024-03-01"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertEPSS(ctx, model.EPSS{CVE: "CVE-2024-1000", Score: 0.6, Percentile: 0.95, Date: "2024-03-02"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`UPDATE patch SET fixed_version='1.0.1' WHERE source='nvd'`); err != nil {
		t.Fatal(err)
	}
	// Not linked to any vulnerability: must not appear.
	if _, err := st.UpsertKEV(ctx, model.KEV{CVE: "CVE-2099-0001"}); err != nil {
		t.Fatal(err)
	}
	return st
}

type projection struct {
	nodes map[string]Node
	edges map[string]Edge
	stats Stats
	order []string
}

func runBuild(t *testing.T, st *canonical.Store, p Policy) projection {
	t.Helper()
	out := projection{nodes: map[string]Node{}, edges: map[string]Edge{}}
	stats, err := Build(context.Background(), st, p,
		func(n Node) error {
			if _, dup := out.nodes[n.ID]; dup {
				t.Errorf("node %s emitted twice", n.ID)
			}
			out.nodes[n.ID] = n
			out.order = append(out.order, "n:"+n.ID)
			return nil
		},
		func(e Edge) error {
			if _, dup := out.edges[e.ID]; dup {
				t.Errorf("edge %s emitted twice", e.ID)
			}
			out.edges[e.ID] = e
			out.order = append(out.order, "e:"+e.ID)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	out.stats = stats
	return out
}

func (p projection) nodesOf(typ string) []Node {
	var out []Node
	for _, n := range p.nodes {
		if n.Type == typ {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (p projection) edgesOf(typ string) []Edge {
	var out []Edge
	for _, e := range p.edges {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func TestBuildVocabularyAndEndpoints(t *testing.T) {
	st := buildFixtureStore(t)
	p := runBuild(t, st, Policy{})
	nodeTypes := toSet(AllNodeTypes)
	for _, n := range p.nodes {
		if _, ok := nodeTypes[n.Type]; !ok {
			t.Errorf("unknown node type %s", n.Type)
		}
		if n.ID == "" {
			t.Error("empty node id")
		}
	}
	for _, e := range p.edges {
		ep, ok := EdgeEndpoints[e.Type]
		if !ok {
			t.Fatalf("unknown edge type %s", e.Type)
		}
		src, dst := p.nodes[e.Src], p.nodes[e.Dst]
		if src.ID == "" || dst.ID == "" {
			t.Fatalf("edge %s %s->%s has an endpoint that was not emitted", e.Type, e.Src, e.Dst)
		}
		if !contains(ep.Src, src.Type) || !contains(ep.Dst, dst.Type) {
			t.Errorf("edge %s %s(%s)->%s(%s) violates endpoint types", e.Type, e.Src, src.Type, e.Dst, dst.Type)
		}
		if e.ID != EdgeID(e.Type, e.Src, e.Dst) {
			t.Errorf("edge id not stable: %s", e.ID)
		}
	}
	// All twelve node types and all edge types appear in this fixture except none missing.
	for _, typ := range AllNodeTypes {
		if len(p.nodesOf(typ)) == 0 {
			t.Errorf("no %s node", typ)
		}
	}
	for _, typ := range AllEdgeTypes {
		if len(p.edgesOf(typ)) == 0 {
			t.Errorf("no %s edge", typ)
		}
	}
	if p.stats.Vulnerabilities != len(p.nodesOf(NodeVulnerability)) {
		t.Errorf("stats vulnerabilities %d", p.stats.Vulnerabilities)
	}
	if n := p.stats.Nodes[NodePackage]; n != len(p.nodesOf(NodePackage)) {
		t.Errorf("stats packages %d", n)
	}
	if _, ok := p.nodes[KEVID("CVE-2099-0001")]; ok {
		t.Error("pending KEV entry was emitted")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestBuildAffectsPropsAndStatus(t *testing.T) {
	st := buildFixtureStore(t)
	p := runBuild(t, st, Policy{})
	vuln := VulnerabilityID("CVE-2024-1000")

	byDst := map[string]Edge{}
	for _, e := range p.edgesOf(EdgeAffects) {
		if e.Src == vuln {
			byDst[e.Dst] = e
		}
	}
	// npm fix-pkg is reported by osv and nvd: corroborated; PyPI by nvd only: verified.
	npm := byDst[PackageID("npm", "fix-pkg")]
	if npm.ID == "" {
		t.Fatal("no AFFECTS edge to npm fix-pkg")
	}
	if npm.Props["status"] != "corroborated" {
		t.Errorf("npm status = %v", npm.Props["status"])
	}
	if !reflect.DeepEqual(npm.Props["sources"], []any{"nvd", "osv"}) {
		t.Errorf("sources = %#v", npm.Props["sources"])
	}
	// Flat props come from the first source (nvd).
	if npm.Props["source"] != "nvd" || npm.Props["introduced"] != "0.5.0" || npm.Props["fixed"] != "1.0.1" || npm.Props["scheme"] != "semver" {
		t.Errorf("flat props = %#v", npm.Props)
	}
	if es, _ := npm.Props["entries"].([]any); len(es) != 2 {
		t.Errorf("entries = %#v", npm.Props["entries"])
	}
	py := byDst[PackageID("PyPI", "fix-py")]
	if py.Props["status"] != "verified" {
		t.Errorf("pypi status = %v", py.Props["status"])
	}
	// Explicit nulls: keys present, value nil.
	for _, k := range []string{"introduced", "fixed", "scheme", "source", "status"} {
		if _, ok := py.Props[k]; !ok {
			t.Errorf("AFFECTS prop %q missing", k)
		}
	}
	if py.Props["introduced"] != nil || py.Props["fixed"] != nil || py.Props["scheme"] != "pep440" {
		t.Errorf("pypi props = %#v", py.Props)
	}
	// Product entry (bounds only).
	prod := byDst[ProductID("Acme", "Widget")]
	if prod.ID == "" || prod.Props["introduced"] != "1.0" || prod.Props["fixed"] != "1.5" || prod.Props["scheme"] != "generic" {
		t.Errorf("product edge = %#v", prod.Props)
	}
	// Every AFFECTS edge carries all flat keys and valid status.
	for _, e := range p.edgesOf(EdgeAffects) {
		for _, k := range []string{"introduced", "fixed", "scheme", "source", "status", "entries", "sources"} {
			if _, ok := e.Props[k]; !ok {
				t.Errorf("AFFECTS %s misses %s", e.ID, k)
			}
		}
		if s := e.Props["status"]; s != "verified" && s != "corroborated" {
			t.Errorf("status %v", s)
		}
	}
	if _, err := CanonicalJSON(npm.Props); err != nil {
		t.Errorf("props not JSON: %v", err)
	}
}

func TestBuildVersionsPatchesEnrichment(t *testing.T) {
	st := buildFixtureStore(t)
	p := runBuild(t, st, Policy{})
	vuln := VulnerabilityID("CVE-2024-1000")
	pkg := PackageID("npm", "fix-pkg")

	for _, id := range []string{
		VersionID("semver", pkg, "0.5.0"), VersionID("semver", pkg, "1.0.1"),
		VersionID("pep440", PackageID("PyPI", "fix-py"), "2.0.0"),
	} {
		if _, ok := p.nodes[id]; !ok {
			t.Errorf("missing version node %s", id)
		}
	}
	if _, ok := p.nodes[VersionID("semver", pkg, "0")]; ok {
		t.Error("sentinel version 0 became a node")
	}
	has := func(typ, src, dst string) bool {
		_, ok := p.edges[EdgeID(typ, src, dst)]
		return ok
	}
	if !has(EdgeAffectsVersion, vuln, VersionID("semver", pkg, "0.5.0")) {
		t.Error("missing AFFECTS_VERSION for introduced")
	}
	if has(EdgeAffectsVersion, vuln, VersionID("semver", pkg, "1.0.1")) {
		t.Error("fixed version must not be AFFECTS_VERSION")
	}
	patch := PatchID("CVE-2024-1000", "https://example.test/fix", "nvd")
	if !has(EdgeFixedBy, vuln, patch) {
		t.Error("missing FIXED_BY")
	}
	if !has(EdgeHasExploit, vuln, ExploitID("CVE-2024-1000", "https://example.test/exp", "nvd")) {
		t.Error("missing HAS_EXPLOIT")
	}
	if !has(EdgeClassifiedAs, vuln, WeaknessID("79")) {
		t.Error("missing CLASSIFIED_AS")
	}
	if !has(EdgeListedInKEV, vuln, KEVID("CVE-2024-1000")) {
		t.Error("missing LISTED_IN_KEV")
	}
	// Only the current EPSS assessment.
	eps := p.nodesOf(NodeEPSSAssessment)
	if len(eps) != 1 || eps[0].ID != EPSSID("CVE-2024-1000", "2024-03-02") || eps[0].Props["current"] != true {
		t.Errorf("epss nodes = %#v", eps)
	}
	if !has(EdgeBelongsToVendor, ProductID("Acme", "Widget"), VendorID("acme")) {
		t.Error("missing BELONGS_TO_VENDOR")
	}
	// Severity disagreement within the fixture is flagged on the vulnerability.
	if p.nodes[vuln].Props["discrepancy"] != true {
		t.Errorf("discrepancy = %v", p.nodes[vuln].Props["discrepancy"])
	}
	if p.nodes[vuln].Props["trust_state"] != "corroborated" {
		t.Errorf("trust_state = %v", p.nodes[vuln].Props["trust_state"])
	}
}

func TestBuildAliasLookupAndWithdrawn(t *testing.T) {
	st := buildFixtureStore(t)
	p := runBuild(t, st, Policy{})

	// GHSA id resolves to the CVE through ALIAS_OF from its record node.
	rec := SourceRecordID("osv", "GHSA-FIX-0001")
	if _, ok := p.edges[EdgeID(EdgeAliasOf, rec, VulnerabilityID("CVE-2024-1000"))]; !ok {
		t.Error("record node does not resolve through ALIAS_OF")
	}
	// The CVE id has no record in osv/nvd named so... nvd has it: record node, not alias.
	if n, ok := p.nodes[AliasID("CVE-2024-1000")]; ok {
		t.Errorf("identifier of a member record became alias node: %v", n)
	}
	// An alias node for an identifier that is not a record id.
	var aliases int
	for _, n := range p.nodesOf(NodeSourceRecord) {
		if n.Props["kind"] == "alias" {
			aliases++
			if !strings.HasPrefix(n.ID, "alias:") {
				t.Errorf("alias id %s", n.ID)
			}
			if len(p.edgesOfSrc(EdgeAliasOf, n.ID)) == 0 {
				t.Errorf("alias %s has no ALIAS_OF", n.ID)
			}
		}
	}
	if aliases == 0 {
		t.Error("no alias nodes")
	}
	if n, ok := p.nodes[AliasID("CVE-2024-2000")]; !ok {
		t.Error("alias CVE-2024-2000 missing")
	} else if _, ok := p.edges[EdgeID(EdgeAliasOf, n.ID, VulnerabilityID("CVE-2024-2000"))]; !ok {
		t.Error("alias CVE-2024-2000 not linked")
	}

	// Withdrawn record: node kept with withdrawn set, nothing derived.
	wd := p.nodes[SourceRecordID("osv", "GHSA-WD-0002")]
	if wd.ID == "" || wd.Props["withdrawn"] == nil {
		t.Fatalf("withdrawn record node = %#v", wd)
	}
	v := p.nodes[VulnerabilityID("CVE-2024-2000")]
	if v.ID == "" || v.Props["withdrawn"] == nil || v.Props["trust_state"] != nil {
		t.Errorf("withdrawn vulnerability props = %#v", v.Props)
	}
	for _, typ := range []string{EdgeAffects, EdgeHasAssessment, EdgeAffectsVersion} {
		for _, e := range p.edgesOf(typ) {
			if e.Src == v.ID {
				t.Errorf("%s derived from a withdrawn record", typ)
			}
		}
	}
}

func (p projection) edgesOfSrc(typ, src string) []Edge {
	var out []Edge
	for _, e := range p.edgesOf(typ) {
		if e.Src == src {
			out = append(out, e)
		}
	}
	return out
}

func TestBuildLevelFilter(t *testing.T) {
	st := buildFixtureStore(t)
	core := runBuild(t, st, Policy{Level: LevelCore})
	for _, n := range core.nodes {
		if !(Policy{Level: LevelCore}).AllowsNode(n.Type) {
			t.Errorf("core emitted %s", n.Type)
		}
	}
	for _, e := range core.edges {
		if !(Policy{Level: LevelCore}).AllowsEdge(e.Type) {
			t.Errorf("core emitted edge %s", e.Type)
		}
		if core.nodes[e.Src].ID == "" || core.nodes[e.Dst].ID == "" {
			t.Errorf("core edge with missing endpoint: %v", e)
		}
	}
	for _, typ := range []string{NodePackage, NodeProduct, NodeVendor, NodeVersion, NodePatch, NodeExploit} {
		if len(core.nodesOf(typ)) != 0 {
			t.Errorf("core has %s", typ)
		}
	}
	full := runBuild(t, st, Policy{})
	if len(core.nodesOf(NodeVulnerability)) != len(full.nodesOf(NodeVulnerability)) {
		t.Error("core must emit all vulnerabilities")
	}

	eco := runBuild(t, st, Policy{Level: LevelEcosystem})
	if len(eco.nodesOf(NodeExploit)) != 0 || len(eco.edgesOf(EdgeHasExploit)) != 0 {
		t.Error("ecosystem level emitted exploits")
	}
	if len(eco.nodesOf(NodePackage)) == 0 || len(eco.nodesOf(NodePatch)) == 0 {
		t.Error("ecosystem level lacks packages or patches")
	}
	cmp := runBuild(t, st, Policy{Level: LevelComplete})
	if len(cmp.nodesOf(NodeExploit)) == 0 {
		t.Error("complete level lacks exploits")
	}
}

func TestBuildEcosystemFilter(t *testing.T) {
	st := buildFixtureStore(t)
	p := runBuild(t, st, Policy{Level: LevelEcosystem, Ecosystems: []string{"pypi"}})
	if got := p.nodesOf(NodeVulnerability); len(got) != 1 || got[0].ID != VulnerabilityID("CVE-2024-1000") {
		t.Fatalf("vulnerabilities = %v", ids(got))
	}
	pk := p.nodesOf(NodePackage)
	if len(pk) != 1 || pk[0].ID != PackageID("PyPI", "fix-py") {
		t.Errorf("packages = %v", ids(pk))
	}
	if len(p.nodesOf(NodeProduct)) != 0 || len(p.nodesOf(NodeVendor)) != 0 {
		t.Error("products emitted with an ecosystem filter")
	}
	if p.stats.SkippedVulnerabilities == 0 {
		t.Error("skipped vulnerabilities not counted")
	}
	for _, e := range p.edges {
		if p.nodes[e.Src].ID == "" || p.nodes[e.Dst].ID == "" {
			t.Errorf("dangling edge %s", e.Type)
		}
	}
	// Complete ignores the filter; core emits every CVE.
	if got := runBuild(t, st, Policy{Level: LevelComplete, Ecosystems: []string{"pypi"}}).nodesOf(NodePackage); len(got) < 2 {
		t.Errorf("complete level honored ecosystem filter: %v", ids(got))
	}
	if got := runBuild(t, st, Policy{Level: LevelCore, Ecosystems: []string{"pypi"}}).nodesOf(NodeVulnerability); len(got) < 2 {
		t.Errorf("core level honored ecosystem filter: %v", ids(got))
	}
	// Unknown ecosystem selects nothing.
	if got := runBuild(t, st, Policy{Level: LevelEcosystem, Ecosystems: []string{"crates.io"}}).nodesOf(NodeVulnerability); len(got) != 0 {
		t.Errorf("crates.io selected %v", ids(got))
	}
}

func ids(ns []Node) []string {
	var out []string
	for _, n := range ns {
		out = append(out, n.ID)
	}
	return out
}

func TestBuildDeterministic(t *testing.T) {
	st := buildFixtureStore(t)
	for _, pol := range []Policy{{}, {Level: LevelEcosystem, Ecosystems: []string{"npm"}}, {Level: LevelCore}} {
		a, b := runBuild(t, st, pol), runBuild(t, st, pol)
		if !reflect.DeepEqual(a.order, b.order) {
			t.Errorf("emission order differs for %+v", pol)
		}
		for id, n := range a.nodes {
			ha, _ := NodeHash(n)
			hb, _ := NodeHash(b.nodes[id])
			if ha != hb {
				t.Errorf("node %s hash differs", id)
			}
		}
		for id, e := range a.edges {
			ha, _ := EdgeHash(e)
			hb, _ := EdgeHash(b.edges[id])
			if ha != hb {
				t.Errorf("edge %s hash differs", id)
			}
		}
	}
}

func TestBuildRejectsUnknownLevelAndPropagatesEmitError(t *testing.T) {
	st := buildFixtureStore(t)
	called := false
	_, err := Build(context.Background(), st, Policy{Level: "bogus"}, func(Node) error { called = true; return nil }, func(Edge) error { return nil })
	if err == nil || called {
		t.Errorf("unknown level: err=%v called=%v", err, called)
	}
	sentinel := os.ErrClosed
	_, err = Build(context.Background(), st, Policy{}, func(Node) error { return sentinel }, func(Edge) error { return nil })
	if err == nil || !strings.Contains(err.Error(), sentinel.Error()) {
		t.Errorf("emit error not propagated: %v", err)
	}
}
