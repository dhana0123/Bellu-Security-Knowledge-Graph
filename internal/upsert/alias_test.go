package upsert

import (
	"reflect"
	"strconv"
	"testing"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/change"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/resolve"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
)

const ghsa = "GHSA-c2f3-4gh5-wxmp"

func advRef(id string) source.Ref { return source.Ref{Kind: source.RefAdvisory, Raw: id} }
func pkgRef(p string) source.Ref  { return source.Ref{Kind: source.RefPackage, Raw: p} }

func vkey(id string) resolve.Key {
	return resolve.Key{Label: "Vulnerability", Prop: "cveID", Value: id}
}

// advBatch is what an OSV or GHSA adapter returns for one advisory.
func advBatch(adv *source.Advisory) Batch {
	return Batch{{ID: ghsa, N: source.Normalized{
		Advisory: adv,
		Entities: []source.Entity{
			{Ref: advRef(ghsa), Props: map[string]any{"description": "d"}},
			{Ref: pkgRef("pkg:npm/lodash")},
		},
		Rels: []source.Rel{{From: advRef(ghsa), To: pkgRef("pkg:npm/lodash"), Type: "AFFECTS_PACKAGE",
			Props: map[string]any{"introduced": "1.0.0"}}},
		Anchor: &source.Ref{Kind: source.RefAdvisory, Raw: ghsa},
		Owned:  []source.OwnedRel{{Type: "AFFECTS_PACKAGE"}},
	}}}
}

// foldMerges applies the planned merges to st the way Apply does.
func foldMerges(st State, w Writes) State {
	for _, m := range w.Merges {
		from := st.Nodes[m.From]
		delete(st.Nodes, m.From)
		if st.Nodes[m.Into] == nil {
			st.Nodes[m.Into] = map[string]any{"cveID": m.Into.Value}
		}
		st.Nodes[m.Into]["aliases"] = unionAliases(m.Into.Value, stringsOf(st.Nodes[m.Into]["aliases"]),
			append([]string{m.From.Value}, stringsOf(from["aliases"])...))
	}
	return fold(st, w)
}

func nodeProps(w Writes, k resolve.Key) map[string]any {
	for _, n := range w.Nodes {
		if n.Key == k {
			return n.Props
		}
	}
	return nil
}

func TestAliasNoCVEKeepsAdvisoryNode(t *testing.T) {
	adv := &source.Advisory{ID: "ghsa-C2F3-4GH5-WXMP", OtherAliases: []string{"PYSEC-2021-1", " ", "PYSEC-2021-1"}}
	w, recs, cnt := Plan(emptyState(), advBatch(adv), rc("ghsa", false))
	k := vkey(ghsa)
	p := nodeProps(w, k)
	if p == nil || p["description"] != "d" || p["exploitability"] != int64(0) || p["exploitDate"] == nil {
		t.Fatalf("advisory node props %v", p)
	}
	if !reflect.DeepEqual(p["aliases"], []string{"PYSEC-2021-1"}) {
		t.Fatalf("aliases %v", p["aliases"])
	}
	if len(w.Rels) != 1 || w.Rels[0].From != k || len(w.Merges) != 0 || cnt.Created != 1 {
		t.Fatalf("writes %+v cnt %+v", w, cnt)
	}
	if got := types(recs); got[TypeVulnerabilityMerged]+got[TypeAliasConflict] != 0 {
		t.Fatalf("records %v", got)
	}
}

func TestAliasSingleCVECreatesTargetAndAliases(t *testing.T) {
	adv := &source.Advisory{ID: ghsa, CVEs: []string{"cve-2021-1001"}, OtherAliases: []string{"PYSEC-2021-1"}}
	w, recs, _ := Plan(emptyState(), advBatch(adv), rc("ghsa", false))
	cveK := vkey("CVE-2021-1001")
	p := nodeProps(w, cveK)
	if p == nil || p["description"] != "d" || p["exploitability"] != int64(0) {
		t.Fatalf("CVE node props %v", p)
	}
	if !reflect.DeepEqual(p["aliases"], []string{ghsa, "PYSEC-2021-1"}) {
		t.Fatalf("aliases %v", p["aliases"])
	}
	if nodeProps(w, vkey(ghsa)) != nil {
		t.Fatal("advisory node must not be created when a CVE alias exists")
	}
	if len(w.Rels) != 1 || w.Rels[0].From != cveK || len(w.Merges) != 0 {
		t.Fatalf("rels %+v merges %+v", w.Rels, w.Merges)
	}
	if got := types(recs); got[TypeVulnerabilityMerged]+got[TypeAliasConflict] != 0 {
		t.Fatalf("records %v", got)
	}
}

func TestAliasMergesExistingAdvisoryNode(t *testing.T) {
	// An earlier run stored the advisory without CVE alias; NVD has the CVE.
	st := emptyState()
	st.Nodes[vkey(ghsa)] = map[string]any{"cveID": ghsa, "aliases": []any{"PYSEC-2021-1"}, "sources": []any{"ghsa"}}
	st.Nodes[vkey("CVE-2021-1001")] = map[string]any{"cveID": "CVE-2021-1001", "sources": []any{"nvd"}, "aliases": []any{"X-1"}}
	adv := &source.Advisory{ID: ghsa, CVEs: []string{"CVE-2021-1001"}}
	w, recs, cnt := Plan(st, advBatch(adv), rc("ghsa", false))
	if !reflect.DeepEqual(w.Merges, []MergeWrite{{From: vkey(ghsa), Into: vkey("CVE-2021-1001")}}) {
		t.Fatalf("merges %+v", w.Merges)
	}
	var merged []change.Record
	for _, r := range recs {
		if r.Type == TypeVulnerabilityMerged {
			merged = append(merged, r)
		}
	}
	if len(merged) != 1 || merged[0].EntityKey != "Vulnerability:CVE-2021-1001" ||
		merged[0].OldValue != `["Vulnerability:`+ghsa+`","Vulnerability:CVE-2021-1001"]` ||
		merged[0].NewValue != `"Vulnerability:CVE-2021-1001"` {
		t.Fatalf("merge records %+v", merged)
	}
	if nodeProps(w, vkey(ghsa)) != nil {
		t.Fatal("merged-away node must not be written")
	}
	p := nodeProps(w, vkey("CVE-2021-1001"))
	if !reflect.DeepEqual(p["aliases"], []string{"X-1", ghsa, "PYSEC-2021-1"}) {
		t.Fatalf("aliases %v", p["aliases"])
	}
	if !reflect.DeepEqual(w.RecomputeCVEs, []string{"CVE-2021-1001"}) || cnt.Created != 1 {
		t.Fatalf("recompute %v cnt %+v", w.RecomputeCVEs, cnt)
	}
	// Re-run on the folded state: nothing to do.
	st = foldMerges(st, w)
	w2, recs2, cnt2 := Plan(st, advBatch(adv), rc("ghsa", false))
	if len(w2.Merges) != 0 || len(w2.Nodes)+len(w2.Rels) != 0 || len(recs2) != 0 || cnt2.Unchanged != 1 {
		t.Fatalf("re-run: %+v %v %+v", w2, recs2, cnt2)
	}
}

func TestAliasMultipleCVEsNeverMerge(t *testing.T) {
	st := emptyState()
	st.Nodes[vkey(ghsa)] = map[string]any{"cveID": ghsa}
	adv := &source.Advisory{ID: ghsa, CVEs: []string{"CVE-2021-1002", "CVE-2021-1001", "cve-2021-1001", "not-a-cve"}}
	w, recs, cnt := Plan(st, advBatch(adv), rc("ghsa", false))
	if len(w.Merges) != 0 || len(w.Rels) != 2 || cnt.Rejected != 1 {
		t.Fatalf("writes %+v cnt %+v", w, cnt)
	}
	for _, id := range []string{"CVE-2021-1001", "CVE-2021-1002"} {
		p := nodeProps(w, vkey(id))
		if p == nil || !reflect.DeepEqual(p["aliases"], []string{ghsa}) || p["description"] != "d" {
			t.Fatalf("%s props %v", id, p)
		}
	}
	var conf []change.Record
	for _, r := range recs {
		if r.Type == TypeAliasConflict {
			conf = append(conf, r)
		}
	}
	if len(conf) != 1 || conf[0].EntityKey != "Vulnerability:"+ghsa || conf[0].NewValue != `["CVE-2021-1001","CVE-2021-1002"]` {
		t.Fatalf("conflict records %+v", conf)
	}
	st = foldMerges(st, w)
	_, recs2, _ := Plan(st, advBatch(adv), rc("ghsa", false))
	if types(recs2)[TypeAliasConflict] != 0 {
		t.Fatalf("conflict record repeated: %v", recs2)
	}
}

func TestAliasLeavesOtherAdvisoryRefsAlone(t *testing.T) {
	other := "GO-2021-0113"
	b := advBatch(&source.Advisory{ID: ghsa, CVEs: []string{"CVE-2021-1001"}})
	b[0].N.Entities = append(b[0].N.Entities, source.Entity{Ref: advRef(other)})
	w, _, _ := Plan(emptyState(), b, rc("ghsa", false))
	if nodeProps(w, vkey(other)) == nil {
		t.Fatalf("a different advisory id must keep its own node: %+v", w.Nodes)
	}
}

func TestAliasCap(t *testing.T) {
	var many []string
	for i := 0; i < 150; i++ {
		many = append(many, "ALIAS-"+strconv.Itoa(i))
	}
	got := unionAliases("CVE-1", []string{"A", "B"}, many)
	if len(got) != MaxAliases || got[0] != "A" || got[1] != "B" {
		t.Fatalf("len %d head %v", len(got), got[:3])
	}
	if got := unionAliases("S", []string{"S", "A"}, []string{"A", "B", ""}); !reflect.DeepEqual(got, []string{"A", "B"}) {
		t.Fatalf("dedupe %v", got)
	}
}

func TestExpandAdvisoryWithoutAdvisoryIsIdentity(t *testing.T) {
	n := source.Normalized{Entities: []source.Entity{{Ref: advRef(ghsa)}}}
	out, ap := expandAdvisory(n)
	if ap != nil || !reflect.DeepEqual(out, n) {
		t.Fatalf("got %+v %v", out, ap)
	}
}
