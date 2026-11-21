package upsert

import (
	"testing"
	"time"

	"github.com/bellu/bskg/internal/change"
	"github.com/bellu/bskg/internal/resolve"
	"github.com/bellu/bskg/internal/source"
)

var t0 = time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

func rc(src string, bulk bool) RunContext {
	return RunContext{Source: src, RunID: "run1", Now: t0, Bulk: bulk}
}

func emptyState() State {
	return State{Nodes: map[resolve.Key]map[string]any{}, Rels: map[RelID]map[string]any{}}
}

// fold applies writes to a state the way Apply would in the database.
func fold(st State, w Writes) State {
	merge := func(dst map[string]any, props map[string]any) {
		for k, v := range props {
			if v == nil {
				delete(dst, k)
			} else {
				dst[k] = v
			}
		}
		srcs, _ := dst["sources"].([]string)
		for _, s := range srcs {
			if s == w.Source {
				return
			}
		}
		dst["sources"] = append(srcs, w.Source)
	}
	for _, n := range w.Nodes {
		m := st.Nodes[n.Key]
		if m == nil {
			m = map[string]any{n.Key.Prop: n.Key.Value}
			st.Nodes[n.Key] = m
		}
		merge(m, n.Props)
	}
	for _, r := range w.Rels {
		id := RelID{Type: r.Type, From: r.From, To: r.To, Ident: ident(identNames(r.Type), r.Key)}
		m := st.Rels[id]
		if m == nil {
			m = map[string]any{}
			st.Rels[id] = m
		}
		merge(m, r.Props)
	}
	return st
}

func identNames(typ string) []string {
	if typ == "CHILD_OF" {
		return []string{"viewID"}
	}
	return nil
}

func cve(id string) source.Ref     { return source.Ref{Kind: source.RefCVE, Raw: id} }
func cwe(id string) source.Ref     { return source.Ref{Kind: source.RefCWE, Raw: id} }
func exploit(id string) source.Ref { return source.Ref{Kind: source.RefExploit, Raw: id} }

func types(recs []change.Record) map[string]int {
	m := map[string]int{}
	for _, r := range recs {
		m[r.Type]++
	}
	return m
}

func nvdBatch(desc string) Batch {
	return Batch{{ID: "CVE-2021-1001", N: source.Normalized{
		Entities: []source.Entity{
			{Ref: cve("cve-2021-1001"), Props: map[string]any{"description": desc}},
			{Ref: cwe("79"), Props: nil, Clear: nil},
		},
		Rels:   []source.Rel{{From: cve("CVE-2021-1001"), To: source.Ref{Kind: source.RefCWE, Raw: "CWE-79", MustExist: true}, Type: "EXAMPLE_OF"}},
		Anchor: &source.Ref{Kind: source.RefCVE, Raw: "CVE-2021-1001"},
		Owned:  []source.OwnedRel{{Type: "EXAMPLE_OF"}},
	}}}
}

func TestPlanCreateAndIdempotent(t *testing.T) {
	st := emptyState()
	w, recs, cnt := Plan(st, nvdBatch("a"), rc("nvd", false))
	if cnt.Created != 1 || len(w.Nodes) != 2 || len(w.Rels) != 1 {
		t.Fatalf("counts %+v writes %+v", cnt, w)
	}
	vk := resolve.Key{Label: "Vulnerability", Prop: "cveID", Value: "CVE-2021-1001"}
	var props map[string]any
	for _, n := range w.Nodes {
		if n.Key == vk {
			props = n.Props
		}
	}
	if props["exploitability"] != int64(0) || props["exploitDate"] == nil || props["description"] != "a" {
		t.Fatalf("new vulnerability props: %v", props)
	}
	if got := types(recs); got[TypeEntityCreated] != 2 || got[TypeRelationshipCreated] != 1 {
		t.Fatalf("records %v", got)
	}
	st = fold(st, w)
	w2, recs2, cnt2 := Plan(st, nvdBatch("a"), rc("nvd", false))
	if len(w2.Nodes)+len(w2.Rels) != 0 || len(recs2) != 0 || cnt2.Unchanged != 1 {
		t.Fatalf("repeat run wrote: %+v %v %+v", w2, recs2, cnt2)
	}
}

func TestPlanChangesOnlyDifferingProperty(t *testing.T) {
	st := fold(emptyState(), func() Writes { w, _, _ := Plan(emptyState(), nvdBatch("a"), rc("nvd", false)); return w }())
	w, recs, cnt := Plan(st, nvdBatch("b"), rc("nvd", false))
	if cnt.Updated != 1 || len(recs) != 1 || recs[0].Type != TypePropertyChanged || recs[0].Field != "description" ||
		recs[0].OldValue != `"a"` || recs[0].NewValue != `"b"` {
		t.Fatalf("recs %+v cnt %+v", recs, cnt)
	}
	if len(w.Nodes) != 1 || len(w.Rels) != 0 {
		t.Fatalf("writes %+v", w)
	}
}

func TestPlanBulkRule(t *testing.T) {
	_, recs, _ := Plan(emptyState(), nvdBatch("a"), rc("nvd", true))
	// Vulnerability and Weakness get a key-only entityCreated; the relationship
	// created with its start node gets no record.
	got := types(recs)
	if got[TypeEntityCreated] != 2 || got[TypeRelationshipCreated] != 0 {
		t.Fatalf("bulk records %v", got)
	}
	for _, r := range recs {
		if r.NewValue != `{"cveID":"CVE-2021-1001"}` && r.NewValue != `{"cweID":"CWE-79"}` {
			t.Fatalf("bulk newValue %s", r.NewValue)
		}
	}
	// Product (other label) gets no creation record in bulk mode.
	b := Batch{{ID: "x", N: source.Normalized{Entities: []source.Entity{{Ref: source.Ref{Kind: source.RefVendor, Raw: "acme"}}}}}}
	if _, recs, _ := Plan(emptyState(), b, rc("nvd", true)); len(recs) != 0 {
		t.Fatalf("vendor record in bulk mode: %v", recs)
	}
}

func TestPlanMustExistNeverCreates(t *testing.T) {
	b := Batch{{ID: "CVE-2021-1001", N: source.Normalized{
		Entities: []source.Entity{{Ref: cve("CVE-2021-1001")}},
		Rels:     []source.Rel{{From: cve("CVE-2021-1001"), To: source.Ref{Kind: source.RefCWE, Raw: "79", MustExist: true}, Type: "EXAMPLE_OF"}},
	}}}
	w, _, cnt := Plan(emptyState(), b, rc("nvd", false))
	if len(w.Rels) != 0 || cnt.Unresolved != 1 {
		t.Fatalf("rels %v cnt %+v", w.Rels, cnt)
	}
	for _, n := range w.Nodes {
		if n.Key.Label == "Weakness" {
			t.Fatal("Weakness created")
		}
	}
	// Unresolved reference form (NVD-CWE-Other) is counted, not rejected.
	b[0].N.Rels[0].To = source.Ref{Kind: source.RefCWE, Raw: "NVD-CWE-Other", MustExist: true}
	if _, _, cnt := Plan(emptyState(), b, rc("nvd", false)); cnt.Unresolved != 1 || cnt.Rejected != 0 {
		t.Fatalf("cnt %+v", cnt)
	}
}

func exploitBatch(withRel bool) Batch {
	n := source.Normalized{
		Gate:     []source.Ref{cve("CVE-2021-1001")},
		Entities: []source.Entity{{Ref: exploit("42"), Props: map[string]any{"exploitPublishDate": time.Date(2020, 5, 6, 0, 0, 0, 0, time.UTC)}}},
		Anchor:   &source.Ref{Kind: source.RefExploit, Raw: "42"},
		Owned:    []source.OwnedRel{{Type: "EXPLOITS"}},
	}
	if withRel {
		n.Rels = []source.Rel{{From: exploit("42"), To: source.Ref{Kind: source.RefCVE, Raw: "CVE-2021-1001", MustExist: true}, Type: "EXPLOITS"}}
	}
	return Batch{{ID: "42", N: n}}
}

func TestPlanGateSkips(t *testing.T) {
	w, _, cnt := Plan(emptyState(), exploitBatch(true), rc("exploitdb", false))
	if cnt.Skipped != 1 || len(w.Nodes) != 0 {
		t.Fatalf("cnt %+v w %+v", cnt, w)
	}
}

func TestPlanRemovalAndRestore(t *testing.T) {
	st := fold(emptyState(), func() Writes { w, _, _ := Plan(emptyState(), nvdBatch("a"), rc("nvd", false)); return w }())
	vk := resolve.Key{Label: "Vulnerability", Prop: "cveID", Value: "CVE-2021-1001"}
	st = fold(st, func() Writes {
		w, _, _ := Plan(st, Batch{{ID: "e", N: source.Normalized{Entities: []source.Entity{{Ref: exploit("42")}}}}}, rc("exploitdb", false))
		return w
	}())
	st = fold(st, func() Writes { w, _, _ := Plan(st, exploitBatch(true), rc("exploitdb", false)); return w }())
	var xid RelID
	for id := range st.Rels {
		if id.Type == "EXPLOITS" {
			xid = id
		}
	}
	if xid.To != vk {
		t.Fatal("EXPLOITS not created")
	}
	// Source drops the relationship.
	w, recs, _ := Plan(st, exploitBatch(false), rc("exploitdb", false))
	if len(w.Rels) != 1 || w.Rels[0].Props["p_exploitdb_removed"] != true || w.Rels[0].Props["removed"] != true ||
		types(recs)[TypeRelationshipRemoved] != 1 || len(w.RecomputeCVEs) != 1 || w.RecomputeCVEs[0] != "CVE-2021-1001" {
		t.Fatalf("removal: %+v %v", w, recs)
	}
	st = fold(st, w)
	// Removed again: nothing more to do.
	if w2, _, _ := Plan(st, exploitBatch(false), rc("exploitdb", false)); len(w2.Rels) != 0 {
		t.Fatalf("second removal wrote %+v", w2.Rels)
	}
	// Re-asserted: flag cleared, derived removed cleared, created record.
	w3, recs3, _ := Plan(st, exploitBatch(true), rc("exploitdb", false))
	if len(w3.Rels) != 1 || w3.Rels[0].Props["p_exploitdb_removed"] != nil || w3.Rels[0].Props["removed"] != nil ||
		types(recs3)[TypeRelationshipCreated] != 1 || len(w3.RecomputeCVEs) != 1 {
		t.Fatalf("restore: %+v %v", w3, recs3)
	}
	if _, ok := w3.Rels[0].Props["removed"]; !ok {
		t.Fatal("restore must write removed=null to clear it")
	}
}

func TestPlanRelationshipIdentityKey(t *testing.T) {
	b := Batch{{ID: "x", N: source.Normalized{
		Entities: []source.Entity{{Ref: cwe("1")}, {Ref: cwe("2")}},
		Rels: []source.Rel{
			{From: cwe("1"), To: cwe("2"), Type: "CHILD_OF", Key: map[string]any{"viewID": "1000"}},
			{From: cwe("1"), To: cwe("2"), Type: "CHILD_OF", Key: map[string]any{"viewID": "699"}},
			{From: cwe("1"), To: cwe("2"), Type: "CHILD_OF"}, // missing identity: rejected
		},
	}}}
	w, _, cnt := Plan(emptyState(), b, rc("cwe", false))
	if len(w.Rels) != 2 || cnt.Rejected != 1 {
		t.Fatalf("rels %d cnt %+v", len(w.Rels), cnt)
	}
}

func TestEqualValue(t *testing.T) {
	d1 := time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		a, b any
		eq   bool
	}{
		{int64(3), 3.0, true},
		{int64(3), 4.0, false},
		{d1, d1.In(time.FixedZone("x", 0)), true},
		{[]string{"a", "b"}, []any{"a", "b"}, true},
		{[]string{"a", "b"}, []string{"b", "a"}, false},
		{nil, "x", false},
	}
	for i, c := range cases {
		if equalValue(c.a, c.b) != c.eq {
			t.Errorf("case %d: %v vs %v want %v", i, c.a, c.b, c.eq)
		}
	}
}

func TestPlanExploitDateChangeRecomputes(t *testing.T) {
	st := emptyState()
	vk := resolve.Key{Label: "Vulnerability", Prop: "cveID", Value: "CVE-2021-1001"}
	ek := resolve.Key{Label: "Exploit", Prop: "eid", Value: "42"}
	st.Nodes[vk] = map[string]any{"cveID": "CVE-2021-1001"}
	st.Nodes[ek] = map[string]any{"eid": "42", "exploitPublishDate": time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC), "sources": []any{"exploitdb"}}
	st.Rels[RelID{Type: "EXPLOITS", From: ek, To: vk}] = map[string]any{"sources": []any{"exploitdb"}}
	w, _, _ := Plan(st, exploitBatch(true), rc("exploitdb", false))
	if len(w.RecomputeCVEs) != 1 || w.RecomputeCVEs[0] != "CVE-2021-1001" {
		t.Fatalf("recompute %v", w.RecomputeCVEs)
	}
}
