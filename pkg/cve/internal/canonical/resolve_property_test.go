package canonical

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

type resProp struct {
	source, id string
	aliases    []string
	summary    string
}

func (r resProp) key() string { return r.source + ":" + r.id }

// ids returns the trimmed identifier set of the record (external id plus aliases).
func (r resProp) ids() []string {
	set := map[string]bool{}
	for _, x := range append([]string{r.id}, r.aliases...) {
		if x = strings.TrimSpace(x); x != "" {
			set[x] = true
		}
	}
	var out []string
	for x := range set {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func (r resProp) cves() []string {
	var out []string
	for _, x := range r.ids() {
		if model.IsCVE(x) {
			out = append(out, x)
		}
	}
	return out
}

var resPool = []string{
	"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003",
	"GHSA-aaaa-0001", "GHSA-aaaa-0002", "GHSA-aaaa-0003",
	"OSV-2024-1", "OSV-2024-2", "OSV-2024-3",
}

func drawResRecords(t *rapid.T, pool []string, maxN int) []resProp {
	n := rapid.IntRange(1, maxN).Draw(t, "n")
	seen := map[string]bool{}
	var out []resProp
	for i := 0; i < n; i++ {
		r := resProp{
			source:  rapid.SampledFrom([]string{"nvd", "osv", "ghsa"}).Draw(t, "src"),
			id:      rapid.SampledFrom(pool).Draw(t, "id"),
			summary: rapid.SampledFrom([]string{"same text", "same text", "other"}).Draw(t, "sum"),
		}
		for _, a := range rapid.SliceOfN(rapid.SampledFrom(pool), 0, 3).Draw(t, "aliases") {
			if rapid.Bool().Draw(t, "pad") {
				a = " " + a + " "
			}
			r.aliases = append(r.aliases, a)
		}
		if seen[r.key()] {
			continue
		}
		seen[r.key()] = true
		out = append(out, r)
	}
	return out
}

func resPropStore(t *rapid.T, recs []resProp) *Store {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	s.SetClock(&fakeClock{t: time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)})
	for _, r := range recs {
		_, err := s.UpsertRecord(context.Background(), &model.Record{
			Source: r.source, ID: r.id, Aliases: r.aliases, Summary: r.summary,
			Modified: time.Unix(1700000000, 0),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func resRows(t *rapid.T, s *Store, q string) []string {
	rows, err := s.DB.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%q", vals))
	}
	sort.Strings(out)
	return out
}

// resState captures the resolution tables, without recorded_at.
func resState(t *rapid.T, s *Store) map[string][]string {
	return map[string][]string{
		"vulnerability":            resRows(t, s, `SELECT * FROM vulnerability`),
		"vulnerability_identifier": resRows(t, s, `SELECT value, vulnerability_id FROM vulnerability_identifier`),
		"record_vulnerability":     resRows(t, s, `SELECT source, external_id, vulnerability_id, method FROM record_vulnerability`),
		"entity_resolution":        resRows(t, s, `SELECT left_id, right_id, decision, confidence, method FROM entity_resolution`),
	}
}

// groupsOf returns record key -> sorted vulnerability ids, and vulnerability id -> member keys.
func groupsOf(t *rapid.T, s *Store) (map[string][]string, map[string][]string) {
	rows, err := s.DB.Query(`SELECT source||':'||external_id, vulnerability_id FROM record_vulnerability`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	byRec, byVuln := map[string][]string{}, map[string][]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			t.Fatal(err)
		}
		byRec[k] = append(byRec[k], v)
		byVuln[v] = append(byVuln[v], k)
	}
	for _, m := range []map[string][]string{byRec, byVuln} {
		for k := range m {
			sort.Strings(m[k])
		}
	}
	return byRec, byVuln
}

func resolveOnce(t *rapid.T, s *Store) ResolveReport {
	rep, err := s.Resolve(context.Background(), ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func shareID(a, b resProp) bool {
	set := map[string]bool{}
	for _, x := range a.ids() {
		set[x] = true
	}
	for _, x := range b.ids() {
		if set[x] {
			return true
		}
	}
	return false
}

func noTwoCVEs(t *rapid.T, s *Store) {
	rows, err := s.DB.Query(`SELECT vulnerability_id, value FROM vulnerability_identifier`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cves := map[string]map[string]bool{}
	for rows.Next() {
		var v, x string
		if err := rows.Scan(&v, &x); err != nil {
			t.Fatal(err)
		}
		if model.IsCVE(x) {
			if cves[v] == nil {
				cves[v] = map[string]bool{}
			}
			cves[v][x] = true
		}
	}
	for v, set := range cves {
		if len(set) > 1 {
			t.Fatalf("vulnerability %s holds distinct CVEs %v", v, set)
		}
	}
}

// Feature: bellu-security-knowledge-graph, Property 15: Resolution partitions by exact identifiers with a CVE guard
// Validates: Requirements 5.1, 5.2, 5.3, 5.6
func TestProp15ResolutionPartitionsByExactIdentifiers(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		recs := drawResRecords(t, resPool, 8)
		s := resPropStore(t, recs)
		defer s.Close()
		rep := resolveOnce(t, s)
		byRec, byVuln := groupsOf(t, s)

		for _, r := range recs {
			if len(byRec[r.key()]) < 1 {
				t.Fatalf("record %s is in no group", r.key())
			}
			// A multi-CVE advisory is a member of exactly its k CVE groups.
			if cv := r.cves(); len(cv) >= 2 && !reflect.DeepEqual(byRec[r.key()], cv) {
				t.Fatalf("multi-CVE record %s in %v, want %v", r.key(), byRec[r.key()], cv)
			}
		}
		noTwoCVEs(t, s)

		sameGroup := func(a, b resProp) bool {
			for _, x := range byRec[a.key()] {
				for _, y := range byRec[b.key()] {
					if x == y {
						return true
					}
				}
			}
			return false
		}
		// Shared identifier implies same group, unless a CVE collision was refused in this run.
		if rep.Collisions == 0 {
			for i, a := range recs {
				for _, b := range recs[i+1:] {
					if len(a.cves()) < 2 && len(b.cves()) < 2 && shareID(a, b) && !sameGroup(a, b) {
						t.Fatalf("%s and %s share an identifier but are in different groups", a.key(), b.key())
					}
				}
			}
		}
		// Every group is connected through shared identifiers (descriptions never merge).
		byKey := map[string]resProp{}
		for _, r := range recs {
			byKey[r.key()] = r
		}
		for v, members := range byVuln {
			seen := map[string]bool{members[0]: true}
			queue := []string{members[0]}
			for len(queue) > 0 {
				cur := queue[0]
				queue = queue[1:]
				for _, m := range members {
					if !seen[m] && shareID(byKey[cur], byKey[m]) {
						seen[m] = true
						queue = append(queue, m)
					}
				}
			}
			if len(seen) != len(members) {
				t.Fatalf("group %s members %v are not connected by shared identifiers", v, members)
			}
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 15: Resolution partitions by exact identifiers with a CVE guard
// Validates: Requirements 5.3
func TestProp15IdenticalSummariesStaySeparate(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(2, 6).Draw(t, "n")
		var recs []resProp
		for i := 0; i < n; i++ {
			recs = append(recs, resProp{source: "osv", id: fmt.Sprintf("GHSA-disj-%04d", i), summary: "identical summary"})
		}
		s := resPropStore(t, recs)
		defer s.Close()
		resolveOnce(t, s)
		_, byVuln := groupsOf(t, s)
		if len(byVuln) != n {
			t.Fatalf("got %d groups, want %d: %v", len(byVuln), n, byVuln)
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 16: Distinct CVEs are never merged
// Validates: Requirements 5.5
func TestProp16DistinctCVEsNeverMerged(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Extras use a pool disjoint from the bridge scenario.
		extraPool := []string{"CVE-2025-0001", "CVE-2025-0002", "GHSA-bbbb-0001", "GHSA-bbbb-0002", "OSV-2025-1"}
		extras := drawResRecords(t, extraPool, 5)
		bridge := []resProp{
			{source: "nvd", id: "CVE-2024-0001"},
			{source: "nvd", id: "CVE-2024-0002"},
			{source: "osv", id: "GHSA-a", aliases: []string{"CVE-2024-0001"}},
			{source: "osv", id: "GHSA-b", aliases: []string{"CVE-2024-0002", "GHSA-a"}},
		}
		recs := append(append([]resProp{}, bridge...), extras...)
		perm := rapid.Permutation(recs).Draw(t, "order")
		s := resPropStore(t, perm)
		defer s.Close()
		srcBefore := resRows(t, s, `SELECT * FROM source_record`)
		rep := resolveOnce(t, s)
		if got := resRows(t, s, `SELECT * FROM source_record`); !reflect.DeepEqual(srcBefore, got) {
			t.Fatal("source_record changed during resolution")
		}
		noTwoCVEs(t, s)
		byRec, _ := groupsOf(t, s)
		if reflect.DeepEqual(byRec["nvd:CVE-2024-0001"], byRec["nvd:CVE-2024-0002"]) {
			t.Fatalf("distinct CVEs merged: %v", byRec)
		}
		if rep.Collisions < 1 {
			t.Fatalf("no collision reported: %+v", rep)
		}
		var body string
		err := s.DB.QueryRow(`SELECT decision FROM entity_resolution WHERE method='identifier-collision' AND left_id='CVE-2024-0001' AND right_id='CVE-2024-0002'`).Scan(&body)
		if err != nil {
			t.Fatal(err)
		}
		var d struct {
			CVEs []string `json:"cve_ids"`
			Recs []string `json:"source_record_ids"`
		}
		if err := json.Unmarshal([]byte(body), &d); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(d.CVEs, []string{"CVE-2024-0001", "CVE-2024-0002"}) || len(d.Recs) == 0 {
			t.Fatalf("collision decision incomplete: %s", body)
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 17: Resolution confluence
// Validates: Requirements 5.9
func TestProp17ResolutionConfluenceRecords(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		recs := drawResRecords(t, resPool, 8)
		order2 := rapid.Permutation(recs).Draw(t, "order")
		s1 := resPropStore(t, recs)
		defer s1.Close()
		s2 := resPropStore(t, order2)
		defer s2.Close()
		resolveOnce(t, s1)
		resolveOnce(t, s2)
		if a, b := resState(t, s1), resState(t, s2); !reflect.DeepEqual(a, b) {
			t.Fatalf("resolution depends on order:\n%v\n%v", a, b)
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 18: Resolution idempotence and non-mutation
// Validates: Requirements 5.7, 5.8, 5.10
func TestProp18ResolutionIdempotenceNonMutation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		recs := drawResRecords(t, resPool, 8)
		s := resPropStore(t, recs)
		defer s.Close()
		src0 := resRows(t, s, `SELECT * FROM source_record`)
		resolveOnce(t, s)
		src1 := resRows(t, s, `SELECT * FROM source_record`)
		st1 := resState(t, s)
		decTimes := resRows(t, s, `SELECT left_id, right_id, method, recorded_at FROM entity_resolution`)

		rep := resolveOnce(t, s)
		if rep.NewDecisions != 0 {
			t.Fatalf("second run created %d decisions", rep.NewDecisions)
		}
		if st2 := resState(t, s); !reflect.DeepEqual(st1, st2) {
			t.Fatalf("tables changed on second run:\n%v\n%v", st1, st2)
		}
		if got := resRows(t, s, `SELECT left_id, right_id, method, recorded_at FROM entity_resolution`); !reflect.DeepEqual(decTimes, got) {
			t.Fatal("decision rows changed on second run")
		}
		if src2 := resRows(t, s, `SELECT * FROM source_record`); !reflect.DeepEqual(src0, src1) || !reflect.DeepEqual(src1, src2) {
			t.Fatal("source_record changed by resolution")
		}

		// Every decision carries a rule, matched identifiers, record ids and a decision time.
		rows, err := s.DB.Query(`SELECT decision, method, COALESCE(recorded_at,'') FROM entity_resolution`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var body, method, at string
			if err := rows.Scan(&body, &method, &at); err != nil {
				t.Fatal(err)
			}
			var d struct {
				Rule    string   `json:"rule"`
				Matched []string `json:"matched"`
				CVEs    []string `json:"cve_ids"`
				Recs    []string `json:"source_record_ids"`
			}
			if err := json.Unmarshal([]byte(body), &d); err != nil {
				t.Fatal(err)
			}
			if d.Rule == "" || d.Rule != method || len(d.Recs) == 0 || at == "" || len(d.Matched)+len(d.CVEs) == 0 {
				t.Fatalf("incomplete decision %s (method %s, at %q)", body, method, at)
			}
		}
	})
}
