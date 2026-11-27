package canonical

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

type resFix struct {
	source, id string
	aliases    []string
}

func resolveStore(t *testing.T, fx []resFix) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for _, f := range fx {
		if _, err := s.UpsertRecord(context.Background(), &model.Record{Source: f.source, ID: f.id, Aliases: f.aliases, Modified: time.Unix(1700000000, 0)}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func membership(t *testing.T, s *Store) map[string][]string {
	t.Helper()
	rows, err := s.DB.Query(`SELECT vulnerability_id, source||':'||external_id FROM record_vulnerability ORDER BY 1,2`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	m := map[string][]string{}
	for rows.Next() {
		var v, r string
		rows.Scan(&v, &r)
		m[v] = append(m[v], r)
	}
	return m
}

func countRows(t *testing.T, s *Store, q string) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestResolveExactAliasGrouping(t *testing.T) {
	s := resolveStore(t, []resFix{
		{"nvd", "CVE-2024-0001", nil},
		{"osv", "GHSA-aaaa", []string{"CVE-2024-0001"}},
		{"osv2", "OSV-1", []string{"GHSA-aaaa"}},
		{"osv", "GHSA-zzzz", nil},
	})
	rep, err := s.Resolve(context.Background(), ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m := membership(t, s)
	want := map[string][]string{
		"CVE-2024-0001": {"nvd:CVE-2024-0001", "osv2:OSV-1", "osv:GHSA-aaaa"},
		"GHSA-zzzz":     {"osv:GHSA-zzzz"},
	}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("got %v want %v", m, want)
	}
	if rep.Groups != 2 || rep.Memberships != 4 || rep.NewDecisions != 3 || rep.Collisions != 0 {
		t.Fatalf("report %+v", rep)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM vulnerability_identifier WHERE vulnerability_id='CVE-2024-0001'`); n != 3 {
		t.Fatalf("identifiers: %d", n)
	}
}

func TestResolveBridgingAliasRefused(t *testing.T) {
	s := resolveStore(t, []resFix{
		{"nvd", "CVE-2024-0001", nil},
		{"nvd", "CVE-2024-0002", nil},
		{"osv", "GHSA-a", []string{"CVE-2024-0001"}},
		{"osv", "GHSA-b", []string{"CVE-2024-0002", "GHSA-a"}},
	})
	rep, err := s.Resolve(context.Background(), ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Groups != 2 || rep.Collisions != 1 {
		t.Fatalf("report %+v", rep)
	}
	var left, right string
	if err := s.DB.QueryRow(`SELECT left_id, right_id FROM entity_resolution WHERE method='identifier-collision'`).Scan(&left, &right); err != nil {
		t.Fatal(err)
	}
	if left != "CVE-2024-0001" || right != "CVE-2024-0002" {
		t.Fatalf("collision %s %s", left, right)
	}
	var body string
	s.DB.QueryRow(`SELECT decision FROM entity_resolution WHERE method='identifier-collision'`).Scan(&body)
	if body == "" || !contains(body, "osv:GHSA-b") {
		t.Fatalf("decision should list source records: %s", body)
	}
	if rep2, _ := s.Resolve(context.Background(), ResolveOptions{}); rep2.NewDecisions != 0 || rep2.Collisions != 1 {
		t.Fatalf("second run %+v", rep2)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestResolveMultiCVEAttachesWithoutMerging(t *testing.T) {
	s := resolveStore(t, []resFix{
		{"nvd", "CVE-2024-0001", nil},
		{"nvd", "CVE-2024-0002", nil},
		{"osv", "GHSA-m", []string{"CVE-2024-0001", "CVE-2024-0002"}},
	})
	rep, err := s.Resolve(context.Background(), ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m := membership(t, s)
	if rep.Groups != 2 || len(m["CVE-2024-0001"]) != 2 || len(m["CVE-2024-0002"]) != 2 {
		t.Fatalf("report %+v members %v", rep, m)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM record_vulnerability WHERE method='multi-cve'`); n != 2 {
		t.Fatalf("multi-cve rows %d", n)
	}
	if rep.Collisions != 0 {
		t.Fatal("unexpected collision")
	}
}

func TestResolveCVELessGroupKeyedBySmallestIdentifier(t *testing.T) {
	s := resolveStore(t, []resFix{
		{"osv", "GHSA-b", []string{"PYSEC-1"}},
		{"osv2", "PYSEC-1", []string{"GHSA-a"}},
	})
	if _, err := s.Resolve(context.Background(), ResolveOptions{}); err != nil {
		t.Fatal(err)
	}
	m := membership(t, s)
	if len(m) != 1 || len(m["GHSA-a"]) != 2 {
		t.Fatalf("membership %v", m)
	}
}

func TestResolveIdempotentPreservesDecisionTime(t *testing.T) {
	s := resolveStore(t, []resFix{
		{"nvd", "CVE-2024-0001", nil},
		{"osv", "GHSA-a", []string{"CVE-2024-0001"}},
	})
	clk := &resClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	s.SetClock(clk)
	r1, _ := s.Resolve(context.Background(), ResolveOptions{})
	clk.t = clk.t.Add(time.Hour)
	r2, err := s.Resolve(context.Background(), ResolveOptions{})
	if err != nil || r1.NewDecisions == 0 || r2.NewDecisions != 0 || r2.Groups != r1.Groups {
		t.Fatalf("%+v %+v %v", r1, r2, err)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM entity_resolution WHERE recorded_at<>'2024-01-01T00:00:00.000Z'`); n != 0 {
		t.Fatalf("decision time changed for %d rows", n)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM source_record`); n != 2 {
		t.Fatal("source_record changed")
	}
}

type resClock struct{ t time.Time }

func (c *resClock) Now() time.Time { return c.t }

func TestResolveOrderIndependent(t *testing.T) {
	fx := []resFix{
		{"nvd", "CVE-2024-0001", nil},
		{"nvd", "CVE-2024-0002", nil},
		{"osv", "GHSA-a", []string{"CVE-2024-0001", "X-1"}},
		{"osv", "GHSA-b", []string{"CVE-2024-0002", "X-1"}},
		{"osv", "GHSA-c", []string{"X-1", "Y-9"}},
		{"gh", "GHSA-m", []string{"CVE-2024-0001", "CVE-2024-0002"}},
		{"gh", "GHSA-l1", []string{"L-2"}},
		{"gh", "GHSA-l2", []string{"L-2", "L-1"}},
	}
	snapshot := func(s *Store) string {
		rows, _ := s.DB.Query(`SELECT 'm',vulnerability_id,source,external_id,method FROM record_vulnerability
UNION ALL SELECT 'i',vulnerability_id,value,'','' FROM vulnerability_identifier
UNION ALL SELECT 'v',id,'','','' FROM vulnerability
UNION ALL SELECT 'd',left_id,right_id,method,decision FROM entity_resolution`)
		defer rows.Close()
		var out []string
		for rows.Next() {
			var a, b, c, d, e string
			rows.Scan(&a, &b, &c, &d, &e)
			out = append(out, fmt.Sprint(a, b, c, d, e))
		}
		sort.Strings(out)
		return fmt.Sprint(out)
	}
	var base string
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 8; i++ {
		perm := append([]resFix(nil), fx...)
		rng.Shuffle(len(perm), func(a, b int) { perm[a], perm[b] = perm[b], perm[a] })
		s := resolveStore(t, perm)
		if _, err := s.Resolve(context.Background(), ResolveOptions{}); err != nil {
			t.Fatal(err)
		}
		got := snapshot(s)
		if i == 0 {
			base = got
		} else if got != base {
			t.Fatalf("order dependent result:\n%s\n%s", base, got)
		}
	}
}

func fuzzyRec(src, id, summary string, aliases []string, pkg string) *model.Record {
	return &model.Record{Source: src, ID: id, Aliases: aliases, Summary: summary, Modified: time.Unix(1700000000, 0),
		Affected: []model.Affected{{Kind: "package", Ecosystem: "npm", Name: pkg}}}
}

func TestResolveFuzzyCandidatesLeaveGroupsUnchanged(t *testing.T) {
	s := resolveStore(t, nil)
	ctx := context.Background()
	for _, r := range []*model.Record{
		fuzzyRec("osv", "GHSA-aaaa", "Prototype pollution in lodash merge function", []string{"CVE-2024-1111"}, "lodash"),
		fuzzyRec("osv", "GHSA-bbbb", "Prototype pollution in lodash merge function allows", []string{"CVE-2024-2222"}, "Lodash"),
		fuzzyRec("osv", "GHSA-cccc", "Completely unrelated text about parsing", []string{"CVE-2024-3333"}, "lodash"),
	} {
		if _, err := s.UpsertRecord(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	base, err := s.Resolve(ctx, ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM candidate_pair`); n != 0 {
		t.Fatalf("fuzzy off wrote %d candidates", n)
	}
	before := membership(t, s)
	nv := countRows(t, s, `SELECT COUNT(*) FROM vulnerability`)
	ne := countRows(t, s, `SELECT COUNT(*) FROM entity_resolution`)
	for i := 0; i < 2; i++ {
		rep, err := s.Resolve(ctx, ResolveOptions{Fuzzy: true, FuzzyThreshold: 0.7})
		if err != nil {
			t.Fatal(err)
		}
		if rep.Groups != base.Groups || rep.Memberships != base.Memberships {
			t.Fatalf("report changed: %+v vs %+v", rep, base)
		}
		var l, r string
		var sc float64
		if n := countRows(t, s, `SELECT COUNT(*) FROM candidate_pair`); n != 1 {
			t.Fatalf("candidates = %d", n)
		}
		if err := s.DB.QueryRow(`SELECT left_id,right_id,score FROM candidate_pair`).Scan(&l, &r, &sc); err != nil {
			t.Fatal(err)
		}
		if l != "osv:GHSA-aaaa" || r != "osv:GHSA-bbbb" || sc < 0.7 || sc > 1 {
			t.Fatalf("pair %s %s %v", l, r, sc)
		}
	}
	if !reflect.DeepEqual(before, membership(t, s)) ||
		nv != countRows(t, s, `SELECT COUNT(*) FROM vulnerability`) ||
		ne != countRows(t, s, `SELECT COUNT(*) FROM entity_resolution`) {
		t.Fatal("fuzzy changed resolution tables")
	}
	if _, err := s.Resolve(ctx, ResolveOptions{}); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM candidate_pair`); n != 0 {
		t.Fatalf("candidates not reconciled away: %d", n)
	}
}

func TestResolveLinksPendingEnrichment(t *testing.T) {
	s := resolveStore(t, nil)
	ctx := context.Background()
	if _, err := s.UpsertKEV(ctx, model.KEV{CVE: "CVE-2024-0001"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertEPSS(ctx, model.EPSS{CVE: "CVE-2024-0001", Score: 0.5, Percentile: 0.9, Date: "2024-01-01"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertRecord(ctx, &model.Record{Source: "nvd", ID: "CVE-2024-0001", Modified: time.Unix(1700000000, 0)}); err != nil {
		t.Fatal(err)
	}
	rep, err := s.Resolve(ctx, ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.LinkedEnrichment != 2 {
		t.Fatalf("LinkedEnrichment = %d", rep.LinkedEnrichment)
	}
	v, _ := s.Enrichment(ctx, "CVE-2024-0001")
	if v.KEV == nil || v.EPSS == nil {
		t.Fatalf("enrichment not linked: %+v", v)
	}
}
