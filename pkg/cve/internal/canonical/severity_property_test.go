package canonical

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/osv"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// Feature: bellu-security-knowledge-graph, Property 11: Severity assessments are retained and attributed
// Feature: bellu-security-knowledge-graph, Property 12: Discrepancy report
// Feature: bellu-security-knowledge-graph, Property 14: Collections are always lists

const sevVuln = "CVE-2024-9999"

var sevVectors = []string{
	"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
	"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	"CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
	"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
	"not-a-vector",
}

func newSevStore(t *rapid.T) *Store {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	s.SetClock(&fakeClock{t: time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)})
	return s
}

func attach(t *rapid.T, s *Store, r *model.Record) {
	ctx := context.Background()
	if _, err := s.UpsertRecord(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO record_vulnerability(source,external_id,vulnerability_id,method) VALUES(?,?,?,?)`,
		r.Source, r.ID, sevVuln, "alias"); err != nil {
		t.Fatal(err)
	}
}

func drawSevRecord(t *rapid.T, step int) *model.Record {
	r := &model.Record{
		Source:   rapid.SampledFrom([]string{"nvd", "osv", "ghsa"}).Draw(t, "source"),
		ID:       rapid.SampledFrom([]string{"R1", "R2"}).Draw(t, "id"),
		Modified: ingestEpoch.Add(time.Duration(step) * time.Hour),
	}
	n := rapid.IntRange(0, 3).Draw(t, "nsev")
	for i := 0; i < n; i++ {
		sv := model.Severity{
			Type:   rapid.SampledFrom([]string{"CVSS_V3", "CVSS_V4"}).Draw(t, "type"),
			Vector: rapid.SampledFrom(sevVectors).Draw(t, "vector"),
		}
		if rapid.Bool().Draw(t, "scored") {
			sc := float64(rapid.IntRange(0, 100).Draw(t, "tenths")) / 10
			sv.Score = &sc
		}
		r.Severities = append(r.Severities, sv)
	}
	return r
}

func TestPropertySeverityRetainedAndAttributed(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := newSevStore(t)
		defer s.Close()
		ctx := context.Background()
		type key struct{ source, id, typ, vector string }
		seen := map[key]bool{}
		prev := 0
		steps := rapid.IntRange(1, 8).Draw(t, "steps")
		for step := 1; step <= steps; step++ {
			r := drawSevRecord(t, step)
			for _, sv := range r.Severities {
				seen[key{r.Source, r.ID, sv.Type, sv.Vector}] = true
			}
			attach(t, s, r)
			es, err := s.Severities(ctx, sevVuln)
			if err != nil {
				t.Fatal(err)
			}
			if len(es) < prev {
				t.Fatalf("assessment count decreased: %d -> %d", prev, len(es))
			}
			prev = len(es)
			if len(es) != len(seen) {
				t.Fatalf("stored %d rows, want one per distinct key (%d)", len(es), len(seen))
			}
			got := map[key]bool{}
			for _, e := range es {
				got[key{e.Source, e.RecordID, e.Type, e.Vector}] = true
				if e.Source == "" || e.Validation == "" {
					t.Fatalf("entry lacks source or validation: %+v", e)
				}
			}
			for k := range seen {
				if !got[k] {
					t.Fatalf("missing assessment %+v", k)
				}
			}
		}
	})
}

func TestPropertyDiscrepancyReport(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ratings := []string{"None", "Low", "Medium", "High", "Critical"}
		n := rapid.IntRange(0, 6).Draw(t, "n")
		var in []SeverityEntry
		for i := 0; i < n; i++ {
			e := SeverityEntry{
				Source:  rapid.SampledFrom([]string{"nvd", "osv", "ghsa"}).Draw(t, "source"),
				Version: rapid.SampledFrom([]string{"3.1", "4.0", ""}).Draw(t, "version"),
			}
			if rapid.Bool().Draw(t, "scored") {
				sc := float64(rapid.IntRange(0, 100).Draw(t, "tenths")) / 10
				e.Score = &sc
				e.Rating = Rating(e.Score)
				if rapid.Bool().Draw(t, "mutate") { // rating may be supplied independently
					e.Rating = rapid.SampledFrom(ratings).Draw(t, "rating")
				}
			}
			in = append(in, e)
		}
		want := false
		for i := range in {
			for j := i + 1; j < len(in); j++ {
				a, b := in[i], in[j]
				if a.Score == nil || b.Score == nil {
					continue
				}
				ta, tb := int(*a.Score*10+0.5), int(*b.Score*10+0.5)
				if ta != tb || a.Rating != b.Rating {
					want = true
				}
			}
		}
		rep := BuildSeverityReport(in)
		if rep.Discrepancy != want {
			t.Fatalf("discrepancy=%v want %v for %+v", rep.Discrepancy, want, in)
		}
		if rep.Entries == nil || len(rep.Entries) != len(in) {
			t.Fatalf("entries not preserved: %+v", rep.Entries)
		}
		for i := range in {
			a, b := in[i], rep.Entries[i]
			if a.Source != b.Source || a.Version != b.Version || a.Rating != b.Rating || (a.Score == nil) != (b.Score == nil) {
				t.Fatalf("entry %d changed: %+v vs %+v", i, a, b)
			}
		}
	})
}

func TestPropertyCollectionsAreLists(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := newSevStore(t)
		defer s.Close()
		ctx := context.Background()
		n := rapid.IntRange(0, 3).Draw(t, "records")
		wantAff := 0
		for i := 0; i < n; i++ {
			r := drawSevRecord(t, i+1)
			r.ID = "R" + string(rune('A'+i)) // distinct records
			for k := rapid.IntRange(0, 2).Draw(t, "naff"); k > 0; k-- {
				r.Affected = append(r.Affected, model.Affected{Kind: "package", Ecosystem: "npm", Name: "p" + string(rune('a'+k))})
				wantAff++
			}
			attach(t, s, r)
		}
		es, err1 := s.Severities(ctx, sevVuln)
		rep, err2 := s.SeverityReportFor(ctx, sevVuln)
		aff, err3 := s.AffectedPackages(ctx, sevVuln)
		recs, err4 := s.SourceRecords(ctx, sevVuln)
		for _, err := range []error{err1, err2, err3, err4} {
			if err != nil {
				t.Fatal(err)
			}
		}
		b, err := json.Marshal(map[string]any{"severities": es, "entries": rep.Entries, "affected": aff, "records": recs})
		if err != nil {
			t.Fatal(err)
		}
		var out map[string][]json.RawMessage
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("a collection is not a JSON array: %v: %s", err, b)
		}
		for name, want := range map[string]int{"severities": len(es), "entries": len(es), "affected": wantAff, "records": n} {
			if out[name] == nil || len(out[name]) != want {
				t.Fatalf("%s: got %v (len %d), want array of %d", name, out[name], len(out[name]), want)
			}
		}
	})
}

// R23.1: the graph fixtures carry conflicting CVSS vectors for CVE-2024-1000 from two sources
// (GHSA-fix-0001 as ghsa, NVD-DISAGREE-1000 as nvd). Both are retained, attributed, and flagged.
func TestSourceDisagreementFromFixtures(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "graph", "snapshot_T.json"))
	if err != nil {
		t.Fatal(err)
	}
	var docs []json.RawMessage
	if err := json.Unmarshal(data, &docs); err != nil {
		t.Fatal(err)
	}
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetClock(&fakeClock{t: time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)})
	ctx := context.Background()
	const vuln = "CVE-2024-1000"
	srcOf := map[string]string{"GHSA-FIX-0001": "ghsa", "NVD-DISAGREE-1000": "nvd"}
	loaded := 0
	for _, d := range docs {
		var h struct{ ID string }
		if err := json.Unmarshal(d, &h); err != nil {
			t.Fatal(err)
		}
		src, ok := srcOf[model.NormID(h.ID)]
		if !ok {
			continue
		}
		// The nvd parser only accepts CVE ids and the fixture is OSV-shaped, so parse it as OSV
		// and attribute the record to its intended source afterwards.
		rec, err := osv.Parse("osv", d)
		if err != nil {
			t.Fatal(err)
		}
		rec.Source = src
		for i := range rec.Severities {
			rec.Severities[i].Source = src
		}
		if _, err := s.UpsertRecord(ctx, rec); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO record_vulnerability(source,external_id,vulnerability_id,method) VALUES(?,?,?,?)`,
			rec.Source, rec.ID, vuln, "alias"); err != nil {
			t.Fatal(err)
		}
		loaded++
	}
	if loaded != 2 {
		t.Fatalf("loaded %d fixture records, want 2", loaded)
	}
	rep, err := s.SeverityReportFor(ctx, vuln)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Entries) != 2 || !rep.Discrepancy {
		t.Fatalf("want 2 attributed entries and a discrepancy: %+v", rep)
	}
	bySource := map[string]SeverityEntry{}
	for _, e := range rep.Entries {
		bySource[e.Source] = e
	}
	g, n := bySource["ghsa"], bySource["nvd"]
	if g.Score == nil || n.Score == nil || *g.Score == *n.Score || g.Vector == n.Vector {
		t.Fatalf("sources should disagree: ghsa=%+v nvd=%+v", g, n)
	}
	if g.Rating == "" || n.Rating == "" || g.Validation == "" || n.Validation == "" {
		t.Fatalf("rating/validation missing: ghsa=%+v nvd=%+v", g, n)
	}
}
