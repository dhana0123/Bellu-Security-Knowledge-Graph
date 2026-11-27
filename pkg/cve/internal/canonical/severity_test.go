package canonical

import (
	"context"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

func f(x float64) *float64 { return &x }

func TestSeverityRetentionAndDiscrepancy(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	const v = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
	vec := "CVSS:3.1/" + v // computes 7.5
	nvd := &model.Record{Source: "nvd", ID: "CVE-2024-1", Modified: time.Now(),
		Severities: []model.Severity{{Type: "CVSS_V3", Vector: vec, Score: f(7.5)}}}
	ghsa := &model.Record{Source: "osv", ID: "GHSA-x", Aliases: []string{"CVE-2024-1"}, Modified: time.Now(),
		Severities: []model.Severity{{Type: "CVSS_V3", Vector: vec, Score: f(5.0), Validation: "mismatch"}}}
	for _, r := range []*model.Record{nvd, ghsa} {
		if _, err := s.UpsertRecord(ctx, r); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO record_vulnerability(source,external_id,vulnerability_id,method) VALUES(?,?,?,?)`,
			r.Source, r.ID, "CVE-2024-1", "alias"); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := s.SeverityReportFor(ctx, "CVE-2024-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Entries) != 2 || !rep.Discrepancy {
		t.Fatalf("want 2 entries and discrepancy: %+v", rep)
	}
	e := rep.Entries[0] // nvd
	if e.Source != "nvd" || e.Version != "3.1" || e.Rating != "High" || e.Validation != "valid" || *e.Score != 7.5 {
		t.Fatalf("nvd entry: %+v", e)
	}
	if rep.Entries[1].Source != "osv" || rep.Entries[1].Rating != "Medium" {
		t.Fatalf("osv entry: %+v", rep.Entries[1])
	}
	// re-ingest with a changed score: row count does not decrease
	nvd2 := *nvd
	nvd2.Modified = nvd.Modified.Add(time.Hour)
	nvd2.Severities = []model.Severity{{Type: "CVSS_V3", Vector: vec, Score: f(5.0)}}
	if _, err := s.UpsertRecord(ctx, &nvd2); err != nil {
		t.Fatal(err)
	}
	es, _ := s.Severities(ctx, "CVE-2024-1")
	if len(es) != 2 {
		t.Fatalf("row count changed: %d", len(es))
	}
	if r := BuildSeverityReport(es); r.Discrepancy {
		t.Fatalf("equal scores should not be discrepant: %+v", r)
	}
}

func TestBuildSeverityReportThresholds(t *testing.T) {
	mk := func(a, b float64) []SeverityEntry {
		return []SeverityEntry{{Source: "a", Score: f(a), Rating: Rating(f(a))}, {Source: "b", Score: f(b), Rating: Rating(f(b))}}
	}
	if !BuildSeverityReport(mk(5.0, 5.1)).Discrepancy {
		t.Error("0.1 difference must be a discrepancy")
	}
	if BuildSeverityReport(mk(5.0, 5.0)).Discrepancy {
		t.Error("equal scores must not be a discrepancy")
	}
	for sc, want := range map[float64]string{0: "None", 0.1: "Low", 3.9: "Low", 4.0: "Medium", 6.9: "Medium", 7.0: "High", 8.9: "High", 9.0: "Critical", 10: "Critical"} {
		if got := Rating(f(sc)); got != want {
			t.Errorf("Rating(%v)=%s want %s", sc, got, want)
		}
	}
}

func TestEmptyCollectionsAreNonNil(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	es, err := s.Severities(ctx, "CVE-none")
	if err != nil || es == nil || len(es) != 0 {
		t.Fatalf("severities: %#v %v", es, err)
	}
	rep, _ := s.SeverityReportFor(ctx, "CVE-none")
	if rep.Entries == nil || rep.Discrepancy {
		t.Fatalf("report: %+v", rep)
	}
	if a, err := s.AffectedPackages(ctx, "CVE-none"); err != nil || a == nil || len(a) != 0 {
		t.Fatalf("affected: %#v %v", a, err)
	}
	if r, err := s.SourceRecords(ctx, "CVE-none"); err != nil || r == nil || len(r) != 0 {
		t.Fatalf("records: %#v %v", r, err)
	}
	if NonNil[int](nil) == nil {
		t.Fatal("NonNil returned nil")
	}
}
