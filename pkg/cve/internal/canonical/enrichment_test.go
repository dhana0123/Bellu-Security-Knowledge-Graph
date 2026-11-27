package canonical

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

func openEnr(t *testing.T) (*Store, context.Context) {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, context.Background()
}

func TestKEVPendingThenLinked(t *testing.T) {
	s, ctx := openEnr(t)
	if _, err := s.UpsertKEV(ctx, model.KEV{CVE: "CVE-2024-0001", Ransomware: "Known"}); err != nil {
		t.Fatal(err)
	}
	v, err := s.Enrichment(ctx, "CVE-2024-0001")
	if err != nil || v.KEV != nil {
		t.Fatalf("pending KEV must not be returned: %+v %v", v.KEV, err)
	}
	if _, err := s.UpsertRecord(ctx, &model.Record{Source: "nvd", ID: "CVE-2024-0001", Modified: time.Now()}); err != nil {
		t.Fatal(err)
	}
	n, err := s.LinkPending(ctx)
	if err != nil || n != 1 {
		t.Fatalf("LinkPending n=%d err=%v", n, err)
	}
	v, _ = s.Enrichment(ctx, "CVE-2024-0001")
	if v.KEV == nil || v.KEV.Ransomware != "known" {
		t.Fatalf("KEV = %+v", v.KEV)
	}
	// One row per CVE; latest entry wins; unrecognised ransomware value becomes unknown.
	s.UpsertKEV(ctx, model.KEV{CVE: "CVE-2024-0001", Ransomware: "maybe"})
	var cnt int
	s.DB.QueryRow(`SELECT COUNT(*) FROM kev`).Scan(&cnt)
	v, _ = s.Enrichment(ctx, "CVE-2024-0001")
	if cnt != 1 || v.KEV == nil || v.KEV.Ransomware != "unknown" {
		t.Fatalf("cnt=%d kev=%+v", cnt, v.KEV)
	}
}

func TestKEVLinkedViaAlias(t *testing.T) {
	s, ctx := openEnr(t)
	s.UpsertRecord(ctx, &model.Record{Source: "osv", ID: "GHSA-aaaa", Aliases: []string{"CVE-2024-0002"}})
	s.UpsertKEV(ctx, model.KEV{CVE: "CVE-2024-0002"})
	if v, _ := s.Enrichment(ctx, "CVE-2024-0002"); v.KEV == nil {
		t.Fatal("KEV for CVE present as alias should be linked")
	}
}

func TestEPSSLatestByScoreDate(t *testing.T) {
	s, ctx := openEnr(t)
	s.UpsertRecord(ctx, &model.Record{Source: "nvd", ID: "CVE-2024-0003"})
	for _, e := range []model.EPSS{
		{CVE: "CVE-2024-0003", Score: 0.5, Percentile: 0.9, Date: "2024-03-02"},
		{CVE: "CVE-2024-0003", Score: 0.1, Percentile: 0.2, Date: "2024-03-01"},
	} {
		if _, err := s.UpsertEPSS(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	v, _ := s.Enrichment(ctx, "CVE-2024-0003")
	if v.EPSS == nil || v.EPSS.Date != "2024-03-02" || v.EPSS.Score != 0.5 {
		t.Fatalf("current EPSS = %+v", v.EPSS)
	}
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM epss_history`).Scan(&n)
	if n != 2 {
		t.Fatalf("history rows = %d", n)
	}
	c, _ := s.GetEPSS(ctx, "CVE-2024-0003")
	if c == nil || c.Date != "2024-03-02" {
		t.Fatalf("epss cache = %+v", c)
	}
	if ch, _ := s.UpsertEPSS(ctx, model.EPSS{CVE: "CVE-2024-0003", Score: 0.5, Percentile: 0.9, Date: "2024-03-02"}); ch {
		t.Fatal("identical EPSS should be a no-op")
	}
}

func TestEPSSPendingNotReturnedThenLinked(t *testing.T) {
	s, ctx := openEnr(t)
	s.UpsertEPSS(ctx, model.EPSS{CVE: "CVE-2024-0004", Score: 0.3, Date: "2024-01-01"})
	if v, _ := s.Enrichment(ctx, "CVE-2024-0004"); v.EPSS != nil {
		t.Fatal("pending EPSS returned")
	}
	s.UpsertRecord(ctx, &model.Record{Source: "nvd", ID: "CVE-2024-0004"})
	if n, _ := s.LinkPending(ctx); n != 1 {
		t.Fatalf("flipped %d", n)
	}
	if v, _ := s.Enrichment(ctx, "CVE-2024-0004"); v.EPSS == nil {
		t.Fatal("EPSS should be linked")
	}
	if n, _ := s.LinkPending(ctx); n != 0 {
		t.Fatalf("second LinkPending flipped %d", n)
	}
}

func TestEnrichmentRejectsBadItemsKeepsOthers(t *testing.T) {
	s, ctx := openEnr(t)
	long := "https://x.example/" + strings.Repeat("a", 2040)
	rec := &model.Record{
		Source: "nvd", ID: "CVE-2024-0005", Modified: time.Now(),
		Weaknesses: []string{"CWE-79", "CWE-79", "cwe-1", "CWE-", "CWE-20"},
		References: []model.Reference{
			{URL: "https://fix.example/1", Type: "FIX"},
			{URL: "https://fix.example/1", Type: "FIX"},
			{URL: long, Type: "FIX"},
			{URL: "https://exp.example/1", Type: "EXPLOIT"},
			{URL: long, Type: "EXPLOIT"},
		},
	}
	errs, err := s.StoreEnrichment(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 4 {
		t.Fatalf("item errors = %+v", errs)
	}
	// Twice: dedup.
	if _, err := s.StoreEnrichment(ctx, rec); err != nil {
		t.Fatal(err)
	}
	changed, err := s.UpsertRecord(ctx, rec)
	if err != nil || !changed {
		t.Fatalf("record must still be stored: %v %v", changed, err)
	}
	v, _ := s.Enrichment(ctx, "CVE-2024-0005")
	if strings.Join(v.Weaknesses, ",") != "CWE-20,CWE-79" {
		t.Fatalf("weaknesses = %v", v.Weaknesses)
	}
	if len(v.Patches) != 1 || len(v.Exploits) != 1 {
		t.Fatalf("patches=%v exploits=%v", v.Patches, v.Exploits)
	}
}

func TestEnrichmentKeyedByAliasCVEOrRecordID(t *testing.T) {
	s, ctx := openEnr(t)
	s.UpsertRecord(ctx, &model.Record{Source: "osv", ID: "GHSA-1", Aliases: []string{"CVE-2024-0006", "CVE-2024-0007"}, Weaknesses: []string{"CWE-22"}})
	s.UpsertRecord(ctx, &model.Record{Source: "osv", ID: "GHSA-2", Weaknesses: []string{"CWE-89"}})
	for _, c := range []string{"CVE-2024-0006", "CVE-2024-0007"} {
		if v, _ := s.Enrichment(ctx, c); len(v.Weaknesses) != 1 || v.Weaknesses[0] != "CWE-22" {
			t.Fatalf("%s: %v", c, v.Weaknesses)
		}
	}
	if v, _ := s.Enrichment(ctx, "GHSA-2"); len(v.Weaknesses) != 1 {
		t.Fatalf("record-id key: %v", v.Weaknesses)
	}
}
