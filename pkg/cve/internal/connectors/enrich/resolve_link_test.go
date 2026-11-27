package enrich

// Task 88.6: KEV and EPSS rows written by the live syncers link to the resolved vulnerability.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

func linkOf(t *testing.T, st *canonical.Store, table, cve string) (status string, vuln sql.NullString) {
	t.Helper()
	if err := st.DB.QueryRow(`SELECT status, vulnerability_id FROM `+table+` WHERE cve=? ORDER BY score_date DESC LIMIT 1`, cve).Scan(&status, &vuln); err != nil {
		// kev has no score_date
		if err2 := st.DB.QueryRow(`SELECT status, vulnerability_id FROM `+table+` WHERE cve=?`, cve).Scan(&status, &vuln); err2 != nil {
			t.Fatal(err2)
		}
	}
	return
}

func TestSyncedKEVEPSSLinkToResolvedID(t *testing.T) {
	ctx := context.Background()
	s, f, st := setup(t)
	const certifi, py, other = "CVE-2023-37920", "CVE-2022-42969", "CVE-2020-0001"
	mod := time.Unix(1700000000, 0)
	// certifi is known (via GHSA and OSV aliases) and resolved before the syncs run.
	for _, r := range []*model.Record{
		{Source: "ghsa", ID: "GHSA-xqr8-7jwr-rhp7", Aliases: []string{certifi}, Modified: mod},
		{Source: "osv", ID: "PYSEC-2023-135", Aliases: []string{"GHSA-xqr8-7jwr-rhp7", certifi}, Modified: mod},
	} {
		if _, err := st.UpsertRecord(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Resolve(ctx, canonical.ResolveOptions{}); err != nil {
		t.Fatal(err)
	}

	f.kev = kevJSON("v1", certifi, py)
	f.current = "2026-11-18"
	f.files["2026-11-18"] = epssCSV("2026-11-18", certifi+",0.5,0.9", py+",0.1,0.5", other+",0.2,0.6")
	f.files["2026-11-19"] = epssCSV("2026-11-19", certifi+",0.6,0.95", py+",0.2,0.55")
	if _, err := s.SyncKEV(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SyncEPSS(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SyncEPSSDate(ctx, "2026-11-19"); err != nil {
		t.Fatal(err)
	}

	// Known CVE: linked and pointing at the vulnerability id straight after the sync.
	for _, tb := range []string{"kev", "epss_history"} {
		if status, v := linkOf(t, st, tb, certifi); status != "linked" || v.String != certifi {
			t.Fatalf("%s %s: %s %v", tb, certifi, status, v)
		}
		// Unknown CVE: pending, no vulnerability id.
		if status, v := linkOf(t, st, tb, py); status != "pending" || v.Valid {
			t.Fatalf("%s %s before arrival: %s %v", tb, py, status, v)
		}
	}
	if n := count(t, st, `SELECT COUNT(*) FROM epss_history WHERE cve=? AND vulnerability_id=?`, certifi, certifi); n != 2 {
		t.Fatalf("certifi epss_history rows linked: %d, want 2", n)
	}
	if v, err := st.Enrichment(ctx, py); err != nil || v.KEV != nil || v.EPSS != nil {
		t.Fatalf("pending served: %+v %v", v, err)
	}

	// The unknown CVE arrives later and one resolve links its pending rows.
	if _, err := st.UpsertRecord(ctx, &model.Record{Source: "osv", ID: "PYSEC-2022-178", Aliases: []string{py}, Modified: mod}); err != nil {
		t.Fatal(err)
	}
	rep, err := st.Resolve(ctx, canonical.ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.LinkedEnrichment != 3 { // KEV + two EPSS dates
		t.Fatalf("linked %d, want 3: %+v", rep.LinkedEnrichment, rep)
	}
	for _, tb := range []string{"kev", "epss_history"} {
		if status, v := linkOf(t, st, tb, py); status != "linked" || v.String != py {
			t.Fatalf("%s %s after arrival: %s %v", tb, py, status, v)
		}
	}
	ev, err := st.Enrichment(ctx, py)
	if err != nil || ev.KEV == nil || ev.EPSS == nil || ev.EPSS.Date != "2026-11-19" || ev.EPSS.Score != 0.2 {
		t.Fatalf("enrichment %+v %v", ev, err)
	}
	// A CVE nobody ever ingested stays pending.
	if status, v := linkOf(t, st, "epss_history", other); status != "pending" || v.Valid {
		t.Fatalf("%s: %s %v", other, status, v)
	}
}
