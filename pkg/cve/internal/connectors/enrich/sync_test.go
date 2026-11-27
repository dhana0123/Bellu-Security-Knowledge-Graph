package enrich

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/fetch"
)

type feeds struct {
	mu       sync.Mutex
	kev      string
	files    map[string]string // date -> csv text
	current  string            // date the current URL redirects to
	redirect int
}

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func epssCSV(date string, rows ...string) string {
	return "#model_version:v2025.03.14,score_date:" + date + "T00:00:00+0000\ncve,epss,percentile\n" + strings.Join(rows, "\n") + "\n"
}

func kevJSON(version string, cves ...string) string {
	var vs []string
	for _, c := range cves {
		vs = append(vs, fmt.Sprintf(`{"cveID":%q,"vendorProject":"V","product":"P","vulnerabilityName":"N","dateAdded":"2024-01-01","dueDate":"2024-02-01","requiredAction":"patch","knownRansomwareCampaignUse":"Unknown"}`, c))
	}
	return fmt.Sprintf(`{"title":"t","catalogVersion":%q,"dateReleased":"2026-11-19T15:00:00.000Z","count":%d,"vulnerabilities":[%s]}`, version, len(cves), strings.Join(vs, ","))
}

func setup(t *testing.T) (*Syncer, *feeds, *canonical.Store) {
	t.Helper()
	f := &feeds{files: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Write([]byte(f.kev))
	})
	mux.HandleFunc("/current.csv.gz", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.redirect++
		http.Redirect(w, r, "/files/epss_scores-"+f.current+".csv.gz", http.StatusFound)
	})
	mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		name := strings.TrimPrefix(r.URL.Path, "/files/epss_scores-")
		date := strings.TrimSuffix(name, ".csv.gz")
		body, ok := f.files[date]
		if !ok {
			http.NotFound(w, r)
			return
		}
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		zw.Write([]byte(body))
		zw.Close()
		w.Write(b.Bytes())
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	st, err := canonical.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	hc := fetch.NewClient("bulk", false)
	if err := hc.SetInterval(time.Millisecond); err != nil {
		t.Fatal(err)
	}
	s := NewSyncer(st, Config{KEVURL: srv.URL + "/kev.json", EPSSCurrentURL: srv.URL + "/current.csv.gz",
		EPSSHistoryBase: srv.URL + "/files", HTTP: hc})
	return s, f, st
}

func count(t *testing.T, st *canonical.Store, q string, args ...any) int {
	t.Helper()
	var n int
	if err := st.DB.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEPSSFirstRepeatAndNewDate(t *testing.T) {
	ctx := context.Background()
	s, f, st := setup(t)
	f.files["2026-11-18"] = epssCSV("2026-11-18", "CVE-2024-0001,0.10000,0.50000", "CVE-2024-0002,0.20000,0.60000")
	f.files["2026-11-19"] = epssCSV("2026-11-19", "CVE-2024-0001,0.30000,0.70000", "CVE-2024-0002,0.20000,0.60000", "CVE-2024-0003,0.01000,0.10000")
	f.current = "2026-11-18"

	r, err := s.SyncEPSS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.ScoreDate != "2026-11-18" || r.ModelVersion != "v2025.03.14" || r.Rows != 2 || r.Changed != 2 || r.Rejected != 0 {
		t.Fatalf("first sync: %+v", r)
	}
	if !strings.Contains(r.Source, "/files/epss_scores-2026-11-18.csv.gz") {
		t.Fatalf("source not the redirect target: %s", r.Source)
	}
	if got := count(t, st, `SELECT COUNT(*) FROM epss_history`); got != 2 {
		t.Fatalf("history rows %d", got)
	}
	e, err := st.GetEPSS(ctx, "CVE-2024-0001")
	if err != nil || e == nil || e.Score != 0.1 || e.Date != "2026-11-18" {
		t.Fatalf("cache %+v %v", e, err)
	}

	// Same date again: no changes, no new rows.
	r, err = s.SyncEPSS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.Changed != 0 || r.Unchanged != 2 || r.Rows != 2 {
		t.Fatalf("repeat sync: %+v", r)
	}
	if got := count(t, st, `SELECT COUNT(*) FROM epss_history`); got != 2 {
		t.Fatalf("history rows after repeat %d", got)
	}
	events := count(t, st, `SELECT COUNT(*) FROM graph_event WHERE event_type='epss_synced'`)
	if events != 1 {
		t.Fatalf("epss_synced events %d, want 1", events)
	}

	// New date: appends history, moves the current cache.
	f.current = "2026-11-19"
	r, err = s.SyncEPSS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.ScoreDate != "2026-11-19" || r.Rows != 3 || r.Changed != 3 {
		t.Fatalf("new date: %+v", r)
	}
	if got := count(t, st, `SELECT COUNT(*) FROM epss_history`); got != 5 {
		t.Fatalf("history rows %d, want 5", got)
	}
	e, _ = st.GetEPSS(ctx, "CVE-2024-0001")
	if e.Score != 0.3 || e.Date != "2026-11-19" {
		t.Fatalf("cache not advanced: %+v", e)
	}

	// Backfilling an older date appends history but does not move the cache back.
	f.files["2026-11-17"] = epssCSV("2026-11-17", "CVE-2024-0001,0.90000,0.99000")
	r, err = s.SyncEPSSDate(ctx, "2026-11-17")
	if err != nil || r.ScoreDate != "2026-11-17" || r.Changed != 1 {
		t.Fatalf("history sync: %+v %v", r, err)
	}
	e, _ = st.GetEPSS(ctx, "CVE-2024-0001")
	if e.Score != 0.3 || e.Date != "2026-11-19" {
		t.Fatalf("cache moved backwards: %+v", e)
	}
	if got := count(t, st, `SELECT COUNT(*) FROM epss_history WHERE cve='CVE-2024-0001'`); got != 3 {
		t.Fatalf("history rows for CVE-2024-0001: %d", got)
	}
	// Job rows carry the as-of date.
	if d, err := s.LastEPSSDate(ctx); err != nil || d != "2026-11-17" {
		t.Fatalf("LastEPSSDate %q %v", d, err)
	}
}

func TestEPSSMalformedRowsRejectedWithReason(t *testing.T) {
	ctx := context.Background()
	s, f, st := setup(t)
	f.files["2026-11-19"] = epssCSV("2026-11-19",
		"CVE-2024-0001,0.10000,0.50000",
		"not-a-cve,0.1,0.2",
		"CVE-2024-0002,abc,0.2",
		"CVE-2024-0003,1.5,0.2",
		"CVE-2024-0004,0.1",
		"CVE-2024-0005,0.2,0.3")
	f.current = "2026-11-19"
	r, err := s.SyncEPSS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rows != 2 || r.Rejected != 4 || len(r.Rejections) != 4 {
		t.Fatalf("result: %+v", r)
	}
	for _, rj := range r.Rejections {
		if rj.Reason == "" || rj.Field == "" {
			t.Fatalf("rejection without reason: %+v", rj)
		}
	}
	if got := count(t, st, `SELECT COUNT(*) FROM epss_history`); got != 2 {
		t.Fatalf("stored %d", got)
	}
	var detail string
	if err := st.DB.QueryRow(`SELECT detail FROM job WHERE source='epss' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil || !strings.Contains(detail, `"rejected":4`) {
		t.Fatalf("job detail %q %v", detail, err)
	}
}

func TestEPSSBadHeaderAndDateMismatch(t *testing.T) {
	ctx := context.Background()
	s, f, _ := setup(t)
	f.files["2026-11-19"] = "#model_version:v1,score_date:2026-11-19T00:00:00+0000\nfoo,bar\nx,y\n"
	f.current = "2026-11-19"
	if _, err := s.SyncEPSS(ctx); err == nil {
		t.Fatal("bad header accepted")
	}
	f.files["2026-11-18"] = epssCSV("2026-11-19", "CVE-2024-0001,0.1,0.2")
	if _, err := s.SyncEPSSDate(ctx, "2026-11-18"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("date mismatch: %v", err)
	}
	if _, err := s.SyncEPSSDate(ctx, "2026-13-01"); err == nil {
		t.Fatal("invalid date accepted")
	}
}

func TestEPSSBatchesAndLinking(t *testing.T) {
	ctx := context.Background()
	s, f, st := setup(t)
	var rows []string
	for i := 0; i < BatchSize*2+17; i++ {
		rows = append(rows, fmt.Sprintf("CVE-2024-%07d,0.5,0.5", i+1000))
	}
	f.files["2026-11-19"] = epssCSV("2026-11-19", rows...)
	f.current = "2026-11-19"
	// One CVE is already known to the store.
	if _, err := st.DB.Exec(`INSERT INTO vulnerability(id) VALUES('CVE-2024-0001000')`); err != nil {
		t.Fatal(err)
	}
	r, err := s.SyncEPSS(ctx)
	if err != nil || r.Rows != len(rows) || r.Changed != len(rows) {
		t.Fatalf("%+v %v", r, err)
	}
	if got := count(t, st, `SELECT COUNT(*) FROM epss_history WHERE status='linked'`); got != 1 {
		t.Fatalf("linked %d, want 1", got)
	}
	v, err := st.Enrichment(ctx, "CVE-2024-0001000")
	if err != nil || v.EPSS == nil || v.EPSS.Date != "2026-11-19" {
		t.Fatalf("enrichment %+v %v", v, err)
	}
}

func TestKEVSyncAndRemovalMarked(t *testing.T) {
	ctx := context.Background()
	s, f, st := setup(t)
	if _, err := st.DB.Exec(`INSERT INTO vulnerability(id) VALUES('CVE-2024-0001')`); err != nil {
		t.Fatal(err)
	}
	f.kev = kevJSON("2026.11.18", "CVE-2024-0001", "CVE-2024-0002", "bogus")
	r, err := s.SyncKEV(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.CatalogVersion != "2026.11.18" || r.DateReleased != "2026-11-19T15:00:00.000Z" || r.Entries != 2 || r.Added != 2 || r.Rejected != 1 {
		t.Fatalf("first: %+v", r)
	}
	if len(r.Rejections) != 1 || r.Rejections[0].Reason == "" {
		t.Fatalf("rejections %+v", r.Rejections)
	}
	k, err := st.GetKEV(ctx, "CVE-2024-0001")
	if err != nil || k == nil || k.Vendor != "V" || k.Ransomware != "unknown" {
		t.Fatalf("kev %+v %v", k, err)
	}
	v, _ := st.Enrichment(ctx, "CVE-2024-0001")
	if v.KEV == nil {
		t.Fatal("linked KEV not served")
	}
	if a, ok, err := s.LastKEVAsOf(ctx); err != nil || !ok || a.CatalogVersion != "2026.11.18" || a.DateReleased == "" {
		t.Fatalf("as-of %+v %v %v", a, ok, err)
	}

	// Same catalogue again: nothing changes.
	r, err = s.SyncKEV(ctx)
	if err != nil || r.Added != 0 || r.Updated != 0 || r.Unchanged != 2 || r.Removed != 0 {
		t.Fatalf("repeat: %+v %v", r, err)
	}

	// 0002 leaves the catalogue: marked removed, row kept, no longer served.
	f.kev = kevJSON("2026.11.19", "CVE-2024-0001")
	r, err = s.SyncKEV(ctx)
	if err != nil || r.Removed != 1 || r.Unchanged != 1 || r.CatalogVersion != "2026.11.19" {
		t.Fatalf("removal: %+v %v", r, err)
	}
	var status string
	if err := st.DB.QueryRow(`SELECT status FROM kev WHERE cve='CVE-2024-0002'`).Scan(&status); err != nil || status != KEVStatusRemoved {
		t.Fatalf("status %q %v", status, err)
	}
	if n := count(t, st, `SELECT COUNT(*) FROM graph_event WHERE entity_id='CVE-2024-0002' AND event_type='kev_removed'`); n != 1 {
		t.Fatalf("removal events %d", n)
	}
	// Removal is reported once, not on every run.
	r, _ = s.SyncKEV(ctx)
	if r.Removed != 0 {
		t.Fatalf("removal repeated: %+v", r)
	}
	// Re-added entry comes back.
	f.kev = kevJSON("2026.11.20", "CVE-2024-0001", "CVE-2024-0002")
	r, err = s.SyncKEV(ctx)
	if err != nil || r.Updated != 1 {
		t.Fatalf("readd: %+v %v", r, err)
	}
	if err := st.DB.QueryRow(`SELECT status FROM kev WHERE cve='CVE-2024-0002'`).Scan(&status); err != nil || status == KEVStatusRemoved {
		t.Fatalf("status after readd %q %v", status, err)
	}
}

func TestKEVRefusesEmptyOrHeaderlessFeed(t *testing.T) {
	ctx := context.Background()
	s, f, st := setup(t)
	f.kev = kevJSON("v1", "CVE-2024-0001")
	if _, err := s.SyncKEV(ctx); err != nil {
		t.Fatal(err)
	}
	f.kev = kevJSON("v2")
	if _, err := s.SyncKEV(ctx); err == nil {
		t.Fatal("empty catalogue accepted")
	}
	f.kev = `{"vulnerabilities":[]}`
	if _, err := s.SyncKEV(ctx); err == nil {
		t.Fatal("headerless catalogue accepted")
	}
	f.kev = `not json`
	if _, err := s.SyncKEV(ctx); err == nil {
		t.Fatal("garbage accepted")
	}
	var status string
	if err := st.DB.QueryRow(`SELECT status FROM kev WHERE cve='CVE-2024-0001'`).Scan(&status); err != nil || status == KEVStatusRemoved {
		t.Fatalf("entry removed by bad feed: %q %v", status, err)
	}
	if n := count(t, st, `SELECT COUNT(*) FROM job WHERE source='kev' AND status='failed'`); n != 3 {
		t.Fatalf("failed jobs %d", n)
	}
}

func TestSyncHTTPErrorFails(t *testing.T) {
	ctx := context.Background()
	s, _, _ := setup(t)
	s.Cfg.HTTP.Retry.MaxAttempts = 1
	if _, err := s.SyncEPSSDate(ctx, "2020-01-01"); err == nil {
		t.Fatal("404 accepted")
	}
}
