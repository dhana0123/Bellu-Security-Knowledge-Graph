package canonical

import (
	"context"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

func touchSeq(t *testing.T, s *Store) int64 {
	t.Helper()
	var n int64
	if err := s.DB.QueryRow(`SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='projection_touch'),0)`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func touched(t *testing.T, s *Store, after int64) map[string]bool {
	t.Helper()
	rows, err := s.DB.Query(`SELECT kind||':'||a||':'||b FROM projection_touch WHERE seq>?`, after)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		out[k] = true
	}
	return out
}

// The change feed behind incremental projection: which writes record a touch, and that
// unlinked KEV and EPSS rows (the bulk of the EPSS feed) record none.
func TestProjectionTouchTriggers(t *testing.T) {
	ctx := context.Background()
	s := openDisk(t)
	mod := time.Unix(1700000000, 0)
	mark := touchSeq(t, s)

	if _, err := s.UpsertRecord(ctx, &model.Record{Source: "nvd", ID: "CVE-2024-0001", Modified: mod, Weaknesses: []string{"CWE-79"}}); err != nil {
		t.Fatal(err)
	}
	got := touched(t, s, mark)
	if !got["r:nvd:CVE-2024-0001"] || !got["k:CVE-2024-0001:"] {
		t.Fatalf("record upsert touched %v", got)
	}

	mark = touchSeq(t, s)
	mustResolve(t, s, ResolveOptions{})
	if got := touched(t, s, mark); !got["v:CVE-2024-0001:"] {
		t.Fatalf("resolve touched %v", got)
	}

	// Unlinked EPSS rows (the bulk of the feed) touch nothing; the linked ones do. An unlinked KEV
	// row may leave one touch (the table default is 'linked' until upsertKEV flips it), which
	// resolves to no vulnerability and costs nothing at projection time.
	mark = touchSeq(t, s)
	for i := 0; i < 50; i++ {
		if _, err := s.UpsertEPSS(ctx, model.EPSS{CVE: "CVE-2098-" + string(rune('0'+i%10)) + "000", Score: 0.1, Percentile: 0.1, Date: "2024-03-01"}); err != nil {
			t.Fatal(err)
		}
	}
	if got := touched(t, s, mark); len(got) != 0 {
		t.Fatalf("unlinked EPSS touched %v", got)
	}
	if _, err := s.UpsertKEV(ctx, model.KEV{CVE: "CVE-2099-0001"}); err != nil {
		t.Fatal(err)
	}
	if got := touched(t, s, mark); len(got) > 1 {
		t.Fatalf("unlinked KEV touched %v", got)
	}
	if _, err := s.UpsertKEV(ctx, model.KEV{CVE: "CVE-2024-0001", DateAdded: "2024-01-01"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertEPSS(ctx, model.EPSS{CVE: "CVE-2024-0001", Score: 0.2, Percentile: 0.3, Date: "2024-03-01"}); err != nil {
		t.Fatal(err)
	}
	if got := touched(t, s, mark); !got["k:CVE-2024-0001:"] {
		t.Fatalf("linked KEV/EPSS touched %v", got)
	}

	// Re-touching keeps one row per subject and moves it past the old seq.
	mark = touchSeq(t, s)
	if _, err := s.UpsertEPSS(ctx, model.EPSS{CVE: "CVE-2024-0001", Score: 0.4, Percentile: 0.5, Date: "2024-03-02"}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM projection_touch WHERE kind='k' AND a='CVE-2024-0001'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows for the key: %d %v", n, err)
	}
	if got := touched(t, s, mark); !got["k:CVE-2024-0001:"] {
		t.Fatalf("second EPSS date not touched: %v", got)
	}
}

func TestLoadIngestStatusEmptyStore(t *testing.T) {
	s := openDisk(t)
	st, err := s.LoadIngestStatus(context.Background(), StatusOptions{Sources: IngestSources, Recent: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Sources) != len(IngestSources) || st.Resolution != (ResolveStatus{}) {
		t.Fatalf("%+v", st)
	}
	for _, src := range st.Sources {
		if src.Status != "never_run" || src.Rejected.Recent == nil || src.Rejected.Total != 0 {
			t.Fatalf("%+v", src)
		}
	}
	one, err := s.LoadIngestStatus(context.Background(), StatusOptions{Sources: IngestSources, Only: "kev"})
	if err != nil || len(one.Sources) != 1 || one.Sources[0].Source != "kev" {
		t.Fatalf("%+v %v", one, err)
	}
}
