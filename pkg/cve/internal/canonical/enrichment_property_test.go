package canonical

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"pgregory.net/rapid"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// Feature: bellu-security-knowledge-graph, Property 19: Enrichment storage rules
// Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5, 6.7
func TestProperty19EnrichmentStorageRules(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		s, err := Open(":memory:")
		if err != nil {
			rt.Fatal(err)
		}
		defer s.Close()
		ctx := context.Background()
		const cve = "CVE-2024-0100"

		// Link the CVE so KEV and EPSS entries are returned as enrichment.
		if _, err := s.UpsertRecord(ctx, &model.Record{Source: "nvd", ID: cve, Modified: time.Now()}); err != nil {
			rt.Fatal(err)
		}

		validCWE := rapid.Custom(func(rt *rapid.T) string {
			id := "CWE-" + rapid.StringMatching(`[1-9][0-9]{0,3}`).Draw(rt, "n")
			if rapid.Bool().Draw(rt, "pad") {
				return " " + id + " "
			}
			return id
		})
		badCWE := rapid.SampledFrom([]string{"", "CWE-", "cwe-79", "CWE-12a", "CWE79", "79", "NVD-CWE-Other", "CWE--1"})
		cwe := rapid.OneOf(validCWE, badCWE)
		long := strings.Repeat("a", 2049)
		okURLs := []string{"https://a.example/1", "https://a.example/2", "https://b.example/x", strings.Repeat("u", 2048)}
		urlGen := rapid.SampledFrom(append([]string{"", long, strings.Repeat("é", 2049)}, okURLs...))
		sources := rapid.SampledFrom([]string{"nvd", "osv", "ghsa"})

		wantCWE := map[string]bool{}
		wantPatch := map[[2]string]bool{}
		wantExploit := map[[2]string]bool{}

		n := rapid.IntRange(1, 6).Draw(rt, "records")
		for i := 0; i < n; i++ {
			rec := &model.Record{Source: sources.Draw(rt, "src"), ID: cve}
			wantErrs := 0
			for _, w := range rapid.SliceOfN(cwe, 0, 8).Draw(rt, "cwes") {
				rec.Weaknesses = append(rec.Weaknesses, w)
				if tw := strings.TrimSpace(w); strings.HasPrefix(tw, "CWE-") && len(tw) > 4 && strings.Trim(tw[4:], "0123456789") == "" {
					wantCWE[tw] = true
				} else {
					wantErrs++
				}
			}
			type refSpec struct {
				typ string
				url string
			}
			refs := rapid.SliceOfN(rapid.Custom(func(rt *rapid.T) refSpec {
				return refSpec{rapid.SampledFrom([]string{"FIX", "EXPLOIT", "WEB"}).Draw(rt, "type"), urlGen.Draw(rt, "url")}
			}), 0, 10).Draw(rt, "refs")
			seenP, seenE := map[string]bool{}, map[string]bool{}
			for _, r := range refs {
				rec.References = append(rec.References, model.Reference{Type: r.typ, URL: r.url})
				if r.url == "" || (r.typ != "FIX" && r.typ != "EXPLOIT") {
					continue // not derived as a patch/exploit
				}
				seen := seenP
				want := wantPatch
				if r.typ == "EXPLOIT" {
					seen, want = seenE, wantExploit
				}
				if seen[r.url] {
					continue
				}
				seen[r.url] = true
				if utf8.RuneCountInString(r.url) > 2048 {
					wantErrs++
				} else {
					want[[2]string{r.url, rec.Source}] = true
				}
			}
			errs, err := s.StoreEnrichment(ctx, rec)
			if err != nil {
				rt.Fatal(err)
			}
			if len(errs) != wantErrs {
				rt.Fatalf("item errors = %d (%v), want %d", len(errs), errs, wantErrs)
			}
			// Re-storing the same record must not add duplicates.
			if _, err := s.StoreEnrichment(ctx, rec); err != nil {
				rt.Fatal(err)
			}
		}

		v, err := s.Enrichment(ctx, cve)
		if err != nil {
			rt.Fatal(err)
		}
		var gotCWE []string
		for w := range wantCWE {
			gotCWE = append(gotCWE, w)
		}
		sort.Strings(gotCWE)
		if strings.Join(v.Weaknesses, ",") != strings.Join(gotCWE, ",") {
			rt.Fatalf("weaknesses = %v, want %v", v.Weaknesses, gotCWE)
		}
		if len(v.Patches) != len(wantPatch) {
			rt.Fatalf("patches = %d, want %d", len(v.Patches), len(wantPatch))
		}
		for _, p := range v.Patches {
			if !wantPatch[[2]string{p.URL, p.Source}] {
				rt.Fatalf("unexpected patch %q/%s", p.URL, p.Source)
			}
		}
		if len(v.Exploits) != len(wantExploit) {
			rt.Fatalf("exploits = %d, want %d", len(v.Exploits), len(wantExploit))
		}
		for _, e := range v.Exploits {
			if !wantExploit[[2]string{e.URL, e.Source}] {
				rt.Fatalf("unexpected exploit %q/%s", e.URL, e.Source)
			}
		}

		// KEV: one row per CVE holding the latest entry; ransomware in {known, unknown}.
		kevs := rapid.SliceOfN(rapid.OneOf(
			rapid.SampledFrom([]string{"Known", "known", "KNOWN", "Unknown", "unknown", "", "maybe"}),
			rapid.String()), 1, 6).Draw(rt, "kev")
		for _, r := range kevs {
			if _, err := s.UpsertKEV(ctx, model.KEV{CVE: cve, Ransomware: r}); err != nil {
				rt.Fatal(err)
			}
		}
		var rows int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM kev WHERE cve=?`, cve).Scan(&rows); err != nil || rows != 1 {
			rt.Fatalf("kev rows = %d err=%v", rows, err)
		}
		wantR := "unknown"
		if strings.EqualFold(strings.TrimSpace(kevs[len(kevs)-1]), "known") {
			wantR = "known"
		}
		if v, _ = s.Enrichment(ctx, cve); v.KEV == nil || v.KEV.Ransomware != wantR {
			rt.Fatalf("kev = %+v, want ransomware %s", v.KEV, wantR)
		}

		// EPSS: every distinct score date retained; current one has the max date.
		type ep struct {
			date  string
			score float64
		}
		eps := rapid.SliceOfN(rapid.Custom(func(rt *rapid.T) ep {
			d := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, rapid.IntRange(0, 400).Draw(rt, "day"))
			return ep{d.Format("2006-01-02"), float64(rapid.IntRange(0, 100).Draw(rt, "score")) / 100}
		}), 1, 12).Draw(rt, "epss")
		dates := map[string]float64{}
		maxDate := ""
		for _, e := range eps {
			if _, err := s.UpsertEPSS(ctx, model.EPSS{CVE: cve, Date: e.date, Score: e.score, Percentile: e.score}); err != nil {
				rt.Fatal(err)
			}
			dates[e.date] = e.score // same date: last write wins
			if e.date > maxDate {
				maxDate = e.date
			}
		}
		var cnt int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM epss_history WHERE cve=?`, cve).Scan(&cnt); err != nil || cnt != len(dates) {
			rt.Fatalf("epss rows = %d, want %d (err=%v)", cnt, len(dates), err)
		}
		if v, _ = s.Enrichment(ctx, cve); v.EPSS == nil || v.EPSS.Date != maxDate || v.EPSS.Score != dates[maxDate] {
			rt.Fatalf("current epss = %+v, want %s/%v", v.EPSS, maxDate, dates[maxDate])
		}
	})
}
