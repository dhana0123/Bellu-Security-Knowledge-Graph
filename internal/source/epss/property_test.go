package epss

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/resolve"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/upsert"
)

// Feature: bellu-security-knowledge-graph, Property 66: KEV and EPSS updates (Phase 2)
//
// For any EPSS file and graph: stored scores equal the file values in 0.0 to
// 1.0, CVEs without a node are skipped and counted, and a Change_Record is
// written if and only if the absolute change reaches the threshold. Scores
// are kept as integers in units of 1e-5 so the model has no rounding.
func TestProperty66EPSSUpdates(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		const unit = 100000
		n := rapid.IntRange(1, 25).Draw(t, "n")
		thrU := rapid.IntRange(0, unit).Draw(t, "threshold") // threshold in 1e-5 units
		type row struct {
			cve      string
			score    int
			pct      int
			inGraph  bool
			hasOld   bool
			oldScore int
		}
		rows := make([]row, n)
		var sb strings.Builder
		sb.WriteString("#model_version:v2026.06.15,score_date:2026-11-21T12:00:24Z\ncve,epss,percentile\n")
		st := upsert.State{Nodes: map[resolve.Key]map[string]any{}, Rels: map[upsert.RelID]map[string]any{}}
		for i := range rows {
			r := row{
				cve:     fmt.Sprintf("CVE-2021-%d", 1000+i),
				score:   rapid.IntRange(0, unit).Draw(t, "score"),
				pct:     rapid.IntRange(0, unit).Draw(t, "pct"),
				inGraph: rapid.Bool().Draw(t, "inGraph"),
				hasOld:  rapid.Bool().Draw(t, "hasOld"),
			}
			if r.hasOld {
				r.oldScore = rapid.IntRange(0, unit).Draw(t, "old")
			}
			rows[i] = r
			fmt.Fprintf(&sb, "%s,%.5f,%.5f\n", r.cve, float64(r.score)/unit, float64(r.pct)/unit)
			if r.inGraph {
				k := resolve.Key{Label: "Vulnerability", Prop: "cveID", Value: r.cve}
				props := map[string]any{"cveID": r.cve}
				if r.hasOld {
					props["epssScore"] = float64(r.oldScore) / unit
					props["epssPercentile"] = 0.5
					props["epssDate"] = time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
				}
				st.Nodes[k] = props
			}
		}
		body := gz(t, sb.String())
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
		defer srv.Close()
		dir, derr := os.MkdirTemp("", "epss")
		if derr != nil {
			t.Fatal(derr)
		}
		defer os.RemoveAll(dir)
		a := New(Options{CacheDir: dir, ChangeThreshold: float64(thrU) / unit, URL: srv.URL, Client: srv.Client(), Clock: &fakeClock{}})
		it, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
		if err != nil {
			t.Fatal(err)
		}
		var batch upsert.Batch
		for {
			rec, err := it.Next(context.Background())
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(rec.Payload) == 0 {
				continue
			}
			norm, err := a.Normalize(rec)
			if err != nil {
				t.Fatal(err)
			}
			batch = append(batch, upsert.Desired{ID: rec.ID, N: norm})
		}
		w, recs, cnt := upsert.Plan(st, batch, upsert.RunContext{Source: Name, RunID: "r", Now: time.Unix(0, 0).UTC()})

		wantSkipped := 0
		wantRecorded := map[string]bool{}
		for _, r := range rows {
			if !r.inGraph {
				wantSkipped++
				continue
			}
			if !r.hasOld {
				wantRecorded[r.cve] = true
				continue
			}
			d := r.score - r.oldScore
			if d < 0 {
				d = -d
			}
			// Threshold 0 records every change; the date always differs from
			// the stored one, so a record exists.
			wantRecorded[r.cve] = d >= thrU
		}
		if cnt.Skipped != wantSkipped {
			t.Fatalf("skipped %d want %d", cnt.Skipped, wantSkipped)
		}
		// No node is created.
		for _, nw := range w.Nodes {
			if _, ok := st.Nodes[nw.Key]; !ok {
				t.Fatalf("created node %v", nw.Key)
			}
		}
		// Stored values equal the file values (in range) for every node in the graph.
		stored := map[string]map[string]any{}
		for _, nw := range w.Nodes {
			stored[nw.Key.Value] = nw.Props
		}
		gotRecorded := map[string]bool{}
		for _, rc := range recs {
			gotRecorded[strings.TrimPrefix(rc.EntityKey, "Vulnerability:")] = true
		}
		for _, r := range rows {
			if !r.inGraph {
				if _, ok := stored[r.cve]; ok || gotRecorded[r.cve] {
					t.Fatalf("%s has no node but was written", r.cve)
				}
				continue
			}
			wantS, wantP := float64(r.score)/unit, float64(r.pct)/unit
			cur := st.Nodes[resolve.Key{Label: "Vulnerability", Prop: "cveID", Value: r.cve}]
			s, okS := valueOf(stored[r.cve], cur, "epssScore")
			p, okP := valueOf(stored[r.cve], cur, "epssPercentile")
			if !okS || !okP || s != wantS || p != wantP || s < 0 || s > 1 || p < 0 || p > 1 {
				t.Fatalf("%s stored (%v,%v) want (%v,%v)", r.cve, s, p, wantS, wantP)
			}
			if gotRecorded[r.cve] != wantRecorded[r.cve] {
				t.Fatalf("%s old=%v/%d new=%d thr=%d: recorded %v want %v",
					r.cve, r.hasOld, r.oldScore, r.score, thrU, gotRecorded[r.cve], wantRecorded[r.cve])
			}
		}
	})
}

// valueOf returns the value after the plan: the write when present, else the
// existing value.
func valueOf(set, cur map[string]any, name string) (float64, bool) {
	if v, ok := set[name]; ok {
		f, ok := v.(float64)
		return f, ok
	}
	f, ok := cur[name].(float64)
	return f, ok
}

// A failed fetch or parse yields no records, so no stored value can change.
func TestProperty66FailedFetchReturnsNoRecords(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		body := rapid.SliceOfN(rapid.Byte(), 0, 200).Draw(t, "garbage")
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
		defer srv.Close()
		dir, derr := os.MkdirTemp("", "epss")
		if derr != nil {
			t.Fatal(derr)
		}
		defer os.RemoveAll(dir)
		a := New(Options{CacheDir: dir, URL: srv.URL, Client: srv.Client(), Clock: &fakeClock{}})
		it, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
		if err == nil || it != nil || !strings.HasPrefix(err.Error(), "epss:") {
			t.Fatalf("it=%v err=%v", it, err)
		}
	})
}
