package canonical

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/osv"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// stepClock is a fake clock whose time is advanced explicitly by the test.
type stepClock struct{ t time.Time }

func (c *stepClock) Now() time.Time { return c.t }

type asofState struct {
	summary   string
	withdrawn bool
}

// asofSnapshot maps "source:id" to the visible state.
type asofSnapshot map[string]asofState

var asofDBSeq atomic.Int64

func openAsOfStore(t testing.TB, dir string) *Store {
	t.Helper()
	st, err := Open(filepath.Join(dir, fmt.Sprintf("p%d.db", asofDBSeq.Add(1))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func viewSnapshot(ctx context.Context, v View) (asofSnapshot, error) {
	out := asofSnapshot{}
	for r, err := range v.Records(ctx) {
		if err != nil {
			return nil, err
		}
		out[r.Source+":"+r.ID] = asofState{summary: r.Summary, withdrawn: !r.Withdrawn.IsZero()}
	}
	return out, nil
}

func copySnapshot(s asofSnapshot) asofSnapshot {
	c := make(asofSnapshot, len(s))
	for k, v := range s {
		c[k] = v
	}
	return c
}

// Feature: bellu-security-knowledge-graph, Property 24: As-of replay and temporal monotonicity
// Feature: bellu-security-knowledge-graph, Property 25: Current knowledge equals as-of now
// **Validates: Requirements 8.2, 8.3, 8.4, 8.5, 8.6, 8.7**
func TestPropertyAsOfReplayAndCurrent(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	ids := []string{"A", "B", "C", "D"}

	rapid.Check(t, func(rt *rapid.T) {
		st := openAsOfStore(t, dir)
		clk := &stepClock{base}
		st.SetClock(clk)

		n := rapid.IntRange(1, 25).Draw(rt, "steps")
		ref := asofSnapshot{} // reference replay of the log so far
		var times []time.Time
		var expected []asofSnapshot

		for k := 0; k < n; k++ {
			// Strictly increasing recorded_at.
			clk.t = clk.t.Add(time.Duration(rapid.IntRange(1, 90).Draw(rt, "dt")) * time.Minute)
			id := rapid.SampledFrom(ids).Draw(rt, "id")
			wd := rapid.Bool().Draw(rt, "withdrawn")
			// Unique summary per step so every write is a real modification.
			rec := &model.Record{Source: "osv", ID: id, Summary: fmt.Sprintf("s%d", k)}
			if wd {
				rec.Withdrawn = clk.t
			}
			changed, err := st.UpsertRecord(ctx, rec)
			if err != nil {
				rt.Fatal(err)
			}
			if !changed {
				rt.Fatalf("step %d: upsert unexpectedly unchanged", k)
			}
			ref["osv:"+id] = asofState{summary: rec.Summary, withdrawn: wd}

			times = append(times, clk.t)
			expected = append(expected, copySnapshot(ref))

			// As-of t_k right after the step equals the replay at step k.
			v, err := st.AsOf(clk.t)
			if err != nil {
				rt.Fatal(err)
			}
			got, err := viewSnapshot(ctx, v)
			if err != nil {
				rt.Fatal(err)
			}
			if !reflect.DeepEqual(got, ref) {
				rt.Fatalf("step %d as-of(%v) = %v, want %v", k, clk.t, got, ref)
			}
		}

		// Monotonicity: later writes never alter earlier as-of views. Also check instants
		// strictly between writes (latest version with recorded_at <= t).
		for k, tk := range times {
			for _, probe := range []time.Time{tk, tk.Add(30 * time.Second)} {
				if probe.After(clk.t) {
					continue
				}
				want := expected[k]
				if k+1 < len(times) && !probe.Before(times[k+1]) {
					want = expected[k+1]
				}
				v, err := st.AsOf(probe)
				if err != nil {
					rt.Fatal(err)
				}
				got, err := viewSnapshot(ctx, v)
				if err != nil {
					rt.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					rt.Fatalf("late as-of(%v) = %v, want %v", probe, got, want)
				}
			}
		}

		// recorded_at of retained versions is never altered: versions per key keep their
		// strictly increasing, distinct recorded_at values, one per write.
		var nv int
		if err := st.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM source_record_version`).Scan(&nv); err != nil {
			rt.Fatal(err)
		}
		if nv != n {
			rt.Fatalf("version rows = %d, want %d", nv, n)
		}
		rows, err := st.DB.QueryContext(ctx, `SELECT recorded_at FROM source_record_version ORDER BY recorded_at`)
		if err != nil {
			rt.Fatal(err)
		}
		i := 0
		for rows.Next() {
			var ra string
			if err := rows.Scan(&ra); err != nil {
				rows.Close()
				rt.Fatal(err)
			}
			if want := times[i].UTC().Format(tsLayout); ra != want {
				rows.Close()
				rt.Fatalf("recorded_at[%d] = %s, want %s", i, ra, want)
			}
			i++
		}
		rows.Close()

		// Before history and invalid / future instants.
		if v, err := st.AsOf(base.Add(-time.Hour)); err != nil {
			rt.Fatal(err)
		} else if got, _ := viewSnapshot(ctx, v); len(got) != 0 {
			rt.Fatalf("pre-history view not empty: %v", got)
		}
		for _, bad := range []time.Time{{}, clk.t.Add(time.Duration(rapid.IntRange(1, 100000).Draw(rt, "future")) * time.Millisecond)} {
			if v, err := st.AsOf(bad); err == nil || v != nil {
				rt.Fatalf("AsOf(%v) = %v, %v; want rejection", bad, v, err)
			}
		}

		// Property 25: Current == AsOf(now) with withdrawn filtered out.
		v, err := st.AsOf(clk.Now())
		if err != nil {
			rt.Fatal(err)
		}
		nowSnap, err := viewSnapshot(ctx, v)
		if err != nil {
			rt.Fatal(err)
		}
		wantCur := asofSnapshot{}
		for k, s := range nowSnap {
			if !s.withdrawn {
				wantCur[k] = s
			}
		}
		curSnap, err := viewSnapshot(ctx, st.Current())
		if err != nil {
			rt.Fatal(err)
		}
		if !reflect.DeepEqual(curSnap, wantCur) {
			rt.Fatalf("Current = %v, want %v", curSnap, wantCur)
		}
	}) // rapid runs 100 checks by default
}

// Unit test (R23.1): temporal reconstruction over the S/T/U graph fixtures.
// **Validates: Requirements 8.2-8.7, 23.1**
func TestAsOfTemporalReconstructionSTU(t *testing.T) {
	ctx := context.Background()
	st := openAsOfStore(t, t.TempDir())
	base := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	clk := &stepClock{base}
	st.SetClock(clk)

	load := func(name string) []string {
		b, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "graph", "snapshot_"+name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var raws []json.RawMessage
		if err := json.Unmarshal(b, &raws); err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, raw := range raws {
			rec, err := osv.Parse("osv", raw)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			if _, err := st.UpsertRecord(ctx, rec); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, rec.ID)
		}
		return ids
	}

	sIDs := load("S")
	tS := clk.t
	clk.t = base.Add(24 * time.Hour)
	tIDs := load("T")
	tT := clk.t
	clk.t = base.Add(48 * time.Hour)
	uIDs := load("U")
	tU := clk.t
	clk.t = base.Add(72 * time.Hour)

	idSet := func(at time.Time) map[string]asofState {
		v, err := st.AsOf(at)
		if err != nil {
			t.Fatal(err)
		}
		s, err := viewSnapshot(ctx, v)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]asofState{}
		for k, x := range s {
			out[k[len("osv:"):]] = x
		}
		return out
	}
	expectIDs := func(label string, got map[string]asofState, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: got %d records %v, want %v", label, len(got), got, want)
		}
		for _, id := range want {
			if _, ok := got[id]; !ok {
				t.Fatalf("%s: missing %s in %v", label, id, got)
			}
		}
	}

	wdID := model.NormID("GHSA-wd-0002")
	gotS, gotT, gotU := idSet(tS), idSet(tT), idSet(tU)
	expectIDs("as-of S", gotS, sIDs)
	expectIDs("as-of T", gotT, tIDs)
	expectIDs("as-of U", gotU, uIDs)

	// Facts recorded later never appear in earlier views.
	if _, ok := gotS[model.NormID("GHSA-bridge-0003")]; ok {
		t.Fatal("bridge advisory visible before it was recorded")
	}
	if _, ok := gotT[model.NormID("GHSA-multi-0004")]; ok {
		t.Fatal("multi-CVE advisory visible as-of T")
	}
	// Withdrawal: active as-of S and T, withdrawn as-of U, still returned as-of T.
	if s, ok := gotT[wdID]; !ok || s.withdrawn {
		t.Fatalf("GHSA-wd-0002 as-of T = %+v, %v; want present and not withdrawn", s, ok)
	}
	if s, ok := gotU[wdID]; !ok || !s.withdrawn {
		t.Fatalf("GHSA-wd-0002 as-of U = %+v, %v; want withdrawn", s, ok)
	}
	// An instant between T and U reconstructs T, even after U was ingested.
	expectIDs("between T and U", idSet(tT.Add(time.Hour)), tIDs)

	// Current excludes the withdrawn advisory.
	cur, err := viewSnapshot(ctx, st.Current())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cur["osv:GHSA-wd-0002"]; ok {
		t.Fatal("Current() returned withdrawn advisory")
	}
	if len(cur) != len(uIDs)-1 {
		t.Fatalf("Current has %d records, want %d", len(cur), len(uIDs)-1)
	}
}
