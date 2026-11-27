package canonical

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/trust"
)

var allLayers = []string{LayerRaw, LayerResolved, LayerInferred, LayerValidated}

func propStore(t *rapid.T) (*Store, *fakeClock) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	c := &fakeClock{t: time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)}
	s.SetClock(c)
	return s, c
}

// dump serialises fact_version and change_history so stores can be compared byte for byte.
func dump(t *rapid.T, s *Store) string {
	var b strings.Builder
	for _, q := range []string{
		`SELECT * FROM fact_version ORDER BY fact_id, version`,
		`SELECT * FROM change_history ORDER BY rowid`,
	} {
		rows, err := s.DB.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&b, "%q\n", vals)
		}
		rows.Close()
		b.WriteString("--\n")
	}
	return b.String()
}

func drawID(t *rapid.T, label string) string {
	return rapid.StringMatching(`[a-z]{1,6}`).Draw(t, label)
}

// seed writes a few valid facts so "unchanged" checks are not vacuous.
func seed(t *rapid.T, s *Store, at time.Time) {
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := s.WriteFact(ctx, directIn(fmt.Sprintf("seed%d", i), allLayers[i], "nvd", at)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.WriteFact(ctx, inferredIn("seedp", LayerInferred)); err != nil {
		t.Fatal(err)
	}
}

// Feature: bellu-security-knowledge-graph, Property 21: Missing provenance is rejected
// **Validates: Requirements 7.1, 7.2**
func TestPropertyMissingProvenanceRejected(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s, clk := propStore(t)
		defer s.Close()
		seed(t, s, clk.t)
		before := dump(t, s)

		in := FactInput{
			FactID: drawID(t, "id"), Layer: rapid.SampledFrom(allLayers).Draw(t, "layer"),
			Kind: "affects", Subject: "CVE-1", Payload: "{}",
		}
		missingSource := rapid.Bool().Draw(t, "noSource")
		badDir := rapid.Bool().Draw(t, "badDir")
		if !missingSource && !badDir {
			badDir = true
		}
		if !missingSource {
			in.Prov.Source = rapid.SampledFrom([]string{"nvd", "osv", "model"}).Draw(t, "src")
		}
		if badDir {
			in.Prov.Direction = trust.Direction(rapid.SampledFrom([]string{"", "DIRECT", "unknown", " "}).Draw(t, "dir"))
		} else {
			in.Prov.Direction = rapid.SampledFrom([]trust.Direction{trust.Direct, trust.Inferred}).Draw(t, "okdir")
		}

		_, err := s.WriteFact(context.Background(), in)
		if err == nil {
			t.Fatal("expected error")
		}
		if missingSource {
			if !errors.Is(err, trust.ErrMissingSource) || !strings.Contains(err.Error(), "source") {
				t.Fatalf("want missing source, got %v", err)
			}
		} else if !errors.Is(err, trust.ErrMissingDirection) || !strings.Contains(err.Error(), "direction") {
			t.Fatalf("want missing direction, got %v", err)
		}
		if after := dump(t, s); after != before {
			t.Fatal("store changed after rejected write")
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 22: Predictions are never promoted without new direct evidence
// **Validates: Requirements 7.9, 20.3**
func TestPropertyNoPromotionWithoutNewDirectEvidence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s, clk := propStore(t)
		defer s.Close()
		ctx := context.Background()
		layer := rapid.SampledFrom([]string{LayerResolved, LayerInferred}).Draw(t, "layer")
		if _, err := s.WriteFact(ctx, inferredIn("f", layer)); err != nil {
			t.Fatal(err)
		}
		predictedAt := clk.t
		clk.t = clk.t.Add(time.Hour)

		type item struct {
			Direct bool
			Offset int
		}
		items := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) item {
			return item{rapid.Bool().Draw(t, "direct"), rapid.IntRange(-5, 5).Draw(t, "off")}
		}), 1, 5).Draw(t, "items")
		srcs := []string{"nvd", "osv", "ghsa", "kev", "x"}
		var ev []trust.Evidence
		hasDirect, wantApplied := false, false
		for i, it := range items {
			ev = append(ev, trust.Evidence{Source: srcs[i], Direct: it.Direct,
				IngestedAt: predictedAt.Add(time.Duration(it.Offset) * time.Second)})
			if it.Direct {
				hasDirect = true
				if it.Offset > 0 {
					wantApplied = true
				}
			}
		}
		if !hasDirect {
			ev[0].Direct = true
			wantApplied = false
			for _, e := range ev {
				if e.Direct && e.IngestedAt.After(predictedAt) {
					wantApplied = true
				}
			}
		}

		vBefore, hBefore := count2(t, s)
		in := directIn("f", layer, "nvd", clk.t)
		in.Evidence = ev
		res, err := s.WriteFact(ctx, in)
		facts, _ := s.FactsInLayers(ctx, layer)
		var cur Fact
		for _, f := range facts {
			if f.FactID == "f" {
				cur = f
			}
		}
		vAfter, hAfter := count2(t, s)
		if wantApplied {
			if err != nil || !res.Changed || cur.TrustState == trust.Predicted {
				t.Fatalf("promotion should apply: %v %+v %s", err, res, cur.TrustState)
			}
			return
		}
		if !errors.Is(err, ErrPromotionRejected) || res.Changed {
			t.Fatalf("promotion should be rejected: %v %+v", err, res)
		}
		if cur.TrustState != trust.Predicted || vAfter != vBefore || hAfter != hBefore+1 {
			t.Fatalf("state=%s versions %d->%d history %d->%d", cur.TrustState, vBefore, vAfter, hBefore, hAfter)
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 22: Predictions are never promoted without new direct evidence (raw/validated rejection)
// **Validates: Requirements 7.9, 20.3**
func TestPropertyPredictedRejectedInRawValidated(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s, clk := propStore(t)
		defer s.Close()
		seed(t, s, clk.t)
		before := dump(t, s)
		layer := rapid.SampledFrom([]string{LayerRaw, LayerValidated}).Draw(t, "layer")
		in := inferredIn(drawID(t, "id"), layer)
		if rapid.Bool().Draw(t, "withRule") {
			c := 0.5
			in.Prov.Confidence, in.Prov.RuleID = &c, "r1"
		}
		if _, err := s.WriteFact(context.Background(), in); !errors.Is(err, ErrLayerRejectsPredictions) {
			t.Fatalf("got %v", err)
		}
		if dump(t, s) != before {
			t.Fatal("store changed")
		}
	})
}

func count2(t *rapid.T, s *Store) (int, int) {
	var v, h int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM fact_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM change_history`).Scan(&h); err != nil {
		t.Fatal(err)
	}
	return v, h
}

// Feature: bellu-security-knowledge-graph, Property 23: Layer isolation
// **Validates: Requirements 7.11**
func TestPropertyLayerIsolation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s, clk := propStore(t)
		defer s.Close()
		ctx := context.Background()
		n := rapid.IntRange(0, 12).Draw(t, "n")
		layerOf := map[string]string{}
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("f%02d", i)
			layer := rapid.SampledFrom(allLayers).Draw(t, "layer")
			var in FactInput
			if (layer == LayerInferred || layer == LayerResolved) && rapid.Bool().Draw(t, "predicted") {
				in = inferredIn(id, layer)
			} else {
				in = directIn(id, layer, "nvd", clk.t)
			}
			if _, err := s.WriteFact(ctx, in); err != nil {
				t.Fatal(err)
			}
			layerOf[id] = layer
		}
		var sel []string
		inSel := map[string]bool{}
		for _, l := range allLayers {
			if rapid.Bool().Draw(t, "sel-"+l) {
				sel = append(sel, l)
				inSel[l] = true
			}
		}
		var want []string
		for id, l := range layerOf {
			if inSel[l] {
				want = append(want, id)
			}
		}
		sort.Strings(want)
		got, err := s.FactsInLayers(ctx, sel...)
		if err != nil {
			t.Fatal(err)
		}
		var gotIDs []string
		for _, f := range got {
			if !inSel[f.Layer] {
				t.Fatalf("fact %s from layer %s leaked", f.FactID, f.Layer)
			}
			gotIDs = append(gotIDs, f.FactID)
		}
		if strings.Join(gotIDs, ",") != strings.Join(want, ",") {
			t.Fatalf("got %v want %v", gotIDs, want)
		}
	})
}

// Unit test for R23.1: every returned fact reports its source and direction.
func TestEveryReturnedFactReportsSource(t *testing.T) {
	s, clk := newFactStore(t)
	ctx := context.Background()
	for i, l := range allLayers {
		if _, err := s.WriteFact(ctx, directIn(fmt.Sprintf("d%d", i), l, fmt.Sprintf("src%d", i), clk.t)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.WriteFact(ctx, inferredIn("p", LayerInferred)); err != nil {
		t.Fatal(err)
	}
	facts, err := s.FactsInLayers(ctx, allLayers...)
	if err != nil || len(facts) != 5 {
		t.Fatalf("%v %d", err, len(facts))
	}
	for _, f := range facts {
		if f.Source == "" || (f.Direction != string(trust.Direct) && f.Direction != string(trust.Inferred)) {
			t.Fatalf("fact %s lacks provenance: %+v", f.FactID, f)
		}
	}
}
