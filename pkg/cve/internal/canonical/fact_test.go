package canonical

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/trust"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

func newFactStore(t *testing.T) (*Store, *fakeClock) {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	c := &fakeClock{t: time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)}
	s.SetClock(c)
	return s, c
}

func count(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func directIn(id, layer, src string, at time.Time) FactInput {
	return FactInput{FactID: id, Layer: layer, Kind: "affects", Subject: "CVE-1", Payload: "{}",
		Prov: trust.Provenance{Source: src, Direction: trust.Direct, IngestTime: at}}
}

func inferredIn(id, layer string) FactInput {
	return FactInput{FactID: id, Layer: layer, Kind: "affects", Subject: "CVE-1", Payload: "{}",
		Prov: trust.Provenance{Source: "model", Direction: trust.Inferred}}
}

func TestWriteFactRejectsBadProvenanceLeavesStoreUnchanged(t *testing.T) {
	s, _ := newFactStore(t)
	ctx := context.Background()
	in := directIn("f1", LayerRaw, "", time.Now())
	if _, err := s.WriteFact(ctx, in); !errors.Is(err, trust.ErrMissingSource) {
		t.Fatal(err)
	}
	in = directIn("f1", LayerRaw, "nvd", time.Now())
	in.Prov.Direction = ""
	if _, err := s.WriteFact(ctx, in); !errors.Is(err, trust.ErrMissingDirection) {
		t.Fatal(err)
	}
	if count(t, s, "fact_version") != 0 || count(t, s, "change_history") != 0 {
		t.Fatal("store changed")
	}
}

func TestWriteFactDirectAndLayers(t *testing.T) {
	s, _ := newFactStore(t)
	ctx := context.Background()
	if _, err := s.WriteFact(ctx, directIn("f1", LayerRaw, "nvd", time.Now())); err != nil {
		t.Fatal(err)
	}
	in := directIn("f2", LayerResolved, "nvd", time.Now())
	in.Evidence = []trust.Evidence{{Source: "nvd", Direct: true}, {Source: "osv", Direct: true}}
	if _, err := s.WriteFact(ctx, in); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteFact(ctx, inferredIn("f3", LayerInferred)); err != nil {
		t.Fatal(err)
	}
	raw, _ := s.FactsInLayers(ctx, LayerRaw)
	if len(raw) != 1 || raw[0].FactID != "f1" || raw[0].TrustState != trust.Verified || *raw[0].Confidence != 0.80 || raw[0].RuleID != trust.RuleSingleAuthoritative {
		t.Fatalf("%+v", raw)
	}
	both, _ := s.FactsInLayers(ctx, LayerResolved, LayerInferred)
	if len(both) != 2 || both[0].TrustState != trust.Corroborated || both[1].TrustState != trust.Predicted || both[1].Confidence != nil {
		t.Fatalf("%+v", both)
	}
	if none, _ := s.FactsInLayers(ctx); len(none) != 0 {
		t.Fatal("empty layer set returns nothing")
	}
	if _, err := s.FactsInLayers(ctx, "bogus"); !errors.Is(err, ErrInvalidLayer) {
		t.Fatal(err)
	}
}

func TestWriteFactPredictedRejectedInRawAndValidated(t *testing.T) {
	s, _ := newFactStore(t)
	ctx := context.Background()
	for _, l := range []string{LayerRaw, LayerValidated} {
		if _, err := s.WriteFact(ctx, inferredIn("p-"+l, l)); !errors.Is(err, ErrLayerRejectsPredictions) {
			t.Fatalf("%s: %v", l, err)
		}
	}
	if count(t, s, "fact_version") != 0 || count(t, s, "change_history") != 0 {
		t.Fatal("store changed")
	}
}

func TestPromotionRequiresNewDirectEvidence(t *testing.T) {
	s, clk := newFactStore(t)
	ctx := context.Background()
	if _, err := s.WriteFact(ctx, inferredIn("f", LayerInferred)); err != nil {
		t.Fatal(err)
	}
	histBefore := count(t, s, "change_history")
	clk.t = clk.t.Add(time.Hour)

	// Direct evidence ingested before the fact became predicted: rejected.
	old := directIn("f", LayerInferred, "nvd", clk.t.Add(-2*time.Hour))
	res, err := s.WriteFact(ctx, old)
	if !errors.Is(err, ErrPromotionRejected) || res.Changed {
		t.Fatalf("%v %+v", err, res)
	}
	if count(t, s, "fact_version") != 1 || count(t, s, "change_history") != histBefore+1 {
		t.Fatal("expected one rejection history row and no new version")
	}
	facts, _ := s.FactsInLayers(ctx, LayerInferred)
	if facts[0].TrustState != trust.Predicted {
		t.Fatal("state must stay predicted")
	}

	// Fresh direct evidence: applied.
	if res, err = s.WriteFact(ctx, directIn("f", LayerInferred, "nvd", clk.t)); err != nil || !res.Changed || res.Version != 2 {
		t.Fatalf("%v %+v", err, res)
	}
	facts, _ = s.FactsInLayers(ctx, LayerInferred)
	if facts[0].TrustState != trust.Verified {
		t.Fatal("expected verified")
	}
}

func TestHistoryAppendOnlyAndProvenanceChange(t *testing.T) {
	s, clk := newFactStore(t)
	ctx := context.Background()
	if _, err := s.WriteFact(ctx, directIn("f", LayerResolved, "nvd", clk.t)); err != nil {
		t.Fatal(err)
	}
	// identical rewrite is a no-op
	if res, _ := s.WriteFact(ctx, directIn("f", LayerResolved, "nvd", clk.t)); res.Changed || count(t, s, "fact_version") != 1 {
		t.Fatal("identical write must not add a version")
	}
	clk.t = clk.t.Add(time.Minute)
	if res, err := s.WriteFact(ctx, directIn("f", LayerResolved, "osv", clk.t)); err != nil || !res.Changed {
		t.Fatal(err)
	}
	if count(t, s, "fact_version") != 2 || count(t, s, "change_history") != 1 {
		t.Fatalf("versions=%d history=%d", count(t, s, "fact_version"), count(t, s, "change_history"))
	}
	if _, err := s.DB.Exec(`UPDATE change_history SET cause='x'`); err == nil {
		t.Fatal("update must fail")
	}
	if _, err := s.DB.Exec(`DELETE FROM change_history`); err == nil {
		t.Fatal("delete must fail")
	}
}
