package upsert

import (
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
)

func epssBatch(score, pct float64, day string) Batch {
	d, _ := time.Parse("2006-01-02", day)
	return Batch{{ID: "CVE-2021-1001", N: source.Normalized{
		Gate: []source.Ref{cve("CVE-2021-1001")},
		Entities: []source.Entity{{
			Ref:             cve("CVE-2021-1001"),
			Props:           map[string]any{"epssScore": score, "epssPercentile": pct, "epssDate": d},
			ChangeThreshold: map[string]float64{"epssScore": 0.01},
			ChangeFollows:   map[string]string{"epssPercentile": "epssScore", "epssDate": "epssScore"},
		}},
	}}}
}

func epssState(t *testing.T) State {
	t.Helper()
	st, _, _ := Plan(emptyState(), nvdBatch("a"), rc("nvd", false))
	return fold(emptyState(), st)
}

func TestThresholdBelowStoresWithoutRecord(t *testing.T) {
	st := epssState(t)
	w, recs, _ := Plan(st, epssBatch(0.05, 0.5, "2026-11-20"), rc("epss", false))
	if len(recs) != 3 { // first value on the node: always recorded
		t.Fatalf("first set: %d records", len(recs))
	}
	st = fold(st, w)
	w, recs, cnt := Plan(st, epssBatch(0.059, 0.6, "2026-11-21"), rc("epss", false))
	if len(recs) != 0 {
		t.Fatalf("below threshold wrote records: %+v", recs)
	}
	if cnt.Updated != 1 || len(w.Nodes) != 1 {
		t.Fatalf("values must be stored: %+v %+v", cnt, w)
	}
	p := w.Nodes[0].Props
	if p["epssScore"] != 0.059 || p["epssPercentile"] != 0.6 {
		t.Fatalf("stored props %v", p)
	}
}

func TestThresholdReachedRecordsScoreAndFollowers(t *testing.T) {
	st := epssState(t)
	w, _, _ := Plan(st, epssBatch(0.05, 0.5, "2026-11-20"), rc("epss", false))
	st = fold(st, w)
	// A change of exactly the threshold counts.
	_, recs, _ := Plan(st, epssBatch(0.06, 0.6, "2026-11-21"), rc("epss", false))
	fields := map[string]bool{}
	for _, r := range recs {
		fields[r.Field] = true
	}
	if len(recs) != 3 || !fields["epssScore"] || !fields["epssPercentile"] || !fields["epssDate"] {
		t.Fatalf("records %+v", recs)
	}
	// A decrease counts too.
	_, recs, _ = Plan(st, epssBatch(0.02, 0.5, "2026-11-20"), rc("epss", false))
	if len(recs) != 1 || recs[0].Field != "epssScore" {
		t.Fatalf("decrease records %+v", recs)
	}
}

func TestThresholdZeroRecordsEveryChange(t *testing.T) {
	st := epssState(t)
	w, _, _ := Plan(st, epssBatch(0.05, 0.5, "2026-11-20"), rc("epss", false))
	st = fold(st, w)
	b := epssBatch(0.05001, 0.5, "2026-11-20")
	b[0].N.Entities[0].ChangeThreshold["epssScore"] = 0
	if _, recs, _ := Plan(st, b, rc("epss", false)); len(recs) != 1 {
		t.Fatalf("records %+v", recs)
	}
}

func TestThresholdUnchangedWritesNothing(t *testing.T) {
	st := epssState(t)
	w, _, _ := Plan(st, epssBatch(0.05, 0.5, "2026-11-20"), rc("epss", false))
	st = fold(st, w)
	w, recs, cnt := Plan(st, epssBatch(0.05, 0.5, "2026-11-20"), rc("epss", false))
	if len(w.Nodes) != 0 || len(recs) != 0 || cnt.Unchanged != 1 {
		t.Fatalf("%+v %+v %+v", w, recs, cnt)
	}
}

// Without ChangeThreshold every changed property is recorded, as before.
func TestNoThresholdRecordsEveryChange(t *testing.T) {
	st := epssState(t)
	b := epssBatch(0.05, 0.5, "2026-11-20")
	b[0].N.Entities[0].ChangeThreshold = nil
	b[0].N.Entities[0].ChangeFollows = nil
	w, _, _ := Plan(st, b, rc("epss", false))
	st = fold(st, w)
	b = epssBatch(0.0501, 0.5, "2026-11-20")
	b[0].N.Entities[0].ChangeThreshold = nil
	b[0].N.Entities[0].ChangeFollows = nil
	if _, recs, _ := Plan(st, b, rc("epss", false)); len(recs) != 1 {
		t.Fatalf("records %+v", recs)
	}
}

func TestThresholdGateSkipsMissingNode(t *testing.T) {
	_, recs, cnt := Plan(emptyState(), epssBatch(0.5, 0.5, "2026-11-21"), rc("epss", false))
	if cnt.Skipped != 1 || len(recs) != 0 {
		t.Fatalf("%+v %+v", cnt, recs)
	}
}
