package validate

import (
	"testing"

	"pgregory.net/rapid"
)

func TestEmbeddedData(t *testing.T) {
	b, err := LoadExpected(ProfileBaseline)
	if err != nil || len(b.Metrics) != 16 || b.Metrics["AFFECTS"] != 212654 {
		t.Fatalf("baseline: %v %d", err, len(b.Metrics))
	}
	f, err := LoadExpected(ProfileFixture)
	if err != nil || len(f.Metrics) != 16 {
		t.Fatalf("fixture: %v %d", err, len(f.Metrics))
	}
	for m := range b.Metrics {
		if _, ok := f.Metrics[m]; !ok {
			t.Errorf("fixture lacks %s", m)
		}
	}
	if _, err := LoadExpected("nope"); err == nil {
		t.Error("expected error for unknown profile")
	}
	d, err := LoadDiscrepancies()
	if err != nil || len(d) != 5 {
		t.Fatalf("discrepancies: %v %d", err, len(d))
	}
}

func TestCompareCounts(t *testing.T) {
	exp, _ := LoadExpected(ProfileBaseline)
	disc, _ := LoadDiscrepancies()
	act := map[string]int64{}
	for k, v := range exp.Metrics {
		act[k] = v
	}
	if !AllPassed(CompareCounts(exp, disc, act)) {
		t.Fatal("exact match should pass")
	}
	act["AFFECTS"] = 212656
	rs := CompareCounts(exp, disc, act)
	if !AllPassed(rs) {
		t.Fatal("212656 is a known discrepancy")
	}
	act["AFFECTS"] = 212655
	if AllPassed(CompareCounts(exp, disc, act)) {
		t.Fatal("212655 must fail")
	}
	act["AFFECTS"] = 212654
	delete(act, "Vendor")
	if AllPassed(CompareCounts(exp, disc, act)) {
		t.Fatal("missing metric must fail")
	}
	act["Vendor"] = 1
	act["Weakness"] = 212656 // discrepancy for another metric must not apply
	for _, r := range CompareCounts(exp, disc, act) {
		if r.Metric == "Weakness" && r.Passed {
			t.Fatal("discrepancy leaked across metrics")
		}
	}
}

func TestCompareCountsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		want := rapid.Int64Range(0, 1000).Draw(t, "want")
		got := rapid.Int64Range(0, 1000).Draw(t, "got")
		obs := rapid.SliceOf(rapid.Int64Range(0, 1000)).Draw(t, "obs")
		exp := Expected{Metrics: map[string]int64{"m": want}}
		disc := []Discrepancy{{ID: "d", Metric: "m", Kind: "count", Observed: obs}}
		r := CompareCounts(exp, disc, map[string]int64{"m": got})[0]
		in := false
		for _, o := range obs {
			in = in || o == got
		}
		if r.Passed != (got == want || in) {
			t.Fatalf("want=%d got=%d obs=%v passed=%v", want, got, obs, r.Passed)
		}
	})
}
