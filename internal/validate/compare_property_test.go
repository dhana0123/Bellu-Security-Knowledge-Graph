package validate

import (
	"sort"
	"testing"

	"pgregory.net/rapid"
)

// Feature: bellu-security-knowledge-graph, Property 27: Validator comparison
// **Validates: Requirements 5.2, 5.4, 5.5, 5.10, 5.11, 6.3, 6.5**
func TestProperty27ValidatorComparisonCounts(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		names := []string{"A", "B", "C", "D", "E"}
		exp := Expected{Metrics: map[string]int64{}}
		actual := map[string]int64{}
		var disc []Discrepancy
		wantFailed := []string{}
		for _, m := range names {
			want := rapid.Int64Range(0, 6).Draw(t, "want"+m)
			got := rapid.Int64Range(0, 6).Draw(t, "got"+m)
			exp.Metrics[m] = want
			actual[m] = got
			obs := rapid.SliceOfN(rapid.Int64Range(0, 6), 0, 3).Draw(t, "obs"+m)
			disc = append(disc, Discrepancy{ID: "d" + m, Metric: m, Kind: "count", Observed: obs})
			// A discrepancy for another metric must never apply.
			other := names[(len(disc))%len(names)]
			disc = append(disc, Discrepancy{ID: "x" + m, Metric: other + "x", Kind: "count", Observed: []int64{got}})
			ok := got == want
			for _, o := range obs {
				ok = ok || o == got
			}
			if !ok {
				wantFailed = append(wantFailed, "count:"+m)
			}
		}
		in := Inputs{
			Profile: "baseline", Expected: &exp, Discrepancy: disc, Counts: actual,
			Constraints: nil, // schema checks fail unless set below
		}
		complete := rapid.Bool().Draw(t, "schemaComplete")
		if complete {
			for _, c := range RequiredConstraints {
				in.Constraints = append(in.Constraints, CatalogConstraint{c.Name, "UNIQUENESS", c.Label, c.Prop})
			}
			for _, i := range RequiredIndexes {
				in.Indexes = append(in.Indexes, CatalogIndex{i.Name, i.Type, "ONLINE"})
			}
		}
		rs := CompareCounts(exp, disc, actual)
		if AllPassed(rs) != (len(wantFailed) == 0) {
			t.Fatalf("AllPassed mismatch, want failed %v", wantFailed)
		}
		rep := BuildReport(in)
		var gotCountFailed []string
		for _, f := range rep.Failed {
			if len(f) > 6 && f[:6] == "count:" {
				gotCountFailed = append(gotCountFailed, f)
			}
		}
		sort.Strings(wantFailed)
		if len(gotCountFailed) != len(wantFailed) {
			t.Fatalf("failed metrics %v, want %v", gotCountFailed, wantFailed)
		}
		for i := range wantFailed {
			if gotCountFailed[i] != wantFailed[i] {
				t.Fatalf("failed metrics %v, want %v", gotCountFailed, wantFailed)
			}
		}
		wantStatus := "passed"
		if len(rep.Failed) > 0 {
			wantStatus = "failed"
		}
		if !complete && len(rep.Failed) == len(gotCountFailed) {
			t.Fatal("missing schema must be reported as failed")
		}
		if rep.Status != wantStatus || rep.Passed() != (wantStatus == "passed") {
			t.Fatalf("status %q with failed %v", rep.Status, rep.Failed)
		}
		if complete && len(wantFailed) == 0 && rep.Status != "passed" {
			t.Fatalf("expected passed, failed=%v", rep.Failed)
		}
	})
}

func genTable(t *rapid.T, label string, cols []string) Table {
	rows := rapid.SliceOfN(rapid.SliceOfN(rapid.Int64Range(0, 3), len(cols), len(cols)), 0, 5).Draw(t, label)
	tb := Table{Columns: cols, Rows: [][]any{}}
	for _, r := range rows {
		row := make([]any, len(r))
		for i, v := range r {
			row[i] = v
		}
		tb.Rows = append(tb.Rows, row)
	}
	return tb
}

func TestProperty27ValidatorComparisonTables(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cols := []string{"a", "b"}
		exp := genTable(t, "exp", cols)
		act := genTable(t, "act", cols)
		if rapid.Bool().Draw(t, "sameCols") == false {
			act.Columns = []string{"a", "c"}
		}
		d := CompareTables(exp, act)
		colsEq := act.Columns[1] == "b"
		first := -1
		n := len(exp.Rows)
		if len(act.Rows) < n {
			n = len(act.Rows)
		}
		for i := 0; i < n && first < 0; i++ {
			for j := range exp.Rows[i] {
				if exp.Rows[i][j] != act.Rows[i][j] {
					first = i
					break
				}
			}
		}
		if first < 0 && len(exp.Rows) != len(act.Rows) {
			first = n
		}
		wantMatch := colsEq && first < 0
		if d.Match != wantMatch {
			t.Fatalf("match=%v want %v (%s)", d.Match, wantMatch, d.Message)
		}
		if !wantMatch && d.Message == "" {
			t.Fatal("mismatch must carry a message")
		}
		if colsEq && !wantMatch && d.RowIndex != first {
			t.Fatalf("rowIndex=%d want %d", d.RowIndex, first)
		}
		if wantMatch && d.RowIndex != -1 {
			t.Fatalf("rowIndex=%d on match", d.RowIndex)
		}
	})
}
