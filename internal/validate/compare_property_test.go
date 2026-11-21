package validate

import (
	"testing"

	"pgregory.net/rapid"
)

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

// Feature: bellu-security-knowledge-graph, Property 27: Validator comparison
// **Validates: Requirements 13**
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
