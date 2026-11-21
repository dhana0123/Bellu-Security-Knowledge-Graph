package validate

import (
	"regexp"
	"strings"
	"testing"
)

func TestNineQueriesAreConstantReadOnlyAndOrdered(t *testing.T) {
	qs, err := Queries()
	if err != nil || len(qs) != 9 {
		t.Fatalf("queries: %d %v", len(qs), err)
	}
	bad := regexp.MustCompile(`(?i)\b(CREATE|MERGE|SET|DELETE|REMOVE|DROP|LOAD\s+CSV|IN\s+TRANSACTIONS)\b`)
	for _, q := range qs {
		body := regexp.MustCompile(`(?m)^//.*$`).ReplaceAllString(q.Cypher, "")
		if bad.MatchString(body) {
			t.Errorf("%s contains a write clause", q.Name)
		}
		if !strings.Contains(body, "ORDER BY") || !strings.Contains(body, "LIMIT") {
			t.Errorf("%s needs ORDER BY and LIMIT", q.Name)
		}
		if strings.Contains(body, "CALL") && !strings.Contains(body, "db.index.fulltext.queryNodes") {
			t.Errorf("%s calls a disallowed procedure", q.Name)
		}
	}
}

func TestCompareTables(t *testing.T) {
	exp := Table{Columns: []string{"a", "b"}, Rows: [][]any{{"x", 1}, {"y", 2.5}}}
	if d := CompareTables(exp, Table{Columns: []string{"a", "b"}, Rows: [][]any{{"x", int64(1)}, {"y", 2.5}}}); !d.Match {
		t.Fatalf("int/float should match: %+v", d)
	}
	d := CompareTables(exp, Table{Columns: []string{"a", "b"}, Rows: [][]any{{"x", 1}, {"z", 2.5}}})
	if d.Match || d.RowIndex != 1 || !strings.Contains(d.Message, `["z",2.5]`) {
		t.Fatalf("first differing row: %+v", d)
	}
	if d := CompareTables(exp, Table{Columns: []string{"a", "c"}, Rows: exp.Rows}); d.Match || d.RowIndex != -1 {
		t.Fatalf("columns: %+v", d)
	}
	if d := CompareTables(exp, Table{Columns: exp.Columns, Rows: exp.Rows[:1]}); d.Match || d.RowIndex != 1 || d.Actual != nil {
		t.Fatalf("missing row: %+v", d)
	}
	if d := CompareTables(exp, Table{Columns: exp.Columns, Rows: append(exp.Rows, []any{"w", 0})}); d.Match || d.RowIndex != 2 || d.Actual == nil {
		t.Fatalf("extra row: %+v", d)
	}
	if d := CompareTables(exp, Table{Columns: exp.Columns, Rows: [][]any{exp.Rows[1], exp.Rows[0]}}); d.Match {
		t.Fatal("row order must matter")
	}
}

func TestQueriesPassed(t *testing.T) {
	if !QueriesPassed(nil) || !QueriesPassed([]QueryResult{{Passed: true}}) || QueriesPassed([]QueryResult{{Passed: true}, {}}) {
		t.Fatal("QueriesPassed")
	}
}
