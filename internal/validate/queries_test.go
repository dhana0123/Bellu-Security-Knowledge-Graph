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
		for _, p := range []Profile{ProfileFixture, ProfileBaseline} {
			if _, err := QueryParams(p, q.Name); err != nil {
				t.Error(err)
			}
		}
		if strings.Contains(body, "CALL") && !strings.Contains(body, "db.index.fulltext.queryNodes") {
			t.Errorf("%s calls a disallowed procedure", q.Name)
		}
	}
}

func TestFixtureExpectedFilesRecordedAndBaselineNot(t *testing.T) {
	for _, n := range queryNames {
		e, found, err := LoadQueryExpected(ProfileFixture, n)
		if err != nil || !found || !e.Derived || len(e.Columns) == 0 {
			t.Errorf("fixture %s: found=%v derived=%v err=%v", n, found, e.Derived, err)
		}
		if _, found, err := LoadQueryExpected(ProfileBaseline, n); err != nil || found {
			t.Errorf("baseline %s: found=%v err=%v", n, found, err)
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

func TestEvaluateQuery(t *testing.T) {
	e, _, _ := LoadQueryExpected(ProfileFixture, "vendor_products")
	r, err := EvaluateQuery(ProfileFixture, "vendor_products", e.Table, nil)
	if err != nil || !r.Passed || !r.Derived {
		t.Fatalf("%+v %v", r, err)
	}
	r, _ = EvaluateQuery(ProfileFixture, "vendor_products", Table{Columns: e.Columns, Rows: [][]any{{"x", "y"}}}, nil)
	if r.Passed || r.Diff == nil || r.Diff.RowIndex != 0 {
		t.Fatalf("%+v", r)
	}
	r, _ = EvaluateQuery(ProfileBaseline, "vendor_products", e.Table, nil)
	if r.Passed || r.Recorded || !strings.Contains(r.Message, "--update-expected") {
		t.Fatalf("missing expected must fail clearly: %+v", r)
	}
	r, _ = EvaluateQuery(ProfileFixture, "vendor_products", Table{}, errTest)
	if r.Passed || !strings.Contains(r.Message, "query failed") {
		t.Fatalf("%+v", r)
	}
}

type testErr string

func (e testErr) Error() string { return string(e) }

const errTest = testErr("boom")

func TestEncodeExpectedRoundTrip(t *testing.T) {
	in := Table{Columns: []string{"a"}, Rows: [][]any{{int64(3)}, {nil}}}
	b, err := EncodeExpected(ProfileBaseline, in)
	if err != nil || !strings.Contains(string(b), `"profile": "baseline"`) {
		t.Fatalf("%s %v", b, err)
	}
	if files, err := embeddedQueryFiles(); err != nil || len(files) != 9 {
		t.Fatalf("%v %v", files, err)
	}
}
