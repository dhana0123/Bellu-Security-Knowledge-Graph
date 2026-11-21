package validate

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"reflect"
	"sort"
	"time"
)

//go:embed queries
var queriesFS embed.FS

// QueryTimeout is the per-query timeout of the representative queries.
const QueryTimeout = 30 * time.Second

// Query is one representative query (Requirement 6.1). Cypher is a constant
// read-only statement; values come only from Params.
type Query struct {
	Name   string
	Cypher string
}

// queryNames lists the nine categories in report order.
var queryNames = []string{
	"lookup_cve",
	"weakness_vulnerabilities",
	"product_vulnerabilities",
	"vendor_products",
	"vulnerability_exploits",
	"vulnerability_domains",
	"fulltext_description",
	"published_range",
	"cvss_v3_version",
}

// Queries returns the nine embedded queries in report order.
func Queries() ([]Query, error) {
	out := make([]Query, 0, len(queryNames))
	for _, n := range queryNames {
		b, err := queriesFS.ReadFile("queries/" + n + ".cypher")
		if err != nil {
			return nil, err
		}
		out = append(out, Query{Name: n, Cypher: string(b)})
	}
	return out, nil
}

// Table is an ordered query result: column names and rows of JSON values.
type Table struct {
	Columns []string `json:"columns"`
	Rows    [][]any  `json:"rows"`
}

// Diff is the outcome of comparing two tables.
type Diff struct {
	Match    bool   `json:"match"`
	Message  string `json:"message,omitempty"`
	RowIndex int    `json:"rowIndex"` // first differing row, -1 when not row related
	Expected []any  `json:"expectedRow,omitempty"`
	Actual   []any  `json:"actualRow,omitempty"`
}

// Normalize converts a table to plain JSON values (numbers as float64, nil
// as null) so integer and float spellings of one number compare equal.
func Normalize(t Table) (Table, error) {
	b, err := json.Marshal(t)
	if err != nil {
		return Table{}, err
	}
	var out Table
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&out); err != nil {
		return Table{}, err
	}
	if out.Rows == nil {
		out.Rows = [][]any{}
	}
	return out, nil
}

// CompareTables is pure. It matches only when column names, row count and
// every row (in order) are equal. On a mismatch it names the first
// differing row.
func CompareTables(exp, act Table) Diff {
	e, errE := Normalize(exp)
	a, errA := Normalize(act)
	if errE != nil || errA != nil {
		return Diff{Message: fmt.Sprintf("cannot normalize tables: %v %v", errE, errA), RowIndex: -1}
	}
	if !reflect.DeepEqual(nonNil(e.Columns), nonNil(a.Columns)) {
		return Diff{RowIndex: -1, Message: fmt.Sprintf("column names differ: expected %v, actual %v", e.Columns, a.Columns)}
	}
	n := len(e.Rows)
	if len(a.Rows) < n {
		n = len(a.Rows)
	}
	for i := 0; i < n; i++ {
		if !reflect.DeepEqual(e.Rows[i], a.Rows[i]) {
			return Diff{RowIndex: i, Expected: e.Rows[i], Actual: a.Rows[i],
				Message: fmt.Sprintf("row %d differs: expected %s, actual %s", i, js(e.Rows[i]), js(a.Rows[i]))}
		}
	}
	switch {
	case len(e.Rows) > len(a.Rows):
		return Diff{RowIndex: n, Expected: e.Rows[n],
			Message: fmt.Sprintf("row count differs: expected %d, actual %d; first missing row %d: %s", len(e.Rows), len(a.Rows), n, js(e.Rows[n]))}
	case len(a.Rows) > len(e.Rows):
		return Diff{RowIndex: n, Actual: a.Rows[n],
			Message: fmt.Sprintf("row count differs: expected %d, actual %d; first extra row %d: %s", len(e.Rows), len(a.Rows), n, js(a.Rows[n]))}
	}
	return Diff{Match: true, RowIndex: -1}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// QueryResult is the outcome of one representative query. A query passes
// when it runs without error; selector-based result checks come with the
// smoke check.
type QueryResult struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Rows    int    `json:"rows"`
	Message string `json:"message,omitempty"`
}

// QueriesPassed reports whether every query result passed.
func QueriesPassed(rs []QueryResult) bool {
	for _, r := range rs {
		if !r.Passed {
			return false
		}
	}
	return true
}

// embeddedQueryFiles returns the sorted embedded query file names (for tests).
func embeddedQueryFiles() ([]string, error) {
	es, err := fs.ReadDir(queriesFS, "queries")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range es {
		if !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}
