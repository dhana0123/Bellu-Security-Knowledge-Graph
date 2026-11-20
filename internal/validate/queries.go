package validate

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"reflect"
	"sort"
	"strings"
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

// profileParams holds the parameters of each query per profile. The baseline
// parameters name well-known real records (Log4Shell, CWE-79, OpenSSL).
var profileParams = map[Profile]map[string]map[string]any{
	ProfileFixture: {
		"lookup_cve":               {"cveID": "CVE-2019-1005"},
		"weakness_vulnerabilities": {"cweID": "CWE-89"},
		"product_vulnerabilities":  {"productName": "openssl"},
		"vendor_products":          {"vendorName": "apache"},
		"vulnerability_exploits":   {"cveID": "CVE-2019-1002"},
		"vulnerability_domains":    {"cveID": "CVE-2019-1004"},
		"fulltext_description":     {"query": "12"},
		"published_range":          {"from": "2019-03-01", "to": "2019-04-30"},
		"cvss_v3_version":          {"v3version": 3.0},
	},
	ProfileBaseline: {
		"lookup_cve":               {"cveID": "CVE-2021-44228"},
		"weakness_vulnerabilities": {"cweID": "CWE-79"},
		"product_vulnerabilities":  {"productName": "openssl"},
		"vendor_products":          {"vendorName": "apache"},
		"vulnerability_exploits":   {"cveID": "CVE-2021-44228"},
		"vulnerability_domains":    {"cveID": "CVE-2021-44228"},
		"fulltext_description":     {"query": "log4j"},
		"published_range":          {"from": "2021-12-01", "to": "2021-12-31"},
		"cvss_v3_version":          {"v3version": 3.1},
	},
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

// QueryParams returns the parameters for a query under a profile.
func QueryParams(p Profile, name string) (map[string]any, error) {
	m, ok := profileParams[p]
	if !ok {
		return nil, fmt.Errorf("unknown validation profile %q", p)
	}
	params, ok := m[name]
	if !ok {
		return nil, fmt.Errorf("no parameters for query %q", name)
	}
	return params, nil
}

// Table is an ordered query result: column names and rows of JSON values.
type Table struct {
	Columns []string `json:"columns"`
	Rows    [][]any  `json:"rows"`
}

// ExpectedTable is the content of a *.expected.json file.
type ExpectedTable struct {
	Profile string `json:"profile"`
	Derived bool   `json:"derived,omitempty"`
	Note    string `json:"note,omitempty"`
	Table
}

// LoadQueryExpected reads the expected table for a query. found is false when
// no file has been recorded for the profile.
func LoadQueryExpected(p Profile, name string) (e ExpectedTable, found bool, err error) {
	b, err := queriesFS.ReadFile("queries/" + string(p) + "/" + name + ".expected.json")
	if err != nil {
		if isNotExist(err) {
			return e, false, nil
		}
		return e, false, err
	}
	if err := json.Unmarshal(b, &e); err != nil {
		return e, false, fmt.Errorf("parse expected file for %s/%s: %w", p, name, err)
	}
	return e, true, nil
}

func isNotExist(err error) bool {
	return err != nil && (reflect.TypeOf(err) == reflect.TypeOf(&fs.PathError{}) || strings.Contains(err.Error(), "file does not exist"))
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

// QueryResult is the outcome of one representative query.
type QueryResult struct {
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Recorded bool   `json:"recorded"` // an expected file exists for the profile
	Derived  bool   `json:"derived,omitempty"`
	Message  string `json:"message,omitempty"`
	Diff     *Diff  `json:"diff,omitempty"`
}

// missingMessage is reported when no expected file is recorded. The
// design is silent on this case, so it counts as a failure with a clear
// instruction (the baseline files are recorded once on AWS).
func missingMessage(p Profile, name string) string {
	return fmt.Sprintf("no expected result recorded for profile %q, query %q; run the validator with --update-expected after reviewing a passing count check", p, name)
}

// EvaluateQuery compares an actual table with the recorded expected result.
// A query error is reported as a failed result by the caller via actualErr.
func EvaluateQuery(p Profile, name string, act Table, actualErr error) (QueryResult, error) {
	r := QueryResult{Name: name}
	exp, found, err := LoadQueryExpected(p, name)
	if err != nil {
		return r, err
	}
	r.Recorded = found
	r.Derived = exp.Derived
	switch {
	case actualErr != nil:
		r.Message = "query failed: " + actualErr.Error()
	case !found:
		r.Message = missingMessage(p, name)
	default:
		d := CompareTables(exp.Table, act)
		if d.Match {
			r.Passed = true
		} else {
			r.Message = d.Message
			r.Diff = &d
		}
	}
	return r, nil
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

// ExpectedFileName returns the repository path (relative to internal/validate)
// of an expected file, for --update-expected writers.
func ExpectedFileName(p Profile, name string) string {
	return "queries/" + string(p) + "/" + name + ".expected.json"
}

// EncodeExpected renders an expected file for a freshly observed table.
func EncodeExpected(p Profile, t Table) ([]byte, error) {
	n, err := Normalize(t)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(ExpectedTable{Profile: string(p), Table: n}, "", " ")
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
