package validate

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
)

//go:embed data/*.json
var dataFS embed.FS

// Profile selects which expected-counts file is used.
type Profile string

const (
	// ProfileBaseline compares against VulKG Table IV.
	ProfileBaseline Profile = "baseline"
	// ProfileFixture compares against the testdata/baseline fixture counts.
	ProfileFixture Profile = "fixture"
)

var expectedFiles = map[Profile]string{
	ProfileBaseline: "data/expected_counts.json",
	ProfileFixture:  "data/expected_counts_fixture.json",
}

// Expected holds expected counts per metric.
type Expected struct {
	Profile string           `json:"profile"`
	Source  string           `json:"source"`
	Metrics map[string]int64 `json:"metrics"`
}

// Discrepancy is a known, documented deviation. Count discrepancies list the
// observed values that are accepted for the metric.
type Discrepancy struct {
	ID       string  `json:"id"`
	Metric   string  `json:"metric"`
	Kind     string  `json:"kind"` // "count" or "property"
	Observed []int64 `json:"observed"`
	Note     string  `json:"note"`
}

// Result is the outcome for one metric.
type Result struct {
	Metric        string `json:"metric"`
	Expected      int64  `json:"expected"`
	Actual        *int64 `json:"actual"`
	Passed        bool   `json:"passed"`
	DiscrepancyID string `json:"discrepancyId,omitempty"`
	Message       string `json:"message,omitempty"`
}

// LoadExpected returns the embedded expected counts for a profile.
func LoadExpected(p Profile) (Expected, error) {
	name, ok := expectedFiles[p]
	if !ok {
		return Expected{}, fmt.Errorf("unknown validation profile %q", p)
	}
	b, err := dataFS.ReadFile(name)
	if err != nil {
		return Expected{}, err
	}
	var e Expected
	if err := json.Unmarshal(b, &e); err != nil {
		return Expected{}, fmt.Errorf("parse %s: %w", name, err)
	}
	return e, nil
}

// LoadDiscrepancies returns the embedded Known_Discrepancy entries.
func LoadDiscrepancies() ([]Discrepancy, error) {
	b, err := dataFS.ReadFile("data/known_discrepancies.json")
	if err != nil {
		return nil, err
	}
	var d []Discrepancy
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("parse known_discrepancies.json: %w", err)
	}
	return d, nil
}

// CompareCounts is pure. A metric fails when its actual value is missing, or
// differs from the expected value and equals no observed value of a count
// discrepancy for that metric. Results are sorted by metric name.
func CompareCounts(exp Expected, disc []Discrepancy, actual map[string]int64) []Result {
	out := make([]Result, 0, len(exp.Metrics))
	for m, want := range exp.Metrics {
		r := Result{Metric: m, Expected: want}
		got, ok := actual[m]
		if !ok {
			r.Message = "no actual count supplied"
			out = append(out, r)
			continue
		}
		r.Actual = &got
		switch {
		case got == want:
			r.Passed = true
		default:
			if id, hit := matchDiscrepancy(disc, m, got); hit {
				r.Passed = true
				r.DiscrepancyID = id
				r.Message = "matches known discrepancy"
			} else {
				r.Message = fmt.Sprintf("expected %d, actual %d", want, got)
			}
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Metric < out[j].Metric })
	return out
}

func matchDiscrepancy(disc []Discrepancy, metric string, v int64) (string, bool) {
	for _, d := range disc {
		if d.Metric != metric || d.Kind != "count" {
			continue
		}
		for _, o := range d.Observed {
			if o == v {
				return d.ID, true
			}
		}
	}
	return "", false
}

// AllPassed reports whether every result passed.
func AllPassed(rs []Result) bool {
	for _, r := range rs {
		if !r.Passed {
			return false
		}
	}
	return true
}
