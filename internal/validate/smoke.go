package validate

import (
	"fmt"
	"sort"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/checkpoint"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/model"
)

// SmokeResult is the outcome of the smoke check (Requirements 13.9, 13.10).
type SmokeResult struct {
	Passed bool   `json:"passed"`
	Mode   string `json:"buildMode"`
	// Limit is the sample limit N (sample mode only).
	Limit int `json:"sampleLimit,omitempty"`
	// Counts holds the count of every node label and relationship type of
	// the applied schema phase.
	Counts   map[string]int64 `json:"counts"`
	Failures []string         `json:"failures,omitempty"`
	Warnings []string         `json:"warnings,omitempty"`
}

// DecideSmoke is the pure smoke-check decision (Property 56).
//
// Sample mode passes iff 1 <= Vulnerability <= limit and Weakness and
// EXAMPLE_OF are each >= 1. Full mode passes iff Vulnerability, Weakness,
// EXAMPLE_OF, AFFECTS, Exploit, and EXPLOITS are each >= 1.
//
// Deviation from Requirement 13.9: in sample mode AFFECTS >= 1 is a warning,
// not a failure. A sample built with BSKG_SAMPLE_ORDER=latest holds recent
// CVEs that NVD has not analysed yet, so they legitimately have no CPE
// configurations and therefore no AFFECTS relationships. Full mode still
// requires AFFECTS.
//
// Any mode other than "sample" or "full" (build mode unset) fails.
func DecideSmoke(mode string, limit int, counts map[string]int64) SmokeResult {
	res := SmokeResult{Mode: mode, Counts: map[string]int64{}}
	for k, v := range counts {
		res.Counts[k] = v
	}
	need := func(name string) {
		if counts[name] < 1 {
			res.Failures = append(res.Failures, fmt.Sprintf("%s count is %d, want at least 1", name, counts[name]))
		}
	}
	switch mode {
	case checkpoint.ModeSample:
		res.Limit = limit
		v := counts["Vulnerability"]
		switch {
		case v < 1:
			res.Failures = append(res.Failures, fmt.Sprintf("Vulnerability count is %d, want at least 1", v))
		case v > int64(limit):
			res.Failures = append(res.Failures, fmt.Sprintf("Vulnerability count is %d, above the sample limit %d", v, limit))
		}
		need("Weakness")
		need("EXAMPLE_OF")
		if counts["AFFECTS"] < 1 {
			res.Warnings = append(res.Warnings, "AFFECTS count is 0 in sample mode; expected with BSKG_SAMPLE_ORDER=latest (recent CVEs have no CPE data yet)")
		}
	case checkpoint.ModeFull:
		for _, n := range []string{"Vulnerability", "Weakness", "EXAMPLE_OF", "AFFECTS", "Exploit", "EXPLOITS"} {
			need(n)
		}
	default:
		res.Failures = append(res.Failures, fmt.Sprintf("build mode is %q, want sample or full", mode))
	}
	res.Passed = len(res.Failures) == 0
	return res
}

// SmokeCountNames returns the node label and relationship type names counted
// for the given schema phase, sorted: domain labels and relationship types
// from internal/model.
func SmokeCountNames(phase int) []string {
	out := model.DomainLabels(phase)
	for _, r := range model.Rels {
		if r.Phase <= phase {
			out = append(out, r.Name)
		}
	}
	sort.Strings(out)
	return out
}
