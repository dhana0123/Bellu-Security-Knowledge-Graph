package validate

import "sort"

// ExploitDataExample is one Exploit node with offending properties.
type ExploitDataExample struct {
	EID   string   `json:"eid"`
	Props []string `json:"props"` // property names (long values are marked "(>256 chars)")
}

// ExploitDataCheck reports Exploit nodes that carry properties beyond eid,
// model.ExploitProps, and provenance properties, or values over 256
// characters (Requirement 13.5: no exploit code is stored).
type ExploitDataCheck struct {
	Passed   bool                 `json:"passed"`
	Count    int64                `json:"count"`
	Examples []ExploitDataExample `json:"examples,omitempty"` // at most MaxExamples
}

// NewExploitDataCheck builds the result, capping examples at MaxExamples.
func NewExploitDataCheck(count int64, ex []ExploitDataExample) ExploitDataCheck {
	if len(ex) > MaxExamples {
		ex = ex[:MaxExamples]
	}
	return ExploitDataCheck{Passed: count == 0, Count: count, Examples: ex}
}

// ExploitabilityCheck reports Vulnerabilities whose exploitability or
// exploitDate differ from what the active (not removed) EXPLOITS
// relationships imply (Requirement 13.6).
type ExploitabilityCheck struct {
	Passed bool  `json:"passed"`
	Count  int64 `json:"count"`
	// WithExploits counts mismatches among Vulnerabilities that have an
	// active EXPLOITS relationship; WithoutExploits counts those that have
	// none but carry exploitability other than 0 or a non-empty exploitDate.
	WithExploits    int64    `json:"withExploits"`
	WithoutExploits int64    `json:"withoutExploits"`
	Examples        []string `json:"examples,omitempty"` // cveIDs, at most MaxExamples
}

// NewExploitabilityCheck merges the two partial results. Examples are
// sorted, de-duplicated, and capped at MaxExamples.
func NewExploitabilityCheck(withExploits, withoutExploits int64, exA, exB []string) ExploitabilityCheck {
	seen := map[string]bool{}
	var ex []string
	for _, s := range append(append([]string(nil), exA...), exB...) {
		if !seen[s] {
			seen[s] = true
			ex = append(ex, s)
		}
	}
	sort.Strings(ex)
	if len(ex) > MaxExamples {
		ex = ex[:MaxExamples]
	}
	n := withExploits + withoutExploits
	return ExploitabilityCheck{Passed: n == 0, Count: n, WithExploits: withExploits, WithoutExploits: withoutExploits, Examples: ex}
}

// UnsetPropsCheck reports Vulnerabilities with gainedAccess or
// vulnerabilityType set; no source supplies them (Requirement 13.8).
type UnsetPropsCheck struct {
	Passed            bool     `json:"passed"`
	Count             int64    `json:"count"`
	GainedAccess      int64    `json:"gainedAccess"`
	VulnerabilityType int64    `json:"vulnerabilityType"`
	Examples          []string `json:"examples,omitempty"` // cveIDs, at most MaxExamples
}

// NewUnsetPropsCheck builds the result. count is the number of Vulnerabilities
// with at least one of the two properties.
func NewUnsetPropsCheck(count, gained, vtype int64, ex []string) UnsetPropsCheck {
	if len(ex) > MaxExamples {
		ex = ex[:MaxExamples]
	}
	return UnsetPropsCheck{Passed: count == 0, Count: count, GainedAccess: gained, VulnerabilityType: vtype, Examples: ex}
}
