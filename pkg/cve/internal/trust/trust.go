// Package trust holds provenance validation, trust-state classification and the
// confidence rules for facts (requirements 7.1-7.10).
package trust

import (
	"errors"
	"sort"
	"time"
)

type TrustState string

const (
	Verified     TrustState = "verified"
	Corroborated TrustState = "corroborated"
	Predicted    TrustState = "predicted"
)

type Direction string

const (
	Direct   Direction = "direct"
	Inferred Direction = "inferred"
)

// Rule ids stored with confidence values.
const (
	RuleSingleAuthoritative = "single-authoritative"
	RuleMultiSource         = "multi-source"
	RuleInferredNoRule      = "inferred-no-rule"
)

var (
	ErrMissingSource     = errors.New("trust: provenance source id is missing")
	ErrMissingDirection  = errors.New("trust: provenance direction is missing or invalid (want direct or inferred)")
	ErrInvalidConfidence = errors.New("trust: provenance confidence outside [0,1]")
)

type Provenance struct {
	Source      string
	PublishTime *time.Time // nil => unknown
	IngestTime  time.Time
	Direction   Direction
	Confidence  *float64 // [0,1] or nil
	RuleID      string
}

type Evidence struct {
	Source      string
	DerivedFrom string
	Direct      bool
	IngestedAt  time.Time
}

// Fact is the part of a stored fact that promotion depends on.
type Fact struct {
	State       TrustState
	PredictedAt time.Time // when the fact became predicted
}

// Validate checks the provenance record.
func Validate(p Provenance) error {
	if p.Source == "" {
		return ErrMissingSource
	}
	if p.Direction != Direct && p.Direction != Inferred {
		return ErrMissingDirection
	}
	if p.Confidence != nil && (*p.Confidence < 0 || *p.Confidence > 1 || *p.Confidence != *p.Confidence) {
		return ErrInvalidConfidence
	}
	return nil
}

// Independent reports whether two evidence items come from distinct sources and
// neither is derived from the other.
func Independent(a, b Evidence) bool {
	if a.Source == b.Source {
		return false
	}
	if a.DerivedFrom != "" && a.DerivedFrom == b.Source {
		return false
	}
	if b.DerivedFrom != "" && b.DerivedFrom == a.Source {
		return false
	}
	return true
}

// independentDirect returns the number of mutually independent direct sources,
// chosen greedily in sorted source order so the result is order-independent.
func independentDirect(ev []Evidence) int {
	var direct []Evidence
	for _, e := range ev {
		if e.Direct {
			direct = append(direct, e)
		}
	}
	sort.SliceStable(direct, func(i, j int) bool {
		if direct[i].Source != direct[j].Source {
			return direct[i].Source < direct[j].Source
		}
		return direct[i].DerivedFrom < direct[j].DerivedFrom
	})
	// Drop exact duplicates, then find the largest mutually independent subset.
	uniq := direct[:0]
	for i, e := range direct {
		if i == 0 || e.Source != direct[i-1].Source || e.DerivedFrom != direct[i-1].DerivedFrom {
			uniq = append(uniq, e)
		}
	}
	return maxIndependent(uniq, nil)
}

// maxIndependent returns the size of the largest mutually independent subset of
// cand that is compatible with picked (exhaustive; evidence lists are small).
func maxIndependent(cand, picked []Evidence) int {
	best := len(picked)
	for i, e := range cand {
		ok := true
		for _, p := range picked {
			if !Independent(p, e) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if n := maxIndependent(cand[i+1:], append(picked[:len(picked):len(picked)], e)); n > best {
			best = n
		}
	}
	return best
}

// Classify: no direct evidence is predicted, one independent source verified,
// two or more corroborated.
func Classify(ev []Evidence) TrustState {
	switch n := independentDirect(ev); {
	case n == 0:
		return Predicted
	case n == 1:
		return Verified
	default:
		return Corroborated
	}
}

// Confidence applies the evidence rules. When no rule applies it returns a nil
// confidence, rule id inferred-no-rule and ok=false.
func Confidence(ev []Evidence) (c *float64, ruleID string, ok bool) {
	n := independentDirect(ev)
	if n == 0 {
		return nil, RuleInferredNoRule, false
	}
	v := 0.80
	rule := RuleSingleAuthoritative
	if n > 1 {
		v = 0.80 + 0.05*float64(n-1)
		if v > 0.95 {
			v = 0.95
		}
		rule = RuleMultiSource
	}
	return &v, rule, true
}

// CanPromote is true only if some new evidence is direct and was ingested after
// the fact became predicted.
func CanPromote(f Fact, newEvidence []Evidence) bool {
	for _, e := range newEvidence {
		if e.Direct && e.IngestedAt.After(f.PredictedAt) {
			return true
		}
	}
	return false
}
