package model

import (
	"sort"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/version"
)

// MatchResult is the tri-state outcome of a version match.
type MatchResult int

const (
	NoMatch MatchResult = iota
	Match
	Unknown
)

func (m MatchResult) String() string {
	switch m {
	case Match:
		return "match"
	case Unknown:
		return "unknown"
	}
	return "no-match"
}

// Matches reports whether version v is affected under the generic scheme.
func (a Affected) Matches(v string) bool {
	m, _ := a.MatchVersion("generic", v)
	return m == Match
}

// MatchVersion evaluates v against every listed version, range and bound.
// A definite Match from any entry wins. An error in an entry yields Unknown
// only when nothing else matched; the first such error is returned with it.
func (a Affected) MatchVersion(scheme, v string) (MatchResult, error) {
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, x := range a.Versions {
		c, err := version.CompareScheme(scheme, x, v)
		if err != nil {
			note(err)
			continue
		}
		if c == 0 {
			return Match, nil
		}
	}
	for _, r := range a.Ranges {
		if r.Type == "GIT" {
			continue // commit ranges cannot be evaluated against a version string
		}
		ok, err := r.contains(scheme, v)
		if err != nil {
			note(err)
			continue
		}
		if ok {
			return Match, nil
		}
	}
	for _, b := range a.Bounds {
		ok, err := b.contains(scheme, v)
		if err != nil {
			note(err)
			continue
		}
		if ok {
			return Match, nil
		}
	}
	if firstErr != nil {
		return Unknown, firstErr
	}
	return NoMatch, nil
}

// cmper compares versions under a scheme and remembers the first error.
type cmper struct {
	scheme string
	err    error
}

func (c *cmper) cmp(a, b string) int {
	n, err := version.CompareScheme(c.scheme, a, b)
	if err != nil && c.err == nil {
		c.err = err
	}
	return n
}

func (b Bound) contains(scheme, v string) (bool, error) {
	c := &cmper{scheme: scheme}
	ok := true
	switch {
	case b.StartIncl != "" && c.cmp(v, b.StartIncl) < 0:
		ok = false
	case b.StartExcl != "" && c.cmp(v, b.StartExcl) <= 0:
		ok = false
	case b.EndIncl != "" && c.cmp(v, b.EndIncl) > 0:
		ok = false
	case b.EndExcl != "" && c.cmp(v, b.EndExcl) >= 0:
		ok = false
	}
	if c.err != nil {
		return false, c.err
	}
	return ok, nil
}

func eventVersion(e Event) string {
	switch {
	case e.Introduced != "":
		return e.Introduced
	case e.Fixed != "":
		return e.Fixed
	case e.LastAffected != "":
		return e.LastAffected
	}
	return e.Limit
}

// contains implements the OSV range evaluation algorithm.
func (r Range) contains(scheme, v string) (bool, error) {
	c := &cmper{scheme: scheme}
	evs := append([]Event(nil), r.Events...)
	sort.SliceStable(evs, func(i, j int) bool {
		vi, vj := eventVersion(evs[i]), eventVersion(evs[j])
		if vi == "0" || vj == "0" {
			return vi == "0" && vj != "0"
		}
		if n := c.cmp(vi, vj); n != 0 {
			return n < 0
		}
		return evs[i].Introduced != "" && evs[j].Introduced == ""
	})
	affected := false
	for _, e := range evs {
		switch {
		case e.Introduced != "":
			if e.Introduced == "0" || c.cmp(v, e.Introduced) >= 0 {
				affected = true
			}
		case e.Fixed != "":
			if c.cmp(v, e.Fixed) >= 0 {
				affected = false
			}
		case e.LastAffected != "":
			if c.cmp(v, e.LastAffected) > 0 {
				affected = false
			}
		}
	}
	if c.err != nil {
		return false, c.err
	}
	return affected, nil
}
