// Package version provides a tolerant, ecosystem-agnostic version comparator.
//
// It handles semver, Go pseudo-versions, PyPI-style (1.0rc1, 1.0.post1) and
// most Maven/npm forms. It is NOT a full implementation of every ecosystem's
// ordering rules (e.g. Debian epochs, RPM tilde); those are approximated.
package version

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	ErrUnsupportedScheme = errors.New("unsupported version scheme")
	ErrInvalidVersion    = errors.New("invalid version")
)

// MaxVersionLen is the longest version string CompareScheme accepts.
const MaxVersionLen = 256

var leading = regexp.MustCompile(`^\d+(\.\d+)*`)

type parsed struct {
	rel  []string
	kind int // -1 pre-release, 0 none, 1 post-release
	tail []string
}

func parse(s string) parsed {
	s = strings.TrimSpace(s)
	if len(s) > 1 && (s[0] == 'v' || s[0] == 'V') && s[1] >= '0' && s[1] <= '9' {
		s = s[1:]
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var p parsed
	m := leading.FindString(s)
	p.rel = strings.Split(m, ".")
	if m == "" {
		p.rel = nil
	}
	rest := strings.TrimLeft(s[len(m):], "-._~")
	if rest == "" {
		return p
	}
	p.tail = tokens(rest)
	if len(p.tail) == 0 {
		return p // only punctuation, e.g. "!"
	}
	first := strings.ToLower(p.tail[0])
	switch first {
	case "final", "ga", "release":
		p.tail = nil
	case "post", "sp", "patch":
		p.kind = 1
	default:
		p.kind = -1
	}
	return p
}

func tokens(s string) []string {
	var out []string
	cur := []byte{}
	var curDigit bool
	flush := func() {
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = cur[:0]
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isD := c >= '0' && c <= '9'
		isA := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !isD && !isA {
			flush()
			continue
		}
		if len(cur) > 0 && isD != curDigit {
			flush()
		}
		curDigit = isD
		cur = append(cur, c)
	}
	flush()
	return out
}

func cmpNum(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func isNum(s string) bool { return s != "" && s[0] >= '0' && s[0] <= '9' }

var rank = map[string]int{"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "pre": 3, "preview": 3, "c": 3, "rc": 3, "snapshot": 3}

func cmpTok(a, b string) int {
	an, bn := isNum(a), isNum(b)
	switch {
	case an && bn:
		return cmpNum(a, b)
	case an:
		return -1
	case bn:
		return 1
	}
	a, b = strings.ToLower(a), strings.ToLower(b)
	ra, oka := rank[a]
	rb, okb := rank[b]
	if !oka {
		ra = 10
	}
	if !okb {
		rb = 10
	}
	if ra != rb {
		if ra < rb {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// SchemeFor maps an ecosystem name to a version scheme, or "" if unknown.
func SchemeFor(ecosystem string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm", "crates.io":
		return "semver"
	case "pypi":
		return "pep440"
	case "maven":
		return "maven"
	case "go":
		return "go"
	case "nuget":
		return "nuget"
	}
	return ""
}

func validate(v string) error {
	if v == "" || len(v) > MaxVersionLen {
		return fmt.Errorf("%w: %q", ErrInvalidVersion, v)
	}
	if parse(v).rel == nil {
		return fmt.Errorf("%w: %q", ErrInvalidVersion, v)
	}
	return nil
}

// CompareScheme compares a and b under scheme and returns -1, 0 or 1.
// All schemes currently share the generic tokenizing comparator.
func CompareScheme(scheme, a, b string) (int, error) {
	switch scheme {
	case "semver", "pep440", "maven", "go", "nuget", "generic":
	default:
		return 0, fmt.Errorf("%w: %q", ErrUnsupportedScheme, scheme)
	}
	if err := validate(a); err != nil {
		return 0, err
	}
	if err := validate(b); err != nil {
		return 0, err
	}
	return compare(a, b), nil
}

// Compare returns -1, 0 or 1. It is tolerant: it never fails, and equals
// CompareScheme("generic") for valid versions.
func Compare(a, b string) int { return compare(a, b) }

func compare(a, b string) int {
	pa, pb := parse(a), parse(b)
	n := max(len(pa.rel), len(pb.rel))
	for i := 0; i < n; i++ {
		x, y := "0", "0"
		if i < len(pa.rel) {
			x = pa.rel[i]
		}
		if i < len(pb.rel) {
			y = pb.rel[i]
		}
		if c := cmpNum(x, y); c != 0 {
			return c
		}
	}
	if pa.kind != pb.kind {
		if pa.kind < pb.kind {
			return -1
		}
		return 1
	}
	m := min(len(pa.tail), len(pb.tail))
	for i := 0; i < m; i++ {
		if c := cmpTok(pa.tail[i], pb.tail[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(pa.tail) == len(pb.tail):
		return 0
	case len(pa.tail) < len(pb.tail):
		return -1
	default:
		return 1
	}
}
