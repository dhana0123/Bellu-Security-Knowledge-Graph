package normalize_test

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/normalize"
	"pgregory.net/rapid"
)

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func ws() *rapid.Generator[string] {
	return rapid.StringOfN(rapid.SampledFrom([]rune(" \t\n")), 0, 3, -1)
}

func caseMix(t *rapid.T, s string) string {
	var b strings.Builder
	for _, r := range s {
		if rapid.Bool().Draw(t, "upper") {
			b.WriteString(strings.ToUpper(string(r)))
		} else {
			b.WriteString(strings.ToLower(string(r)))
		}
	}
	return b.String()
}

// Feature: bellu-security-knowledge-graph, Property 5: Canonicalization of identifiers, ecosystems and package names
// **Validates: Requirements 2.5, 2.6, 2.7, 2.8, 2.9**
func TestProperty5CanonicalCVEValid(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		year := rapid.StringMatching(`[0-9]{4}`).Draw(t, "year")
		seq := rapid.StringMatching(`[0-9]{4,12}`).Draw(t, "seq")
		want := "CVE-" + year + "-" + seq
		in := ws().Draw(t, "pre") + caseMix(t, want) + ws().Draw(t, "post")
		got, err := normalize.CanonicalCVE(in)
		if err != nil || got != want {
			t.Fatalf("CanonicalCVE(%q) = %q, %v; want %q", in, got, err, want)
		}
		again, err := normalize.CanonicalCVE(got)
		if err != nil || again != got {
			t.Fatalf("not idempotent: %q -> %q, %v", got, again, err)
		}
	})
}

// **Validates: Requirements 2.5, 2.6**
func TestProperty5CanonicalCVEAcceptsExactlyPattern(t *testing.T) {
	gen := rapid.OneOf(
		rapid.String(),
		rapid.StringMatching(`\s{0,2}[cC][vV][eE]-[0-9]{0,5}-[0-9]{0,6}\s{0,2}`),
		rapid.StringMatching(`CVE-[0-9]{4}-[0-9]{1,3}`),
		rapid.StringMatching(`[a-z]{1,3}-[0-9]{4}-[0-9]{4,6}`),
	)
	rapid.Check(t, func(t *rapid.T) {
		in := gen.Draw(t, "in")
		got, err := normalize.CanonicalCVE(in)
		want := strings.ToUpper(strings.TrimSpace(in))
		if cvePattern.MatchString(want) {
			if err != nil || got != want {
				t.Fatalf("CanonicalCVE(%q) = %q, %v; want %q", in, got, err, want)
			}
			return
		}
		var rej normalize.Rejection
		if !errors.As(err, &rej) || rej.Field == "" || got != "" {
			t.Fatalf("CanonicalCVE(%q) = %q, %v; want Rejection naming field", in, got, err)
		}
	})
}

// **Validates: Requirements 2.7, 2.8**
func TestProperty5CanonicalEcosystem(t *testing.T) {
	vocab := []string{"npm", "PyPI", "Maven", "Go", "crates.io", "NuGet"}
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.SampledFrom(vocab).Draw(t, "vocab")
		got, mapped := normalize.CanonicalEcosystem(caseMix(t, v))
		if !mapped || got != v {
			t.Fatalf("got %q,%v want %q,true", got, mapped, v)
		}
	})
	rapid.Check(t, func(t *rapid.T) {
		s := rapid.String().Draw(t, "name")
		got, mapped := normalize.CanonicalEcosystem(s)
		inVocab := false
		for _, v := range vocab {
			if strings.EqualFold(strings.TrimSpace(s), v) {
				inVocab = true
			}
		}
		if mapped != inVocab {
			t.Fatalf("%q: mapped=%v want %v", s, mapped, inVocab)
		}
		if !mapped && got != strings.TrimSpace(s) {
			t.Fatalf("unmapped %q not preserved: %q", s, got)
		}
		// result is a fixed point
		g2, m2 := normalize.CanonicalEcosystem(got)
		if g2 != got || m2 != mapped {
			t.Fatalf("not idempotent: %q", s)
		}
	})
}

// **Validates: Requirements 2.9**
func TestProperty5CanonicalPackage(t *testing.T) {
	ecos := []string{"npm", "PyPI", "Maven", "Go", "crates.io", "NuGet", "Debian:11", ""}
	rapid.Check(t, func(t *rapid.T) {
		eco := rapid.SampledFrom(ecos).Draw(t, "eco")
		name := rapid.String().Draw(t, "name")
		once := normalize.CanonicalPackage(eco, name)
		if twice := normalize.CanonicalPackage(eco, once); twice != once {
			t.Fatalf("not idempotent (%q,%q): %q -> %q", eco, name, once, twice)
		}
	})
}

// **Validates: Requirements 2.9**
func TestProperty5PyPISeparatorsAndCase(t *testing.T) {
	seg := rapid.StringMatching(`[a-zA-Z0-9]{1,6}`)
	sep := rapid.StringMatching(`[-_.]{1,3}`)
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 4).Draw(t, "n")
		segs := make([]string, n)
		for i := range segs {
			segs[i] = seg.Draw(t, "seg")
		}
		build := func() string {
			var b strings.Builder
			for i, s := range segs {
				if i > 0 {
					b.WriteString(sep.Draw(t, "sep"))
				}
				b.WriteString(caseMix(t, s))
			}
			return b.String()
		}
		a, b := build(), build()
		ca, cb := normalize.CanonicalPackage("PyPI", a), normalize.CanonicalPackage("pypi", b)
		if ca != cb {
			t.Fatalf("%q -> %q but %q -> %q", a, ca, b, cb)
		}
	})
}
