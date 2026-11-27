package version_test

import (
	"testing"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/testgen"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/version"
	"pgregory.net/rapid"
)

var supportedSchemes = []string{"semver", "pep440", "maven", "go", "nuget", "generic"}

// versionFor draws from testgen's scheme generators, mixed with free-form
// dotted/dashed tokens to stress the tokenizing comparator.
func versionFor(scheme string) *rapid.Generator[string] {
	gen := "semver"
	switch scheme {
	case "pep440", "maven":
		gen = scheme
	}
	free := rapid.StringMatching(`[0-9]{1,3}(\.[0-9a-z]{1,3}){0,3}([-+~][0-9a-zA-Z.]{1,4})?`)
	// Only versions the scheme accepts are generated, so a comparison error
	// is a real failure rather than something to skip.
	return rapid.OneOf(testgen.Version(gen), testgen.AnyVersion(), free).Filter(func(v string) bool {
		_, err := version.CompareScheme(scheme, v, v)
		return err == nil
	})
}

// Feature: bellu-security-knowledge-graph, Property 7: Version comparator is a strict weak order
// **Validates: Requirements 3.1, 3.8**
func TestProperty7ComparatorStrictWeakOrder(t *testing.T) {
	for _, scheme := range supportedSchemes {
		scheme := scheme
		t.Run(scheme, func(t *testing.T) {
			nonEqual := 0
			rapid.Check(t, func(t *rapid.T) {
				g := versionFor(scheme)
				a, b, c := g.Draw(t, "a"), g.Draw(t, "b"), g.Draw(t, "c")
				cmp := func(x, y string) int {
					r, err := version.CompareScheme(scheme, x, y)
					if err != nil {
						t.Fatalf("Compare(%q,%q) on scheme %s: %v", x, y, scheme, err)
					}
					if r != -1 && r != 0 && r != 1 {
						t.Fatalf("Compare(%q,%q)=%d, want -1/0/1", x, y, r)
					}
					return r
				}
				if cmp(a, a) != 0 {
					t.Fatalf("Compare(%q,%q) != 0", a, a)
				}
				ab, ba := cmp(a, b), cmp(b, a)
				if ab != 0 {
					nonEqual++
				}
				if ab != -ba {
					t.Fatalf("antisymmetry: Compare(%q,%q)=%d, reverse=%d", a, b, ab, ba)
				}
				bc, ac := cmp(b, c), cmp(a, c)
				if ab < 0 && bc < 0 && ac >= 0 {
					t.Fatalf("transitivity: %q<%q<%q but Compare(a,c)=%d", a, b, c, ac)
				}
				if ab == 0 && bc == 0 && ac != 0 {
					t.Fatalf("equivalence transitivity: %q==%q==%q but Compare(a,c)=%d", a, b, c, ac)
				}
				// Equivalent elements compare identically against any third element.
				if ab == 0 && cmp(a, c) != cmp(b, c) {
					t.Fatalf("equivalence substitutivity: %q~%q but differ against %q", a, b, c)
				}
			})
			if nonEqual == 0 {
				t.Fatalf("vacuous test: no non-equal comparisons generated for scheme %s", scheme)
			}
		})
	}
}
