package model_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
	"pgregory.net/rapid"
)

type tri [3]int

func (t tri) String() string { return fmt.Sprintf("%d.%d.%d", t[0], t[1], t[2]) }

func triCmp(a, b tri) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

var supportedSchemes = []string{"semver", "pep440", "maven", "go", "nuget", "generic"}

func genTri(t *rapid.T, label string) tri {
	return tri{
		rapid.IntRange(0, 5).Draw(t, label+"0"),
		rapid.IntRange(0, 5).Draw(t, label+"1"),
		rapid.IntRange(0, 5).Draw(t, label+"2"),
	}
}

// neighbours returns v, and the versions immediately below and above it.
func neighbours(v tri) []tri {
	out := []tri{v}
	up := v
	up[2]++
	out = append(out, up)
	if v[2] > 0 {
		dn := v
		dn[2]--
		out = append(out, dn)
	}
	return out
}

func genProbe(t *rapid.T, bounds ...tri) tri {
	pool := []tri{}
	for _, b := range bounds {
		pool = append(pool, neighbours(b)...)
	}
	if len(pool) > 0 && rapid.Bool().Draw(t, "useBoundary") {
		return rapid.SampledFrom(pool).Draw(t, "boundaryProbe")
	}
	return genTri(t, "probe")
}

// genOrdered draws two distinct versions lo < hi.
func genOrdered(t *rapid.T) (tri, tri) {
	a := genTri(t, "a")
	b := genTri(t, "b")
	for triCmp(a, b) == 0 {
		b[2]++
	}
	if triCmp(a, b) > 0 {
		a, b = b, a
	}
	return a, b
}

// Feature: bellu-security-knowledge-graph, Property 8: Range membership matches the reference predicate
// **Validates: Requirements 3.3, 3.4, 3.5, 3.6**
func TestProperty8RangeMembershipMatchesReference(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		scheme := rapid.SampledFrom(supportedSchemes).Draw(t, "scheme")
		intro, hi := genOrdered(t)
		probe := genProbe(t, intro, hi)
		v := probe.String()

		check := func(name string, a model.Affected, want bool) {
			got, err := a.MatchVersion(scheme, v)
			if err != nil {
				t.Fatalf("%s: unexpected error for %s: %v", name, v, err)
			}
			if (got == model.Match) != want || (got != model.Match && got != model.NoMatch) {
				t.Fatalf("%s: scheme=%s intro=%s hi=%s v=%s got=%v want match=%v", name, scheme, intro, hi, v, got, want)
			}
		}
		rng := func(evs ...model.Event) model.Affected {
			return model.Affected{Ranges: []model.Range{{Type: "SEMVER", Events: evs}}}
		}

		check("fixed", rng(model.Event{Introduced: intro.String()}, model.Event{Fixed: hi.String()}),
			triCmp(intro, probe) <= 0 && triCmp(probe, hi) < 0)
		check("last_affected", rng(model.Event{Introduced: intro.String()}, model.Event{LastAffected: hi.String()}),
			triCmp(intro, probe) <= 0 && triCmp(probe, hi) <= 0)
		check("open", rng(model.Event{Introduced: intro.String()}),
			triCmp(intro, probe) <= 0)
		check("explicit", model.Affected{Versions: []string{intro.String(), hi.String()}},
			triCmp(probe, intro) == 0 || triCmp(probe, hi) == 0)
		check("bound incl/excl", model.Affected{Bounds: []model.Bound{{StartIncl: intro.String(), EndExcl: hi.String()}}},
			triCmp(intro, probe) <= 0 && triCmp(probe, hi) < 0)
		check("bound excl/incl", model.Affected{Bounds: []model.Bound{{StartExcl: intro.String(), EndIncl: hi.String()}}},
			triCmp(intro, probe) < 0 && triCmp(probe, hi) <= 0)
	})
}

// Feature: bellu-security-knowledge-graph, Property 9: Unsupported scheme and invalid versions yield unknown
// **Validates: Requirements 3.2, 3.7, 12.6**
func TestProperty9UnsupportedAndInvalidYieldUnknown(t *testing.T) {
	supported := map[string]bool{}
	for _, s := range supportedSchemes {
		supported[s] = true
	}
	invalidVersion := rapid.OneOf(
		rapid.Just(""),
		rapid.Just(strings.Repeat("1", 257)),
		rapid.StringMatching(`[a-zA-Z!@#]{1,12}`), // no leading digits
	)

	rapid.Check(t, func(t *rapid.T) {
		lo, hi := genOrdered(t)
		a := model.Affected{Ranges: []model.Range{{Type: "SEMVER", Events: []model.Event{
			{Introduced: lo.String()}, {Fixed: hi.String()},
		}}}}

		// Unsupported scheme (including empty) with a valid version.
		bad := rapid.OneOf(rapid.Just(""), rapid.StringMatching(`[a-z]{1,10}`)).
			Filter(func(s string) bool { return !supported[s] }).Draw(t, "badScheme")
		got, err := a.MatchVersion(bad, lo.String())
		if got != model.Unknown || err == nil {
			t.Fatalf("scheme %q: got %v, %v; want Unknown with error", bad, got, err)
		}

		// Invalid probe version under a supported scheme.
		scheme := rapid.SampledFrom(supportedSchemes).Draw(t, "scheme")
		iv := invalidVersion.Draw(t, "invalidVersion")
		got, err = a.MatchVersion(scheme, iv)
		if got != model.Unknown || err == nil {
			t.Fatalf("version %.20q: got %v, %v; want Unknown with error", iv, got, err)
		}

		// A definitive match from another entry keeps the result Match,
		// even with an invalid listed version or an invalid-bound entry.
		probe := genProbe(t, lo, hi)
		mixed := model.Affected{
			Versions: []string{iv, probe.String()},
			Bounds:   []model.Bound{{StartIncl: iv}},
		}
		got, err = mixed.MatchVersion(scheme, probe.String())
		if got != model.Match || err != nil {
			t.Fatalf("mixed: got %v, %v; want Match", got, err)
		}
	})
}
