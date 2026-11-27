package model_test

import (
	"strings"
	"testing"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

func rangeOf(evs ...model.Event) model.Affected {
	return model.Affected{Ranges: []model.Range{{Type: "ECOSYSTEM", Events: evs}}}
}

// Validates: Requirement 23.1 (version-boundary table tests).
func TestMatchVersionBoundaries(t *testing.T) {
	fixed := rangeOf(model.Event{Introduced: "1.2.0"}, model.Event{Fixed: "1.5.0"})
	last := rangeOf(model.Event{Introduced: "1.2.0"}, model.Event{LastAffected: "1.5.0"})
	open := rangeOf(model.Event{Introduced: "1.2.0"})
	zero := rangeOf(model.Event{Introduced: "0"}, model.Event{Fixed: "1.5.0"})
	multi := model.Affected{Ranges: []model.Range{{Type: "SEMVER", Events: []model.Event{
		{Introduced: "1.0.0"}, {Fixed: "1.1.0"}, {Introduced: "2.0.0"}, {Fixed: "2.1.0"},
	}}}}
	unordered := rangeOf(model.Event{Fixed: "1.5.0"}, model.Event{Introduced: "1.2.0"})
	bound := model.Affected{Bounds: []model.Bound{{StartIncl: "1.2.0", EndExcl: "1.5.0"}}}
	boundEx := model.Affected{Bounds: []model.Bound{{StartExcl: "1.2.0", EndIncl: "1.5.0"}}}
	explicit := model.Affected{Versions: []string{"1.2.0", "1.5.0"}}
	git := model.Affected{Ranges: []model.Range{{Type: "GIT", Events: []model.Event{{Introduced: "0"}}}}}

	cases := []struct {
		name string
		a    model.Affected
		v    string
		want model.MatchResult
	}{
		// exclusive upper (fixed)
		{"fixed/below lower", fixed, "1.1.9", model.NoMatch},
		{"fixed/at lower", fixed, "1.2.0", model.Match},
		{"fixed/above lower", fixed, "1.2.1", model.Match},
		{"fixed/below upper", fixed, "1.4.9", model.Match},
		{"fixed/at upper", fixed, "1.5.0", model.NoMatch},
		{"fixed/above upper", fixed, "1.5.1", model.NoMatch},
		// inclusive upper (last_affected)
		{"last/below lower", last, "1.1.9", model.NoMatch},
		{"last/at lower", last, "1.2.0", model.Match},
		{"last/below upper", last, "1.4.9", model.Match},
		{"last/at upper", last, "1.5.0", model.Match},
		{"last/above upper", last, "1.5.1", model.NoMatch},
		// open-ended
		{"open/below", open, "1.1.9", model.NoMatch},
		{"open/at", open, "1.2.0", model.Match},
		{"open/far above", open, "99.0.0", model.Match},
		// introduced 0
		{"zero/low", zero, "0.0.1", model.Match},
		{"zero/at fixed", zero, "1.5.0", model.NoMatch},
		// multiple intervals, and unsorted events
		{"multi/gap", multi, "1.1.0", model.NoMatch},
		{"multi/second", multi, "2.0.5", model.Match},
		{"multi/after", multi, "2.1.0", model.NoMatch},
		{"unordered/inside", unordered, "1.3.0", model.Match},
		{"unordered/at fixed", unordered, "1.5.0", model.NoMatch},
		// bounds
		{"bound/at start incl", bound, "1.2.0", model.Match},
		{"bound/at end excl", bound, "1.5.0", model.NoMatch},
		{"boundEx/at start excl", boundEx, "1.2.0", model.NoMatch},
		{"boundEx/above start excl", boundEx, "1.2.1", model.Match},
		{"boundEx/at end incl", boundEx, "1.5.0", model.Match},
		{"boundEx/above end incl", boundEx, "1.5.1", model.NoMatch},
		// explicit versions
		{"explicit/hit", explicit, "1.5.0", model.Match},
		{"explicit/miss", explicit, "1.5.1", model.NoMatch},
		// GIT ranges are ignored
		{"git/ignored", git, "1.0.0", model.NoMatch},
		// pre-release ordering
		{"pre/rc below fixed", fixed, "1.5.0-rc1", model.Match},
		{"pre/rc of lower bound", fixed, "1.2.0-rc1", model.NoMatch},
		{"pre/alpha<beta<rc", rangeOf(model.Event{Introduced: "1.0.0-beta"}, model.Event{Fixed: "1.0.0-rc1"}), "1.0.0-beta2", model.Match},
		{"pre/alpha below beta", rangeOf(model.Event{Introduced: "1.0.0-beta"}, model.Event{Fixed: "1.0.0-rc1"}), "1.0.0-alpha", model.NoMatch},
		{"pre/release at fixed pre", rangeOf(model.Event{Introduced: "1.0.0-beta"}, model.Event{Fixed: "1.0.0-rc1"}), "1.0.0", model.NoMatch},
		{"pre/last_affected pre", rangeOf(model.Event{Introduced: "0"}, model.Event{LastAffected: "1.0.0-rc1"}), "1.0.0-rc1", model.Match},
		// qualifiers
		{"qual/v prefix", fixed, "v1.3.0", model.Match},
		{"qual/build metadata ignored", fixed, "1.5.0+build5", model.NoMatch},
		{"qual/trailing zeros equal", fixed, "1.5", model.NoMatch},
		{"qual/final equals release", fixed, "1.5.0.Final", model.NoMatch},
		{"qual/post is above", fixed, "1.2.0.post1", model.Match},
		{"qual/post above last_affected", last, "1.5.0.post1", model.NoMatch},
		// numeric, not lexical, comparison
		{"num/10 above 9", rangeOf(model.Event{Introduced: "1.9.0"}, model.Event{Fixed: "1.10.0"}), "1.9.5", model.Match},
		{"num/10 at fixed", rangeOf(model.Event{Introduced: "1.9.0"}, model.Event{Fixed: "1.10.0"}), "1.10.0", model.NoMatch},
		// epoch-style versions: parseable, never an error
		// epochs are approximated (documented in package version): the epoch
		// prefix is treated as a pre-release tail, so the probe sorts below 1.2.0.
		{"epoch/parseable, no error", open, "1:1.3.0", model.NoMatch},
		{"epoch/same epoch bounds compare", rangeOf(model.Event{Introduced: "1:1.0"}, model.Event{Fixed: "1:2.0"}), "1:1.5", model.Match},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.a.MatchVersion("generic", c.v)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Fatalf("MatchVersion(%q) = %v, want %v", c.v, got, c.want)
			}
		})
	}
}

func TestMatchVersionUnknownCases(t *testing.T) {
	r := rangeOf(model.Event{Introduced: "1.0.0"}, model.Event{Fixed: "2.0.0"})
	long := make([]byte, 257)
	for i := range long {
		long[i] = '1'
	}
	for _, c := range []struct{ name, scheme, v string }{
		{"empty scheme", "", "1.5.0"},
		{"unknown scheme", "rpm", "1.5.0"},
		{"empty version", "semver", ""},
		{"too long", "semver", string(long)},
		{"unparseable", "semver", "latest"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := r.MatchVersion(c.scheme, c.v)
			if got != model.Unknown || err == nil {
				t.Fatalf("got %v, %v; want Unknown with error", got, err)
			}
		})
	}
	// 256 characters is still valid.
	ok := "1" + strings.Repeat(".0", 127) + "0" // exactly 256 chars, equals 1
	if got, err := r.MatchVersion("semver", ok); err != nil || got != model.Match {
		t.Fatalf("256-char version: got %v, %v", got, err)
	}
	// A definite match elsewhere wins over an invalid entry.
	mixed := model.Affected{Versions: []string{"bad!", "1.5.0"}}
	if got, err := mixed.MatchVersion("semver", "1.5.0"); got != model.Match || err != nil {
		t.Fatalf("mixed: got %v, %v", got, err)
	}
}
