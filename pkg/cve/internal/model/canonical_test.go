package model

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMatchVersionTriState(t *testing.T) {
	a := Affected{Versions: []string{"bad!!", "1.0"}, Bounds: []Bound{{StartIncl: "2.0", EndExcl: "3.0"}}}
	if m, err := a.MatchVersion("generic", "1.0"); m != Match || err != nil {
		t.Fatalf("got %v %v", m, err)
	}
	if m, err := a.MatchVersion("generic", "2.5"); m != Match || err != nil {
		t.Fatalf("got %v %v", m, err)
	}
	if m, err := a.MatchVersion("generic", "9.0"); m != Unknown || err == nil {
		t.Fatalf("want Unknown, got %v %v", m, err)
	}
	if m, _ := (Affected{Versions: []string{"1.0"}}).MatchVersion("generic", "2.0"); m != NoMatch {
		t.Fatal("want NoMatch")
	}
	if m, err := a.MatchVersion("nope", "1.0"); m != Unknown || err == nil {
		t.Fatalf("unsupported scheme: %v %v", m, err)
	}
	if a.Matches("9.0") || !a.Matches("1.0") {
		t.Fatal("Matches wrapper")
	}
}

func TestMatchVersionRangeAndGit(t *testing.T) {
	a := Affected{Ranges: []Range{
		{Type: "GIT", Events: []Event{{Introduced: "0"}}},
		{Type: "SEMVER", Events: []Event{{Introduced: "1.0.0"}, {Fixed: "1.2.0"}}},
	}}
	for v, want := range map[string]MatchResult{"1.1.0": Match, "1.2.0": NoMatch, "0.5.0": NoMatch} {
		if m, err := a.MatchVersion("semver", v); m != want || err != nil {
			t.Errorf("%s: %v %v", v, m, err)
		}
	}
	if m, err := a.MatchVersion("semver", ""); m != Unknown || err == nil {
		t.Errorf("empty version: %v %v", m, err)
	}
}

func TestKEVAndDerived(t *testing.T) {
	for in, want := range map[string]string{"Known": "known", " known ": "known", "Unknown": "unknown", "": "unknown", "x": "unknown"} {
		if got := NormalizeRansomware(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
	r := Record{Source: "osv", References: []Reference{{"FIX", "http://a"}, {"FIX", "http://a"}, {"EXPLOIT", "http://e"}, {"WEB", "http://w"}},
		Fixes: []Fix{{"https://g/r/", "abc"}, {"", "x"}}}
	p := r.Patches()
	if len(p) != 2 || p[1].URL != "https://g/r/commit/abc" || p[0].Source != "osv" {
		t.Fatalf("%+v", p)
	}
	if e := r.Exploits(); len(e) != 1 || e[0].URL != "http://e" {
		t.Fatalf("%+v", e)
	}
}

func TestMarshalRoundTripNullTimes(t *testing.T) {
	r := Record{Source: "s", ID: "CVE-2024-0001", Published: time.Date(2024, 1, 2, 3, 4, 5, 123456789, time.FixedZone("x", 3600))}
	r.Normalize()
	if r.Published.Nanosecond() != 123000000 || r.Published.Location() != time.UTC {
		t.Fatalf("normalize: %v", r.Published)
	}
	b, err := Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"modified":null`) || !strings.Contains(string(b), `"withdrawn":null`) {
		t.Fatalf("%s", b)
	}
	var got Record
	if err := Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Published.Equal(r.Published) || !got.Modified.IsZero() || !got.Withdrawn.IsZero() {
		t.Fatalf("%+v", got)
	}
	got.Published = r.Published
	if !reflect.DeepEqual(got, r) {
		t.Fatalf("%+v vs %+v", got, r)
	}
}
