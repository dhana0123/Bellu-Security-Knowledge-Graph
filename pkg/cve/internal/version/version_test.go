package version

import (
	"errors"
	"strings"
	"testing"
)

func TestSchemeFor(t *testing.T) {
	for eco, want := range map[string]string{"npm": "semver", "crates.io": "semver", "PyPI": "pep440", "Maven": "maven", "Go": "go", "NuGet": "nuget", "Other": "", "": ""} {
		if got := SchemeFor(eco); got != want {
			t.Errorf("SchemeFor(%q)=%q want %q", eco, got, want)
		}
	}
}

func TestCompareScheme(t *testing.T) {
	for _, s := range []string{"semver", "pep440", "maven", "go", "nuget", "generic"} {
		if c, err := CompareScheme(s, "1.2.0", "1.10.0"); err != nil || c != -1 {
			t.Errorf("%s: got %d,%v", s, c, err)
		}
	}
	for _, s := range []string{"", "bogus"} {
		if _, err := CompareScheme(s, "1", "2"); !errors.Is(err, ErrUnsupportedScheme) {
			t.Errorf("scheme %q: err=%v", s, err)
		}
	}
	for _, v := range []string{"", "abc", strings.Repeat("1", MaxVersionLen+1)} {
		if _, err := CompareScheme("generic", v, "1"); !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("a=%q: err=%v", v, err)
		}
		if _, err := CompareScheme("generic", "1", v); !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("b=%q: err=%v", v, err)
		}
	}
	if _, err := CompareScheme("generic", strings.Repeat("1", MaxVersionLen), "1"); err != nil {
		t.Errorf("max length rejected: %v", err)
	}
}

func TestCompare(t *testing.T) {
	if Compare("1.0rc1", "1.0") != -1 || Compare("1.0.post1", "1.0") != 1 || Compare("v1.0", "1.0") != 0 {
		t.Error("unexpected ordering")
	}
}
