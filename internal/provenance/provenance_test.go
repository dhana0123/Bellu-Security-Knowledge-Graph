package provenance

import (
	"strings"
	"testing"
	"time"
)

func TestPropsAndKey(t *testing.T) {
	at := time.Date(2024, 1, 2, 3, 4, 5, 678901234, time.UTC)
	p, err := Props(SourceVulKG, "RUN1", "abc", at)
	if err != nil {
		t.Fatal(err)
	}
	if p["p_vulkg_run"] != "RUN1" || p["p_vulkg_ref"] != "abc" {
		t.Fatalf("props %v", p)
	}
	if got := p["p_vulkg_at"].(time.Time); got.Nanosecond() != 678000000 {
		t.Fatalf("at not ms precision: %v", got)
	}
	if s := p["sources"].([]string); len(s) != 1 || s[0] != "vulkg" {
		t.Fatalf("sources %v", s)
	}
	if k, _ := Key("nvd", "removed"); k != "p_nvd_removed" {
		t.Fatal(k)
	}
}

func TestInvalidSource(t *testing.T) {
	for _, s := range []string{"", "Vulkg", "a-b", "1a", "x'y", strings.Repeat("a", 17)} {
		if _, err := Props(s, "r", "x", time.Now()); err == nil {
			t.Errorf("Props accepted %q", s)
		}
		if _, err := SetClause("n", s); err == nil {
			t.Errorf("SetClause accepted %q", s)
		}
		if _, err := Key(s, "run"); err == nil {
			t.Errorf("Key accepted %q", s)
		}
	}
}

func TestSetClause(t *testing.T) {
	c, err := SetClause("r", "vulkg")
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"r.sources", "r.p_vulkg_run = $runID", "r.p_vulkg_at = $at", "r.p_vulkg_ref = $ref"} {
		if !strings.Contains(c, w) {
			t.Errorf("missing %q in %s", w, c)
		}
	}
}
