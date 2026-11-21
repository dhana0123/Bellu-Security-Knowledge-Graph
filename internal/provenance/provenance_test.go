package provenance

import (
	"strings"
	"testing"
	"time"
)

func TestPropsAndKey(t *testing.T) {
	at := time.Date(2024, 1, 2, 3, 4, 5, 678901234, time.UTC)
	p, err := Props("nvd", "RUN1", "abc", at)
	if err != nil {
		t.Fatal(err)
	}
	if p["p_nvd_run"] != "RUN1" || p["p_nvd_ref"] != "abc" {
		t.Fatalf("props %v", p)
	}
	if got := p["p_nvd_at"].(time.Time); got.Nanosecond() != 678000000 {
		t.Fatalf("at not ms precision: %v", got)
	}
	if s := p["sources"].([]string); len(s) != 1 || s[0] != "nvd" {
		t.Fatalf("sources %v", s)
	}
	if k, _ := Key("nvd", "removed"); k != "p_nvd_removed" {
		t.Fatal(k)
	}
}

func TestInvalidSource(t *testing.T) {
	for _, s := range []string{"", "Nvd", "a-b", "1a", "x'y", strings.Repeat("a", 17)} {
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
	c, err := SetClause("r", "nvd")
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"r.sources", "r.p_nvd_run = $runID", "r.p_nvd_at = $at", "r.p_nvd_ref = $ref"} {
		if !strings.Contains(c, w) {
			t.Errorf("missing %q in %s", w, c)
		}
	}
}

func TestRemovedAndMerge(t *testing.T) {
	if k, err := RemovedKey("nvd"); err != nil || k != "p_nvd_removed" || RemovedKeyOf("nvd") != k {
		t.Fatal(k, err)
	}
	if _, err := RemovedKey("Bad-Src"); err == nil {
		t.Fatal("want error")
	}
	in := []string{"nvd"}
	if got := MergeSources(in, "nvd"); len(got) != 1 {
		t.Fatal(got)
	}
	if got := MergeSources(in, "epss"); len(got) != 2 || len(in) != 1 {
		t.Fatal(got)
	}
}
