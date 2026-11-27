package testgen

import (
	"regexp"
	"testing"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
	"pgregory.net/rapid"
)

func TestCVEGenerators(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if v := ValidCVE().Draw(t, "valid"); !model.IsCVE(v) {
			t.Fatalf("valid CVE rejected: %q", v)
		}
		if v := InvalidCVE().Draw(t, "invalid"); model.IsCVE(v) {
			t.Fatalf("invalid CVE accepted: %q", v)
		}
	})
}

var vecRe = regexp.MustCompile(`^CVSS:3\.[01](/[A-Z]+:[A-Z])+$`)

func TestRecordAndVectorGenerators(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if v := CVSSv3Vector().Draw(t, "vec"); !vecRe.MatchString(v) {
			t.Fatalf("bad vector %q", v)
		}
		s := Store().Draw(t, "store")
		if len(s.Groups) != len(s.Records) {
			t.Fatal("group length mismatch")
		}
		for _, r := range s.Records {
			for _, a := range r.Aliases {
				if a == r.ID {
					t.Fatal("self alias")
				}
			}
		}
		for _, scheme := range Schemes {
			if len(VersionWithProbes(scheme).Draw(t, "probes")) == 0 {
				t.Fatal("no probes")
			}
		}
		_ = SmallGraph(5).Draw(t, "graph")
	})
}
