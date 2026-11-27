package normalize_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/enrich"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/nvd"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/osv"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/normalize"
	"pgregory.net/rapid"
)

func fixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "tests", "fixtures"}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCanonicalCVE(t *testing.T) {
	got, err := normalize.CanonicalCVE("  cve-2021-44228 ")
	if err != nil || got != "CVE-2021-44228" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{"", "CVE-21-1", "CVE-2021-123", "GHSA-xxxx"} {
		var r normalize.Rejection
		if _, err := normalize.CanonicalCVE(bad); !errors.As(err, &r) || r.Field == "" {
			t.Errorf("%q: want Rejection, got %v", bad, err)
		}
	}
}

func TestCanonicalEcosystemAndPackage(t *testing.T) {
	for in, want := range map[string]string{"NPM": "npm", "pypi": "PyPI", " maven ": "Maven", "GO": "Go", "Crates.IO": "crates.io", "nuget": "NuGet"} {
		if got, ok := normalize.CanonicalEcosystem(in); got != want || !ok {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	if got, ok := normalize.CanonicalEcosystem("Debian:11"); got != "Debian:11" || ok {
		t.Errorf("unmapped: %q %v", got, ok)
	}
	for _, c := range [][3]string{
		{"PyPI", "Foo_Bar.baz--Qux", "foo-bar-baz-qux"},
		{"npm", " Left-Pad ", "left-pad"},
		{"Maven", " Org.Apache : Commons-IO ", "Org.Apache:Commons-IO"},
		{"Go", "github.com/Foo/Bar", "github.com/Foo/Bar"},
		{"crates.io", "Serde_JSON", "serde_json"},
		{"NuGet", "Newtonsoft.Json", "newtonsoft.json"},
	} {
		if got := normalize.CanonicalPackage(c[0], c[1]); got != c[2] {
			t.Errorf("%s %q: got %q want %q", c[0], c[1], got, c[2])
		}
	}
	if model.PackageID("PyPI", "Foo_Bar") != "pkg:pypi/foo-bar" {
		t.Error("PackageID must wrap CanonicalPackage")
	}
}

func TestPackageProperties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		eco := rapid.SampledFrom([]string{"npm", "pypi", "Maven", "go", "CRATES.IO", "nuget", "Other"}).Draw(t, "eco")
		name := rapid.StringMatching(`[ A-Za-z0-9_.:/-]{0,20}`).Draw(t, "name")
		c := normalize.CanonicalPackage(eco, name)
		if normalize.CanonicalPackage(eco, c) != c {
			t.Fatalf("not idempotent: %q", c)
		}
		if got := normalize.CanonicalPackage("PyPI", strings.ToUpper(strings.ReplaceAll(name, "-", "_"))); got != normalize.CanonicalPackage("PyPI", name) && !strings.Contains(name, "  ") {
			t.Fatalf("pypi separators/case matter: %q vs %q", got, normalize.CanonicalPackage("PyPI", name))
		}
	})
}

func TestOSVGoldenWithdrawn(t *testing.T) {
	rec, rej, err := osv.ParseAt("ghsa", fixture(t, "ghsa", "GHSA-withdrawn-0001.json"), time.Time{})
	if err != nil || len(rej) != 0 {
		t.Fatal(err, rej)
	}
	want := time.Date(2022, 5, 1, 0, 0, 0, 0, time.UTC)
	if !rec.Withdrawn.Equal(want) || rec.Affected[0].Ecosystem != "npm" || rec.Affected[0].Unmapped {
		t.Fatalf("%+v", rec)
	}
}

func TestOSVWithdrawnFallsBackToRetrieval(t *testing.T) {
	retrieved := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	rec, _, err := osv.ParseAt("osv", []byte(`{"id":"x-1","withdrawn":"garbage"}`), retrieved)
	if err != nil || !rec.Withdrawn.Equal(retrieved) {
		t.Fatalf("%v %+v", err, rec)
	}
}

func TestOSVUnmappedEcosystemAndErrors(t *testing.T) {
	rec, _, err := osv.ParseAt("osv", []byte(`{"id":"a-1","affected":[{"package":{"ecosystem":"Debian:11","name":"Foo"}}]}`), time.Time{})
	if err != nil || !rec.Affected[0].Unmapped || rec.Affected[0].Name != "Foo" {
		t.Fatalf("%v %+v", err, rec)
	}
	if _, _, err := osv.ParseAt("osv", []byte(`{not json`), time.Time{}); !errors.Is(err, normalize.ErrFormat) {
		t.Fatalf("want ErrFormat, got %v", err)
	}
	rec, rej, err := osv.ParseAt("osv", []byte(`{"id":" "}`), time.Time{})
	if err != nil || rec != nil || len(rej) == 0 || rej[0].Field != "id" {
		t.Fatalf("%v %v %v", rec, rej, err)
	}
}

func TestNVDGolden(t *testing.T) {
	recs, rej, err := nvd.ParseResponse(fixture(t, "nvd", "page1.json"), time.Time{})
	if err != nil || len(rej) != 0 || len(recs) == 0 {
		t.Fatal(err, rej, len(recs))
	}
	for _, r := range recs {
		if !model.IsCVE(r.ID) {
			t.Errorf("bad id %q", r.ID)
		}
	}
}

func TestNVDMixedPayloadAndFormat(t *testing.T) {
	mixed := `{"vulnerabilities":[{"cve":{"id":"cve-2020-0001","lastModified":"2020-01-01T00:00:00","vulnStatus":"Rejected"}},{"cve":{"id":"nope"}},{"cve":{"id":""}}]}`
	retrieved := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	recs, rej, err := nvd.ParseResponse([]byte(mixed), retrieved)
	if err != nil || len(recs) != 1 || len(rej) != 2 || recs[0].ID != "CVE-2020-0001" {
		t.Fatalf("%v %v %v", recs, rej, err)
	}
	if !recs[0].Withdrawn.Equal(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("withdrawn %v", recs[0].Withdrawn)
	}
	recs, rej, err = nvd.ParseResponse([]byte(`<html>`), retrieved)
	if !errors.Is(err, normalize.ErrFormat) || recs != nil || rej != nil {
		t.Fatalf("%v %v %v", recs, rej, err)
	}
}

func TestKEVAndEPSS(t *testing.T) {
	k, rej, err := enrich.ParseKEVReport(bytes.NewReader(fixture(t, "kev", "known_exploited_vulnerabilities.json")))
	if err != nil || len(k) == 0 || len(rej) != 0 {
		t.Fatal(err, rej, len(k))
	}
	k, rej, err = enrich.ParseKEVReport(strings.NewReader(`{"vulnerabilities":[{"cveID":"cve-2020-1234"},{"cveID":"bad"}]}`))
	if err != nil || len(k) != 1 || k[0].CVE != "CVE-2020-1234" || len(rej) != 1 || k[0].Ransomware != "unknown" {
		t.Fatalf("%v %v %v", k, rej, err)
	}
	if k, _, err := enrich.ParseKEVReport(strings.NewReader(`[`)); !errors.Is(err, normalize.ErrFormat) || k != nil {
		t.Fatalf("%v %v", k, err)
	}
	e, rej, err := enrich.ParseEPSSReport(bytes.NewReader(fixture(t, "epss", "epss_scores.csv")))
	if err != nil || len(e) != 2 || len(rej) != 1 || rej[0].RecordID != "CVE-2023-0002" {
		t.Fatal(err, rej, len(e))
	}
	e, rej, err = enrich.ParseEPSSReport(strings.NewReader("cve,epss,percentile\ncve-2020-1,0.5,0.5\nCVE-2020-0001,2,0.5\nCVE-2020-0002,0.1,0.2\n"))
	if err != nil || len(e) != 1 || len(rej) != 2 {
		t.Fatalf("%v %v %v", e, rej, err)
	}
	if e, _, err := enrich.ParseEPSSReport(strings.NewReader("a,b\n1,2\n")); !errors.Is(err, normalize.ErrFormat) || e != nil {
		t.Fatalf("%v %v", e, err)
	}
}

func TestOSVAndGHSAGolden(t *testing.T) {
	rec, rej, err := osv.ParseAt("osv", fixture(t, "osv", "PYSEC-2020-1.json"), time.Time{})
	if err != nil || len(rej) != 0 || rec.ID != "PYSEC-2020-1" {
		t.Fatal(err, rej, rec)
	}
	if a := rec.Affected[0]; a.Ecosystem != "PyPI" || a.Name != "example-pkg" || a.Unmapped {
		t.Fatalf("%+v", a)
	}
	rec, rej, err = osv.ParseAt("osv", fixture(t, "osv", "GHSA-jfh8-c2jp-5v3q.json"), time.Time{})
	if err != nil || len(rej) != 0 || rec.Affected[0].Ecosystem != "Maven" {
		t.Fatal(err, rej, rec)
	}
	found := false
	for _, a := range rec.Aliases {
		found = found || a == "CVE-2021-44228"
	}
	if !found {
		t.Fatalf("aliases %v", rec.Aliases)
	}
	rec, rej, err = osv.ParseAt("ghsa", fixture(t, "ghsa", "GHSA-multi-0002.json"), time.Time{})
	if err != nil || len(rej) != 0 || len(rec.Aliases) != 2 || rec.Affected[0].Name != "multi-pkg" {
		t.Fatal(err, rej, rec)
	}
}
