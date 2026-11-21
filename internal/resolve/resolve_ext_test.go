package resolve

import (
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/bellu/bskg/internal/source"
)

func TestPackage(t *testing.T) {
	good := map[string]string{
		"pkg:npm/lodash@4.17.21":                            "pkg:npm/lodash",
		"pkg:npm/%40Angular/Core@1":                         "pkg:npm/%40angular/core",
		" pkg:PyPI/Django_Foo@3.0?x=y#sub ":                 "pkg:pypi/django-foo",
		"pkg:golang/github.com/foo/bar@v1.2.3":              "pkg:golang/github.com/foo/bar",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.0": "pkg:maven/org.apache.logging.log4j/log4j-core",
		"pkg:cargo/serde":                                   "pkg:cargo/serde",
		"pkg:gem/rails":                                     "pkg:gem/rails",
		"pkg:nuget/Newtonsoft.Json":                         "pkg:nuget/Newtonsoft.Json",
		"pkg:composer/laravel/framework":                    "pkg:composer/laravel/framework",
		"pkg:pub/http":                                      "pkg:pub/http",
		"pkg:hex/phoenix":                                   "pkg:hex/phoenix",
		"pkg:github/actions/checkout@v4":                    "pkg:github/actions/checkout",
		"pkg:swift/github.com/apple/swift-nio@2":            "pkg:swift/github.com/apple/swift-nio",
	}
	for in, want := range good {
		k, err := Package(in)
		if err != nil || k != (Key{"Package", "purl", want}) {
			t.Errorf("Package(%q) = %+v %v, want %s", in, k, err, want)
		}
	}
	for _, in := range []string{"", "pkg:", "pkg:npm", "npm/lodash", "pkg:deb/debian/curl@7", "pkg:docker/library/nginx"} {
		_, err := Package(in)
		if err == nil {
			t.Errorf("Package(%q) must fail", in)
		} else if in != "" && !strings.Contains(err.Error(), in) {
			t.Errorf("error for %q does not name the purl: %v", in, err)
		}
	}
}

func TestPurlFromOSV(t *testing.T) {
	cases := []struct{ eco, name, want string }{
		{"npm", "lodash", "pkg:npm/lodash"},
		{"npm", "@Angular/core", "pkg:npm/%40angular/core"},
		{"PyPI", "Django_Foo", "pkg:pypi/django-foo"},
		{"Go", "github.com/foo/bar", "pkg:golang/github.com/foo/bar"},
		{"Go", "stdlib", "pkg:golang/stdlib"},
		{"Maven", "org.apache.logging.log4j:log4j-core", "pkg:maven/org.apache.logging.log4j/log4j-core"},
		{"crates.io", "serde", "pkg:cargo/serde"},
		{"RubyGems", "rails", "pkg:gem/rails"},
		{"NuGet", "Newtonsoft.Json", "pkg:nuget/Newtonsoft.Json"},
		{"Packagist", "laravel/framework", "pkg:composer/laravel/framework"},
		{"Pub", "http", "pkg:pub/http"},
		{"Hex", "phoenix", "pkg:hex/phoenix"},
		{"GitHub Actions", "actions/checkout", "pkg:github/actions/checkout"},
		{"GitHub Actions", "actions/cache/save", "pkg:github/actions/cache"},
		{"SwiftURL", "github.com/apple/swift-nio", "pkg:swift/github.com/apple/swift-nio"},
		{"SwiftURL", "https://github.com/apple/swift-nio.git", "pkg:swift/github.com/apple/swift-nio"},
	}
	for _, c := range cases {
		got, err := PurlFromOSV(c.eco, c.name)
		if err != nil || got != c.want {
			t.Errorf("PurlFromOSV(%q, %q) = %q %v, want %q", c.eco, c.name, got, err, c.want)
			continue
		}
		// The result is a fixed point of the Package rule.
		if k, err := Package(got); err != nil || k.Value != got {
			t.Errorf("Package(%q) = %+v %v", got, k, err)
		}
	}
	for _, c := range []struct{ eco, name string }{
		{"Debian", "curl"}, {"npm", ""}, {"Maven", "no-colon"}, {"GitHub Actions", "solo"}, {"SwiftURL", "solo"},
	} {
		if _, err := PurlFromOSV(c.eco, c.name); err == nil {
			t.Errorf("PurlFromOSV(%q, %q) must fail", c.eco, c.name)
		}
	}
	if got := OSVEcosystems(); len(got) != 12 || got[0] != "npm" || got[11] != "SwiftURL" {
		t.Errorf("OSVEcosystems = %v", got)
	}
}

func TestAdvisory(t *testing.T) {
	good := map[string]string{
		"GHSA-C2F3-4GH5-WXMP":     "GHSA-c2f3-4gh5-wxmp",
		" ghsa-c2f3-4gh5-wxmp ":   "GHSA-c2f3-4gh5-wxmp",
		"pysec-2021-1":            "PYSEC-2021-1",
		"GO-2021-0113":            "GO-2021-0113",
		"rustsec-2020-0001":       "RUSTSEC-2020-0001",
		"OSV-2020-111":            "OSV-2020-111",
		"openSUSE-SU-2020:1234-1": "OPENSUSE-SU-2020:1234-1",
		"MAL-2022-Abc":            "MAL-2022-Abc",
	}
	for in, want := range good {
		k, err := Advisory(in)
		if err != nil || k != (Key{"Vulnerability", "cveID", want}) {
			t.Errorf("Advisory(%q) = %+v %v, want %s", in, k, err, want)
		}
	}
	for _, in := range []string{"", "GHSA", "GHSA-abcd", "GHSA-c2f3-4gh5-wxy", "GHSA-aaaa-bbbb-cccc", "CVE-2021-44228", "1-2", "GO-", "GO- 1", "GO 2021"} {
		if _, err := Advisory(in); err == nil {
			t.Errorf("Advisory(%q) must fail", in)
		}
	}
}

func TestCAPECTechniqueAtlas(t *testing.T) {
	for in, want := range map[string]string{"CAPEC-0066": "CAPEC-66", "capec-1": "CAPEC-1", "66": "CAPEC-66", " 007 ": "CAPEC-7"} {
		k, err := CAPEC(in)
		if err != nil || k != (Key{"AttackPattern", "capecID", want}) {
			t.Errorf("CAPEC(%q) = %+v %v", in, k, err)
		}
	}
	for _, in := range []string{"", "CAPEC-", "CAPEC-0", "0", "CAPEC-x", "CAPEC-99999999999"} {
		if _, err := CAPEC(in); err == nil {
			t.Errorf("CAPEC(%q) must fail", in)
		}
	}
	for in, want := range map[string]string{"t1059": "T1059", " T1059.001 ": "T1059.001"} {
		if k, err := Technique(in); err != nil || k != (Key{"Technique", "attackID", want}) {
			t.Errorf("Technique(%q) = %+v %v", in, k, err)
		}
	}
	for _, in := range []string{"", "T105", "T10599", "T1059.1", "AML.T0000", "TA0001"} {
		if _, err := Technique(in); err == nil {
			t.Errorf("Technique(%q) must fail", in)
		}
	}
	for in, want := range map[string]string{"aml.t0000": "AML.T0000", "AML.T0000.001": "AML.T0000.001"} {
		if k, err := Atlas(in); err != nil || k != (Key{"AtlasTechnique", "atlasID", want}) {
			t.Errorf("Atlas(%q) = %+v %v", in, k, err)
		}
	}
	for _, in := range []string{"", "T1059", "AML.T00", "AML.0000", "AML.T0000.01"} {
		if _, err := Atlas(in); err == nil {
			t.Errorf("Atlas(%q) must fail", in)
		}
	}
}

// Feature: bellu-security-knowledge-graph, Property 2 (Phase 2 and 3 kinds): resolving a canonical key again returns the same key.
func TestPropertyResolverIdempotenceExt(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kind := rapid.SampledFrom([]source.RefKind{source.RefPackage, source.RefAdvisory, source.RefCAPEC, source.RefTechnique, source.RefAtlas}).Draw(t, "kind")
		raw := rapid.OneOf(
			rapid.String(),
			rapid.StringMatching(`\s*(?i:pkg):(npm|pypi|PyPI|golang|maven|cargo|gem|nuget|composer|pub|hex|github|swift|deb)/[A-Za-z0-9._@%/-]{0,24}(@[0-9.]{1,6})?(\?a=b)?\s*`),
			rapid.StringMatching(`\s*(?i:ghsa)-[2-9cfghjmpqrvwxCFGHJMPQRVWX]{4}-[2-9cfghjmpqrvwxCFGHJMPQRVWX]{4}-[2-9cfghjmpqrvwxCFGHJMPQRVWX]{4}\s*`),
			rapid.StringMatching(`\s*[A-Za-z]{1,8}-[A-Za-z0-9._:+-]{1,16}\s*`),
			rapid.StringMatching(`\s*(?i:capec-)?0{0,3}\d{1,5}\s*`),
			rapid.StringMatching(`\s*(?i:t)\d{4}(\.\d{3})?\s*`),
			rapid.StringMatching(`\s*(?i:aml\.t)\d{4}(\.\d{3})?\s*`),
		).Draw(t, "raw")
		k, err := Resolve(source.Ref{Kind: kind, Raw: raw})
		if err != nil {
			return
		}
		k2, err := Resolve(source.Ref{Kind: kind, Raw: k.Value})
		if err != nil || k2 != k {
			t.Fatalf("%s %q -> %+v, again -> %+v %v", kind, raw, k, k2, err)
		}
		if kind == source.RefPackage && strings.ContainsAny(k.Value, "@?#") {
			t.Fatalf("Package key %q carries a version, qualifier, or subpath", k.Value)
		}
	})
}
