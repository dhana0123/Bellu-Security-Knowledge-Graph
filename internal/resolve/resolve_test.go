package resolve

import (
	"strings"
	"testing"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
)

func TestCVE(t *testing.T) {
	good := map[string]string{
		" cve-2021-44228 ": "CVE-2021-44228",
		"CVE-1999-0001":    "CVE-1999-0001",
		"CVE-2024-1234567": "CVE-2024-1234567",
	}
	for in, want := range good {
		k, err := CVE(in)
		if err != nil || k != (Key{"Vulnerability", "cveID", want}) {
			t.Errorf("CVE(%q) = %+v %v", in, k, err)
		}
	}
	for _, bad := range []string{"", "OSVDB-58726", "CVE-21-1234", "CVE-2021-123", "CVE-2021-1234 x", "CVE-2021-12345678901234567890"} {
		if _, err := CVE(bad); err == nil {
			t.Errorf("CVE(%q) must fail", bad)
		}
	}
}

func TestCWE(t *testing.T) {
	good := map[string]string{"CWE-79": "CWE-79", "cwe-079": "CWE-79", "79": "CWE-79", " 0020 ": "CWE-20"}
	for in, want := range good {
		k, err := CWE(in)
		if err != nil || k.Value != want || k.Label != "Weakness" {
			t.Errorf("CWE(%q) = %+v %v", in, k, err)
		}
	}
	for _, in := range []string{"NVD-CWE-Other", "NVD-CWE-noinfo", "", "CWE-", "CWE-x"} {
		_, err := CWE(in)
		if err == nil || !IsUnresolved(err) {
			t.Errorf("CWE(%q) must be unresolved, got %v", in, err)
		}
	}
	for _, in := range []string{"0", "CWE-000"} {
		if _, err := CWE(in); err == nil || IsUnresolved(err) {
			t.Errorf("CWE(%q) must be rejected, got %v", in, err)
		}
	}
}

func TestDomain(t *testing.T) {
	good := map[string]string{
		"https://User:pw@GitHub.com:8443/a/b?q=1": "github.com",
		"http://example.org./x":                   "example.org",
		"example.com":                             "example.com",
		"http://[::1]:80/":                        "::1",
		"::1":                                     "::1",
	}
	for in, want := range good {
		k, err := Domain(in)
		if err != nil || k.Value != want {
			t.Errorf("Domain(%q) = %+v %v, want %q", in, k, err, want)
		}
	}
	for _, in := range []string{"", "  ", "http://", "http:///path"} {
		if _, err := Domain(in); err == nil {
			t.Errorf("Domain(%q) must fail", in)
		}
	}
}

func TestExploitAndText(t *testing.T) {
	if k, err := Exploit(" 50592 "); err != nil || k.Value != "50592" {
		t.Fatal(k, err)
	}
	for _, in := range []string{"", "EDB-1", "12a", "-1"} {
		if _, err := Exploit(in); err == nil {
			t.Errorf("Exploit(%q) must fail", in)
		}
	}
	if k, err := Resolve(source.Ref{Kind: source.RefAuthor, Raw: "  Jane Doe "}); err != nil || k.Value != "Jane Doe" {
		t.Fatal(k, err)
	}
	if _, err := Resolve(source.Ref{Kind: source.RefAuthor, Raw: " "}); err == nil {
		t.Fatal("empty author must fail")
	}
	if _, err := Resolve(source.Ref{Kind: "nope", Raw: "x"}); err == nil {
		t.Fatal("unknown kind must fail")
	}
}

func TestCPE(t *testing.T) {
	c, err := CPE(`cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*`)
	if err != nil || c.Product.Value != "log4j" || c.Vendor.Value != "apache" || c.ProductType != "Application" {
		t.Fatalf("%+v %v", c, err)
	}
	c, err = CPE(`cpe:2.3:o:linux:linux_kernel:5.10:*:*:*:*:*:*:*`)
	if err != nil || c.ProductType != "Operating System" {
		t.Fatalf("%+v %v", c, err)
	}
	c, err = CPE(`cpe:2.3:h:cisco:asr_1001\-x:-:*:*:*:*:*:*:*`)
	if err != nil || c.Product.Value != "asr_1001-x" || c.ProductType != "Hardware" {
		t.Fatalf("%+v %v", c, err)
	}
	// An escaped colon stays inside the field. Case is kept.
	c, err = CPE(`cpe:2.3:a:Foo\:Bar:Baz\.Qux:1.0:*:*:*:*:*:*:*`)
	if err != nil || c.Vendor.Value != "Foo:Bar" || c.Product.Value != "Baz.Qux" {
		t.Fatalf("%+v %v", c, err)
	}
	// Two vendors with one product name share one Product.
	a, _ := CPE(`cpe:2.3:a:v1:shared:1:*:*:*:*:*:*:*`)
	b, _ := CPE(`cpe:2.3:a:v2:shared:1:*:*:*:*:*:*:*`)
	if a.Product != b.Product || a.Vendor == b.Vendor {
		t.Fatal("product key must ignore the vendor")
	}
	for _, bad := range []string{"", "cpe:/a:x:y", "cpe:2.3:z:x:y", "cpe:2.3:a:*:y", "cpe:2.3:a:x:-", "cpe:2.3:a:x", "cpe:2.2:a:x:y"} {
		if _, err := CPE(bad); err == nil {
			t.Errorf("CPE(%q) must fail", bad)
		}
	}
}

func TestNormalizeRepoURL(t *testing.T) {
	good := map[string]string{
		"https://github.com/Apache/Struts":                     "https://github.com/Apache/Struts",
		"HTTP://GitHub.COM:443/o/r.git/":                       "https://github.com/o/r",
		"https://user:pw@github.com/o/r?tab=x#readme":          "https://github.com/o/r",
		"git@github.com:o/r.git":                               "https://github.com/o/r",
		"ssh://git@github.com/o/r":                             "https://github.com/o/r",
		"ssh://git@gitlab.com:2222/g/s/r.git":                  "https://gitlab.com/g/s/r",
		"https://gitlab.com/g/s/r/-/commit/abc":                "https://gitlab.com/g/s/r",
		"https://bitbucket.org/o/r/commits/abc":                "https://bitbucket.org/o/r",
		"https://github.com/o/r/issues/1":                      "https://github.com/o/r",
		"  https://github.com/o/r.git.git  ":                   "https://github.com/o/r",
		"git@bitbucket.org:o/r.git":                            "https://bitbucket.org/o/r",
		"https://GITLAB.com/group/repo/-/merge_requests/3?x=1": "https://gitlab.com/group/repo",
	}
	for in, want := range good {
		got, err := NormalizeRepoURL(in)
		if err != nil || got != want {
			t.Errorf("NormalizeRepoURL(%q) = %q, %v; want %q", in, got, err, want)
		}
		if again, err := NormalizeRepoURL(got); err != nil || again != got {
			t.Errorf("not idempotent: %q -> %q -> %q, %v", in, got, again, err)
		}
	}
	for _, bad := range []string{"", "github.com/o/r", "https://example.com/o/r", "https://github.com/o",
		"https://github.com/", "ftp://github.com/o/r", "https://github.com/o/.git", "https://gitlab.com/-/x",
		"https://gitlab.com/g/-/x", "https://www.github.com/o/r", "https://github.com/o/r%20x"} {
		if got, err := NormalizeRepoURL(bad); err == nil {
			t.Errorf("NormalizeRepoURL(%q) = %q, must fail", bad, got)
		}
	}
}

func TestFixCommit(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	want := "https://github.com/o/r@" + sha
	for _, in := range []string{
		"https://github.com/o/r@" + sha,
		"git@github.com:o/r.git@" + strings.ToUpper(sha),
		"HTTPS://GITHUB.COM/o/r/@" + sha,
	} {
		k, err := FixCommit(in)
		if err != nil || k != (Key{"FixCommit", "fcKey", want}) {
			t.Errorf("FixCommit(%q) = %+v, %v", in, k, err)
		}
		if k2, err := Resolve(source.Ref{Kind: source.RefFixCommit, Raw: k.Value}); err != nil || k2 != k {
			t.Errorf("not idempotent: %+v -> %+v, %v", k, k2, err)
		}
	}
	for _, bad := range []string{"", "https://github.com/o/r", "https://github.com/o/r@abc",
		"https://github.com/o/r@" + sha + "0", "https://github.com/o/r@" + sha[:39] + "g",
		"https://example.com/o/r@" + sha, "@" + sha} {
		if k, err := FixCommit(bad); err == nil {
			t.Errorf("FixCommit(%q) = %+v, must fail", bad, k)
		}
	}
	k, err := Resolve(source.Ref{Kind: source.RefRepository, Raw: "git@github.com:o/r.git"})
	if err != nil || k != (Key{"Repository", "url", "https://github.com/o/r"}) {
		t.Errorf("Resolve repository = %+v, %v", k, err)
	}
}
