package resolve

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/bellu/bskg/internal/source"
)

// Phase 2 and 3 rules (Requirements 9.10 to 9.12, 14 to 17). They follow the
// same convention as the Phase 1 rules: exact, no fuzzy matching, and
// resolving a canonical value again returns the same key.

// ecosystem maps an OSV ecosystem name to a purl type.
type ecosystem struct {
	OSV  string
	Type string
}

// osvEcosystems lists the supported OSV ecosystems in the order of the
// BSKG_OSV_ECOSYSTEMS default. A purl type outside this list is rejected
// (Requirement 9.11).
var osvEcosystems = []ecosystem{
	{"npm", packageurl.TypeNPM},
	{"PyPI", packageurl.TypePyPi},
	{"Go", packageurl.TypeGolang},
	{"Maven", packageurl.TypeMaven},
	{"crates.io", packageurl.TypeCargo},
	{"RubyGems", packageurl.TypeGem},
	{"NuGet", packageurl.TypeNuget},
	{"Packagist", packageurl.TypeComposer},
	{"Pub", packageurl.TypePub},
	{"Hex", packageurl.TypeHex},
	{"GitHub Actions", packageurl.TypeGithub},
	{"SwiftURL", packageurl.TypeSwift},
}

// OSVEcosystems returns the supported OSV ecosystem names in default order.
func OSVEcosystems() []string {
	out := make([]string, len(osvEcosystems))
	for i, e := range osvEcosystems {
		out[i] = e.OSV
	}
	return out
}

// OSVEcosystemType returns the purl type of an OSV ecosystem name (exact
// match, case sensitive).
func OSVEcosystemType(name string) (string, bool) {
	for _, e := range osvEcosystems {
		if e.OSV == name {
			return e.Type, true
		}
	}
	return "", false
}

func supportedPurlType(t string) bool {
	for _, e := range osvEcosystems {
		if e.Type == t {
			return true
		}
	}
	return false
}

// Package resolves a package URL to its Package key. The key is the
// canonical purl without version, qualifiers, and subpath: one Package per
// package, versions live on AFFECTS_PACKAGE. The purl must parse and its type
// must be one of the supported ecosystems; otherwise the error names the purl.
func Package(raw string) (Key, error) {
	v := strings.TrimSpace(raw)
	bad := func(reason string) (Key, error) {
		return Key{}, &Error{Kind: source.RefPackage, Raw: raw, Reason: reason}
	}
	if v == "" {
		return bad("empty purl")
	}
	p, err := packageurl.FromString(v)
	if err != nil {
		return bad("malformed purl " + strconv.Quote(v) + ": " + err.Error())
	}
	if !supportedPurlType(p.Type) {
		return bad("unsupported package ecosystem " + strconv.Quote(p.Type) + " in purl " + strconv.Quote(v))
	}
	if p.Name == "" {
		return bad("malformed purl " + strconv.Quote(v) + ": no package name")
	}
	if p.Type == packageurl.TypeNPM { // npm names are lowercase
		p.Namespace, p.Name = strings.ToLower(p.Namespace), strings.ToLower(p.Name)
	}
	canon := packageurl.PackageURL{Type: p.Type, Namespace: p.Namespace, Name: p.Name}
	return Key{"Package", "purl", canon.ToString()}, nil
}

// PurlFromOSV builds the canonical Package purl (no version) for an OSV
// package: the ecosystem name as OSV writes it ("PyPI", "Go", "crates.io",
// "GitHub Actions", ...) and the package name as OSV writes it
// ("@scope/pkg", "group:artifact", "github.com/owner/repo"). Adapters call it
// and pass the result as Ref{Kind: RefPackage}. An unsupported ecosystem or
// an unusable name is an error naming both.
func PurlFromOSV(ecosystemName, name string) (string, error) {
	typ, ok := OSVEcosystemType(strings.TrimSpace(ecosystemName))
	if !ok {
		return "", fmt.Errorf("resolve: unsupported OSV ecosystem %q (package %q)", ecosystemName, name)
	}
	n := strings.TrimSpace(name)
	fail := func(why string) (string, error) {
		return "", fmt.Errorf("resolve: OSV package %q in ecosystem %q: %s", name, ecosystemName, why)
	}
	if n == "" {
		return fail("empty name")
	}
	var ns, nm string
	switch typ {
	case packageurl.TypeNPM, packageurl.TypeComposer, packageurl.TypeHex:
		ns, nm = splitLast(n, "/")
	case packageurl.TypeGolang:
		ns, nm = splitLast(n, "/")
	case packageurl.TypeMaven:
		var found bool
		ns, nm, found = strings.Cut(n, ":")
		if !found || ns == "" || nm == "" {
			return fail("want group:artifact")
		}
	case packageurl.TypeGithub:
		parts := strings.Split(n, "/")
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return fail("want owner/repo")
		}
		ns, nm = parts[0], parts[1] // a path inside the repository is dropped
	case packageurl.TypeSwift:
		n = strings.TrimSuffix(strings.TrimRight(stripScheme(n), "/"), ".git")
		ns, nm = splitLast(n, "/")
		if ns == "" {
			return fail("want host/owner/repo")
		}
	default: // pypi, cargo, gem, nuget, pub
		nm = n
	}
	if nm == "" {
		return fail("empty name")
	}
	pu := packageurl.PackageURL{Type: typ, Namespace: ns, Name: nm}
	k, err := Package(pu.ToString())
	if err != nil {
		return "", err
	}
	return k.Value, nil
}

func splitLast(s, sep string) (head, last string) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):]
	}
	return "", s
}

func stripScheme(s string) string {
	if u, err := url.Parse(s); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Host + u.Path
	}
	return s
}

var (
	ghsaRe     = regexp.MustCompile(`^GHSA(-[2-9cfghjmpqrvwx]{4}){3}$`)
	advPrefix  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)
	advRest    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+-]*$`)
	capecRe    = regexp.MustCompile(`^(?:CAPEC-)?(\d+)$`)
	techniqueR = regexp.MustCompile(`^T\d{4}(?:\.\d{3})?$`)
	atlasRe    = regexp.MustCompile(`^AML\.T\d{4}(?:\.\d{3})?$`)
)

const maxAdvisoryLen = 200

// Advisory canonicalizes an advisory id and returns the Vulnerability key
// that holds it (Vulnerability.cveID stores the advisory id of an
// advisory-only record, Requirement 9.5).
//
//	GHSA ids:  "GHSA-" + lowercase body, for example GHSA-abcd-2345-wxyz.
//	OSV ids:   <PREFIX>-<rest>; the prefix is uppercased and trimmed, the rest
//	           keeps its case (PYSEC-2021-1, GO-2021-0113, RUSTSEC-2020-0001).
//
// CVE ids are not advisory ids; use RefCVE.
func Advisory(raw string) (Key, error) {
	bad := func(reason string) (Key, error) {
		return Key{}, &Error{Kind: source.RefAdvisory, Raw: raw, Reason: reason}
	}
	v := strings.TrimSpace(raw)
	if v == "" || len(v) > maxAdvisoryLen {
		return bad("empty or too long")
	}
	prefix, rest, ok := strings.Cut(v, "-")
	if !ok || !advPrefix.MatchString(prefix) || !advRest.MatchString(rest) {
		return bad("not an advisory id <PREFIX>-<rest>")
	}
	up := strings.ToUpper(prefix)
	switch up {
	case "CVE":
		return bad("a CVE id is not an advisory id")
	case "GHSA":
		id := "GHSA-" + strings.ToLower(rest)
		if !ghsaRe.MatchString(id) {
			return bad("not a GHSA id GHSA-xxxx-xxxx-xxxx")
		}
		return Key{"Vulnerability", "cveID", id}, nil
	}
	return Key{"Vulnerability", "cveID", up + "-" + rest}, nil
}

// CAPEC returns CAPEC-<n> without leading zeros; the input is CAPEC-<n> in
// any letter case or a bare number. CAPEC-0 is rejected.
func CAPEC(raw string) (Key, error) {
	m := capecRe.FindStringSubmatch(strings.ToUpper(strings.TrimSpace(raw)))
	if m == nil {
		return Key{}, &Error{Kind: source.RefCAPEC, Raw: raw, Reason: "not a CAPEC id"}
	}
	digits := strings.TrimLeft(m[1], "0")
	if digits == "" {
		return Key{}, &Error{Kind: source.RefCAPEC, Raw: raw, Reason: "CAPEC numbers start at 1"}
	}
	n, err := strconv.ParseUint(digits, 10, 32)
	if err != nil {
		return Key{}, &Error{Kind: source.RefCAPEC, Raw: raw, Reason: "number out of range"}
	}
	return Key{"AttackPattern", "capecID", "CAPEC-" + strconv.FormatUint(n, 10)}, nil
}

// Technique returns the uppercase ATT&CK technique id T1234 or T1234.001.
func Technique(raw string) (Key, error) {
	v := strings.ToUpper(strings.TrimSpace(raw))
	if !techniqueR.MatchString(v) {
		return Key{}, &Error{Kind: source.RefTechnique, Raw: raw, Reason: "not an ATT&CK technique id"}
	}
	return Key{"Technique", "attackID", v}, nil
}

// Atlas returns the uppercase ATLAS technique id AML.T0000 or AML.T0000.000.
func Atlas(raw string) (Key, error) {
	v := strings.ToUpper(strings.TrimSpace(raw))
	if !atlasRe.MatchString(v) {
		return Key{}, &Error{Kind: source.RefAtlas, Raw: raw, Reason: "not an ATLAS technique id"}
	}
	return Key{"AtlasTechnique", "atlasID", v}, nil
}
