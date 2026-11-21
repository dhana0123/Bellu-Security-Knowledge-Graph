// Package resolve is the Entity_Resolver: the only component that decides the
// canonical key of a node (Requirement 9). Rules are exact. There is no fuzzy
// matching: identifiers that differ after the documented normalization get
// different keys.
package resolve

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/bellu/bskg/internal/source"
)

// Key identifies a node: its label, key property, and canonical value.
type Key struct {
	Label string
	Prop  string
	Value string
}

// String returns "Label:value" for logs and Change_Record entity keys.
func (k Key) String() string { return k.Label + ":" + k.Value }

// Error reports an identifier that has no canonical key.
type Error struct {
	Kind   source.RefKind
	Raw    string
	Reason string
	// Unresolved marks a reference that is valid in its source but names no
	// node of this graph (NVD-CWE-Other). The pipeline counts these as
	// unresolved instead of rejected.
	Unresolved bool
}

func (e *Error) Error() string {
	return fmt.Sprintf("resolve %s %q: %s", e.Kind, e.Raw, e.Reason)
}

// IsUnresolved reports whether err is an unresolved (not rejected) reference.
func IsUnresolved(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Unresolved
}

var (
	cveRe    = regexp.MustCompile(`^CVE-\d{4}-\d{4,19}$`)
	cweRe    = regexp.MustCompile(`^(?:CWE-)?(\d+)$`)
	digitsRe = regexp.MustCompile(`^\d+$`)
)

// Resolve returns the canonical key for ref.
func Resolve(ref source.Ref) (Key, error) {
	switch ref.Kind {
	case source.RefCVE:
		return CVE(ref.Raw)
	case source.RefCWE:
		return CWE(ref.Raw)
	case source.RefCPE:
		c, err := CPE(ref.Raw)
		return c.Product, err
	case source.RefCPEVend:
		c, err := CPE(ref.Raw)
		return c.Vendor, err
	case source.RefVendor:
		return text(ref, "Vendor", "vendorName")
	case source.RefDomain:
		return Domain(ref.Raw)
	case source.RefExploit:
		return Exploit(ref.Raw)
	case source.RefAuthor:
		return text(ref, "Author", "authorName")
	}
	return Key{}, &Error{Kind: ref.Kind, Raw: ref.Raw, Reason: "unknown reference kind"}
}

// CVE trims and uppercases a CVE id. Other ids (OSVDB-58726) are rejected.
func CVE(raw string) (Key, error) {
	v := strings.ToUpper(strings.TrimSpace(raw))
	if !cveRe.MatchString(v) {
		return Key{}, &Error{Kind: source.RefCVE, Raw: raw, Reason: "not a CVE id"}
	}
	return Key{"Vulnerability", "cveID", v}, nil
}

// CWE accepts CWE-<n> in any letter case or a bare number and returns
// CWE-<n> without leading zeros. NVD-CWE-Other, NVD-CWE-noinfo, and other
// non-numeric forms are unresolved references. CWE-0 does not exist and is
// rejected.
func CWE(raw string) (Key, error) {
	v := strings.ToUpper(strings.TrimSpace(raw))
	m := cweRe.FindStringSubmatch(v)
	if m == nil {
		return Key{}, &Error{Kind: source.RefCWE, Raw: raw, Reason: "not a weakness id", Unresolved: true}
	}
	digits := strings.TrimLeft(m[1], "0")
	if digits == "" {
		return Key{}, &Error{Kind: source.RefCWE, Raw: raw, Reason: "weakness numbers start at 1"}
	}
	n, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return Key{}, &Error{Kind: source.RefCWE, Raw: raw, Reason: "number out of range"}
	}
	return Key{"Weakness", "cweID", "CWE-" + strconv.FormatUint(n, 10)}, nil
}

// Domain returns the lowercased host of a URL, without port, credentials, or
// trailing dot. A bare host is accepted, so resolving a canonical key again
// returns the same key.
func Domain(raw string) (Key, error) {
	v := strings.TrimSpace(raw)
	bad := func(reason string) (Key, error) {
		return Key{}, &Error{Kind: source.RefDomain, Raw: raw, Reason: reason}
	}
	if v == "" {
		return bad("empty")
	}
	if !strings.Contains(v, "://") {
		if strings.Contains(v, ":") && !strings.ContainsAny(v, "/?#@") && strings.Count(v, ":") > 1 {
			v = "[" + v + "]" // bare IPv6 host
		}
		v = "http://" + v
	}
	u, err := url.Parse(v)
	if err != nil {
		return bad("not a URL")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" || strings.ContainsAny(host, " \t\r\n/\\") {
		return bad("no host")
	}
	return Key{"Domain", "domainName", host}, nil
}

// Exploit returns the Exploit-DB id as a digit string.
func Exploit(raw string) (Key, error) {
	v := strings.TrimSpace(raw)
	if !digitsRe.MatchString(v) {
		return Key{}, &Error{Kind: source.RefExploit, Raw: raw, Reason: "not a numeric Exploit-DB id"}
	}
	return Key{"Exploit", "eid", v}, nil
}

func text(ref source.Ref, label, prop string) (Key, error) {
	v := strings.TrimSpace(ref.Raw)
	if v == "" {
		return Key{}, &Error{Kind: ref.Kind, Raw: ref.Raw, Reason: "empty"}
	}
	return Key{label, prop, v}, nil
}

// CPEKeys is the result of the CPE rule.
type CPEKeys struct {
	Product Key
	Vendor  Key
	// ProductType is set on the Product only when it is created.
	ProductType string
}

// CPE applies the CPE rule: a CPE 2.3 name is split on unescaped ':'; the
// vendor is field 3 and the product is field 4, unescaped, with case kept.
// Product nodes are keyed by product name alone, so two vendors with the same
// product name share one Product. A wildcard or "not applicable" vendor or
// product has no node and is rejected.
func CPE(raw string) (CPEKeys, error) {
	bad := func(reason string) (CPEKeys, error) {
		return CPEKeys{}, &Error{Kind: source.RefCPE, Raw: raw, Reason: reason}
	}
	f := splitCPE(strings.TrimSpace(raw))
	if len(f) < 5 || f[0] != "cpe" || f[1] != "2.3" {
		return bad("not a CPE 2.3 name")
	}
	var ptype string
	switch f[2] {
	case "a":
		ptype = "Application"
	case "o":
		ptype = "Operating System"
	case "h":
		ptype = "Hardware"
	default:
		return bad("unknown CPE part")
	}
	vendor, product := unescapeCPE(f[3]), unescapeCPE(f[4])
	for _, v := range []string{vendor, product} {
		if v == "" || v == "*" || v == "-" {
			return bad("vendor or product is a wildcard")
		}
	}
	return CPEKeys{
		Product:     Key{"Product", "productName", product},
		Vendor:      Key{"Vendor", "vendorName", vendor},
		ProductType: ptype,
	}, nil
}

// splitCPE splits on ':' that is not preceded by a backslash. The fields keep
// their escapes.
func splitCPE(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++ // skip the escaped character
		case ':':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func unescapeCPE(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
