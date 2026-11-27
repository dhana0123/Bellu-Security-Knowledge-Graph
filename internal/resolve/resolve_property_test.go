package resolve

import (
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
)

// Feature: bellu-security-knowledge-graph, Property 2: Resolver idempotence and CVE canonical form
// **Validates: Requirements 9.2, 9.3, 9.16**
func TestPropertyResolverIdempotence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kind := rapid.SampledFrom([]source.RefKind{source.RefCVE, source.RefCWE, source.RefDomain, source.RefExploit, source.RefAuthor, source.RefVendor}).Draw(t, "kind")
		raw := rapid.OneOf(
			rapid.String(),
			rapid.StringMatching(`\s*(?i:cve)-\d{4}-\d{3,8}\s*`),
			rapid.StringMatching(`\s*(?i:cwe)?-?0{0,3}\d{1,5}\s*`),
			rapid.StringMatching(`(https?://)?([a-zA-Z0-9]+@)?[A-Za-z0-9.-]{1,20}(:\d{1,4})?(/[a-z]*)?`),
			rapid.StringMatching(`\s*\d{1,8}\s*`),
		).Draw(t, "raw")
		k, err := Resolve(source.Ref{Kind: kind, Raw: raw})
		if err != nil {
			return
		}
		k2, err := Resolve(source.Ref{Kind: kind, Raw: k.Value})
		if err != nil || k2 != k {
			t.Fatalf("%s %q -> %+v, again -> %+v %v", kind, raw, k, k2, err)
		}
		if kind == source.RefCVE {
			if k.Value != strings.ToUpper(strings.TrimSpace(raw)) || !cveRe.MatchString(k.Value) {
				t.Fatalf("CVE canonical form %q from %q", k.Value, raw)
			}
		}
		if kind == source.RefCWE && !strings.HasPrefix(k.Value, "CWE-") {
			t.Fatalf("CWE key %q", k.Value)
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 3: No fuzzy merging
// **Validates: Requirements 9.15**
func TestPropertyNoFuzzyMerging(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := rapid.StringMatching(`[A-Za-z0-9_.-]{1,12}`).Draw(t, "a")
		b := rapid.StringMatching(`[A-Za-z0-9_.-]{1,12}`).Draw(t, "b")
		for _, kind := range []source.RefKind{source.RefVendor, source.RefAuthor} {
			ka, errA := Resolve(source.Ref{Kind: kind, Raw: a})
			kb, errB := Resolve(source.Ref{Kind: kind, Raw: b})
			if errA != nil || errB != nil {
				t.Fatal(errA, errB)
			}
			// Equal keys only when the trimmed text is equal: case and
			// punctuation differences never merge.
			if (ka == kb) != (strings.TrimSpace(a) == strings.TrimSpace(b)) {
				t.Fatalf("%s: %q and %q gave %v and %v", kind, a, b, ka, kb)
			}
		}
		pa, errA := CPE("cpe:2.3:a:v:" + a + ":1:*:*:*:*:*:*:*")
		pb, errB := CPE("cpe:2.3:a:v:" + b + ":1:*:*:*:*:*:*:*")
		if errA == nil && errB == nil && (pa.Product == pb.Product) != (a == b) {
			t.Fatalf("products %q and %q: %v %v", a, b, pa.Product, pb.Product)
		}
	})
}

func escapeCPE(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\:*?!"#$%&'()+,/;<=>@[]^`+"`"+`{|}~-.`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Feature: bellu-security-knowledge-graph, Property 6: CPE rule round trip
// **Validates: Requirements 8.11, 9.12**
func TestPropertyCPERoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		vendor := rapid.StringMatching(`[A-Za-z0-9_:.\-!+]{1,15}`).Draw(t, "vendor")
		product := rapid.StringMatching(`[A-Za-z0-9_:.\-!+]{1,15}`).Draw(t, "product")
		if vendor == "-" || product == "-" {
			t.Skip() // "-" means not applicable
		}
		part := rapid.SampledFrom([]string{"a", "o", "h"}).Draw(t, "part")
		cpe := "cpe:2.3:" + part + ":" + escapeCPE(vendor) + ":" + escapeCPE(product) + ":1.0:*:*:*:*:*:*:*"
		c, err := CPE(cpe)
		if err != nil {
			t.Fatalf("%q: %v", cpe, err)
		}
		if c.Vendor.Value != vendor || c.Product.Value != product {
			t.Fatalf("%q gave vendor %q product %q, want %q and %q", cpe, c.Vendor.Value, c.Product.Value, vendor, product)
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 2b: repository URL and fix-commit key idempotence
// **Validates: Requirement 9.17**
func TestPropertyRepoURLIdempotence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		raw := rapid.OneOf(
			rapid.String(),
			rapid.StringMatching(`(?i:https?|ssh|git)://([a-z]{1,5}(:[a-z]{1,5})?@)?(?i:github\.com|gitlab\.com|bitbucket\.org)(:\d{1,4})?(/[A-Za-z0-9._~-]{0,6}){0,6}(\.git)*/?(\?[a-z=]{0,5})?(#[a-z]{0,4})?`),
			rapid.StringMatching(`[a-z]{1,4}@(github\.com|gitlab\.com|bitbucket\.org):[A-Za-z0-9._-]{1,6}/[A-Za-z0-9._-]{1,6}(\.git)?`),
		).Draw(t, "raw")
		n, err := NormalizeRepoURL(raw)
		if err != nil {
			return
		}
		n2, err := NormalizeRepoURL(n)
		if err != nil || n2 != n {
			t.Fatalf("%q -> %q -> %q, %v", raw, n, n2, err)
		}
		sha := rapid.StringMatching(`[0-9a-fA-F]{40}`).Draw(t, "sha")
		k, err := FixCommit(raw + "@" + sha)
		if err != nil {
			return
		}
		k2, err := Resolve(source.Ref{Kind: source.RefFixCommit, Raw: k.Value})
		if err != nil || k2 != k || k.Value != n+"@"+strings.ToLower(sha) {
			t.Fatalf("%q -> %+v -> %+v, %v", raw, k, k2, err)
		}
	})
}
