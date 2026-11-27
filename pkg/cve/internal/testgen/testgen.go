// Package testgen provides rapid generators shared by property tests.
// It depends only on stable model types and simple parameters.
package testgen

import (
	"fmt"
	"strings"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
	"pgregory.net/rapid"
)

// Schemes lists the version schemes the version generators support.
var Schemes = []string{"semver", "pep440", "maven", "deb", "rpm"}

// Version draws a version string for the given scheme.
func Version(scheme string) *rapid.Generator[string] {
	num := rapid.IntRange(0, 12)
	return rapid.Custom(func(t *rapid.T) string {
		a, b, c := num.Draw(t, "major"), num.Draw(t, "minor"), num.Draw(t, "patch")
		switch scheme {
		case "semver":
			s := fmt.Sprintf("%d.%d.%d", a, b, c)
			if rapid.IntRange(0, 4).Draw(t, "pre") == 0 {
				s += "-" + rapid.SampledFrom([]string{"alpha", "beta", "rc.1", "rc.2", "0"}).Draw(t, "prerelease")
			}
			return s
		case "pep440":
			s := fmt.Sprintf("%d.%d", a, b)
			if rapid.Bool().Draw(t, "hasPatch") {
				s += fmt.Sprintf(".%d", c)
			}
			return s + rapid.SampledFrom([]string{"", "", "", "a1", "b2", "rc1", ".post1", ".dev1"}).Draw(t, "suffix")
		case "maven":
			s := fmt.Sprintf("%d.%d.%d", a, b, c)
			return s + rapid.SampledFrom([]string{"", "", "-SNAPSHOT", "-beta1", ".Final", "-rc1"}).Draw(t, "qualifier")
		case "deb":
			s := fmt.Sprintf("%d.%d.%d", a, b, c)
			if rapid.IntRange(0, 5).Draw(t, "epoch") == 0 {
				s = fmt.Sprintf("%d:%s", rapid.IntRange(1, 2).Draw(t, "e"), s)
			}
			return s + rapid.SampledFrom([]string{"", "-1", "-2ubuntu1", "~rc1", "+dfsg"}).Draw(t, "rev")
		case "rpm":
			return fmt.Sprintf("%d.%d.%d-%d", a, b, c, rapid.IntRange(1, 9).Draw(t, "release"))
		}
		return fmt.Sprintf("%d.%d.%d", a, b, c)
	})
}

// AnyVersion draws a version from a randomly chosen scheme.
func AnyVersion() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		return Version(rapid.SampledFrom(Schemes).Draw(t, "scheme")).Draw(t, "version")
	})
}

// Probes returns boundary-biased versions for a boundary version v: v itself,
// and neighbours just below and above (patch/last component +-1, and
// pre-release / zero-suffixed forms). Callers can use them to test interval
// membership at its edges.
func Probes(v string) []string {
	out := []string{v, v + ".0", v + ".1", "0", v + "-0", v + "~0"}
	parts := strings.Split(v, ".")
	last := parts[len(parts)-1]
	var n int
	if _, err := fmt.Sscanf(last, "%d", &n); err == nil && fmt.Sprint(n) == last {
		if n > 0 {
			p := append(append([]string(nil), parts[:len(parts)-1]...), fmt.Sprint(n-1))
			out = append(out, strings.Join(p, "."))
		}
		p := append(append([]string(nil), parts[:len(parts)-1]...), fmt.Sprint(n+1))
		out = append(out, strings.Join(p, "."))
	}
	return out
}

// VersionWithProbes draws a boundary version of the scheme together with probes around it.
func VersionWithProbes(scheme string) *rapid.Generator[[]string] {
	return rapid.Custom(func(t *rapid.T) []string {
		return Probes(Version(scheme).Draw(t, "boundary"))
	})
}

// ValidCVE draws a well-formed CVE id (year 1999..2030, 4 to 7 digit sequence).
func ValidCVE() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		y := rapid.IntRange(1999, 2030).Draw(t, "year")
		digits := rapid.IntRange(4, 7).Draw(t, "digits")
		seq := rapid.StringMatching(fmt.Sprintf(`[0-9]{%d}`, digits)).Draw(t, "seq")
		return fmt.Sprintf("CVE-%d-%s", y, seq)
	})
}

// InvalidCVE draws strings that look like CVE ids but are malformed.
func InvalidCVE() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.SampledFrom([]string{"", "CVE", "CVE-", "CVE-2021", "CVE-2021-", "CVE-21-12345", "CVE-2021-123", "CVE-2021-12a45",
			"cve-2021-12345 ", " CVE-2021-12345", "CVE_2021_12345", "CVE-20211-12345", "GHSA-xxxx-xxxx-xxxx", "CVE-2021-12345-1"}),
		rapid.StringMatching(`[A-Za-z0-9_ -]{0,16}`).Filter(func(s string) bool { return !model.IsCVE(s) }),
	)
}

// IDPool is the small identifier pool used for record ids and aliases so that
// collisions and alias bridges are frequent.
var IDPool = []string{
	"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004",
	"GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb", "GHSA-cccc-cccc-cccc",
	"PYSEC-2024-1", "PYSEC-2024-2", "RUSTSEC-2024-0001",
}

var pkgPool = []struct{ eco, name string }{
	{"npm", "alpha"}, {"npm", "beta"}, {"PyPI", "Gamma_Pkg"}, {"Maven", "org.x:delta"}, {"crates.io", "eps"},
}

// Records are timestamps on a fixed grid so generation is deterministic per draw.
var epoch = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// Record draws a model.Record whose ID and aliases come from IDPool.
func Record() *rapid.Generator[model.Record] {
	return rapid.Custom(func(t *rapid.T) model.Record {
		id := rapid.SampledFrom(IDPool).Draw(t, "id")
		aliases := rapid.SliceOfNDistinct(rapid.SampledFrom(IDPool), 0, 3, func(s string) string { return s }).Draw(t, "aliases")
		var al []string
		for _, a := range aliases {
			if a != id {
				al = append(al, a)
			}
		}
		pub := epoch.Add(time.Duration(rapid.IntRange(0, 100).Draw(t, "pub")) * 24 * time.Hour)
		mod := pub.Add(time.Duration(rapid.IntRange(0, 100).Draw(t, "mod")) * 24 * time.Hour)
		r := model.Record{
			Source:    rapid.SampledFrom([]string{"osv", "ghsa", "nvd"}).Draw(t, "source"),
			ID:        id,
			Aliases:   al,
			Summary:   rapid.StringMatching(`[a-z ]{0,20}`).Draw(t, "summary"),
			Published: pub,
			Modified:  mod,
		}
		if rapid.IntRange(0, 9).Draw(t, "withdrawn") == 0 {
			r.Withdrawn = mod
		}
		if rapid.Bool().Draw(t, "hasSeverity") {
			v := CVSSv3Vector().Draw(t, "vector")
			r.Severities = []model.Severity{{Source: r.Source, Type: "CVSS_V3", Version: "3.1", Vector: v}}
		}
		if rapid.Bool().Draw(t, "hasAffected") {
			p := rapid.SampledFrom(pkgPool).Draw(t, "pkg")
			fixed := Version("semver").Draw(t, "fixed")
			r.Affected = []model.Affected{{
				Kind: "package", Ecosystem: p.eco, Name: p.name,
				Ranges: []model.Range{{Type: "ECOSYSTEM", Events: []model.Event{{Introduced: "0"}, {Fixed: fixed}}}},
			}}
		}
		if rapid.IntRange(0, 3).Draw(t, "hasCWE") == 0 {
			r.Weaknesses = []string{fmt.Sprintf("CWE-%d", rapid.IntRange(1, 1400).Draw(t, "cwe"))}
		}
		return r
	})
}

// Records draws between 0 and max records.
func Records(max int) *rapid.Generator[[]model.Record] {
	return rapid.SliceOfN(Record(), 0, max)
}

var cvssChoices = [][]string{
	{"N", "A", "L", "P"}, // AV
	{"L", "H"},           // AC
	{"N", "L", "H"},      // PR
	{"N", "R"},           // UI
	{"U", "C"},           // S
	{"N", "L", "H"},      // C
	{"N", "L", "H"},      // I
	{"N", "L", "H"},      // A
}

var cvssKeys = []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

// CVSSv3Vector draws a valid CVSS v3.0/v3.1 base vector string.
func CVSSv3Vector() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		ver := rapid.SampledFrom([]string{"3.0", "3.1"}).Draw(t, "version")
		var b strings.Builder
		b.WriteString("CVSS:" + ver)
		for i, k := range cvssKeys {
			v := rapid.SampledFrom(cvssChoices[i]).Draw(t, k)
			b.WriteString("/" + k + ":" + v)
		}
		return b.String()
	})
}

// CanonicalStore is a small in-memory canonical store description built from
// generated records: records grouped by alias-connected component. It holds
// only model types so it does not depend on the canonical package.
type CanonicalStore struct {
	Records []model.Record
	// Groups maps each record index to a group id (union-find over ids and aliases).
	Groups []int
}

// Store draws a small canonical store of up to 8 records.
func Store() *rapid.Generator[CanonicalStore] {
	return rapid.Custom(func(t *rapid.T) CanonicalStore {
		recs := Records(8).Draw(t, "records")
		return CanonicalStore{Records: recs, Groups: groupOf(recs)}
	})
}

func groupOf(recs []model.Record) []int {
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		if p, ok := parent[x]; ok && p != x {
			r := find(p)
			parent[x] = r
			return r
		}
		parent[x] = x
		return x
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra != rb {
			if ra < rb {
				parent[rb] = ra
			} else {
				parent[ra] = rb
			}
		}
	}
	for _, r := range recs {
		find(r.ID)
		for _, a := range r.Aliases {
			union(r.ID, a)
		}
	}
	ids := map[string]int{}
	out := make([]int, len(recs))
	for i, r := range recs {
		root := find(r.ID)
		if _, ok := ids[root]; !ok {
			ids[root] = len(ids)
		}
		out[i] = ids[root]
	}
	return out
}

// Graph is a small snapshot graph of vulnerability and package nodes with edges.
type Graph struct {
	Nodes []string
	Edges [][2]string // (from, to)
}

// SmallGraph draws a graph of up to maxNodes nodes from a fixed label pool.
func SmallGraph(maxNodes int) *rapid.Generator[Graph] {
	return rapid.Custom(func(t *rapid.T) Graph {
		pool := []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "pkg:npm/alpha", "pkg:npm/beta", "pkg:pypi/gamma-pkg", "cpe:acme:widget", "CWE-79"}
		nodes := rapid.SliceOfNDistinct(rapid.SampledFrom(pool), 0, maxNodes, func(s string) string { return s }).Draw(t, "nodes")
		g := Graph{Nodes: nodes}
		if len(nodes) < 2 {
			return g
		}
		idx := rapid.IntRange(0, len(nodes)-1)
		n := rapid.IntRange(0, 2*len(nodes)).Draw(t, "edgeCount")
		seen := map[[2]string]bool{}
		for i := 0; i < n; i++ {
			a, b := nodes[idx.Draw(t, "from")], nodes[idx.Draw(t, "to")]
			e := [2]string{a, b}
			if a != b && !seen[e] {
				seen[e] = true
				g.Edges = append(g.Edges, e)
			}
		}
		return g
	})
}
