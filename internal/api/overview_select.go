package api

import (
	"fmt"
	"sort"
)

// Pure selection and ranking for GET /v1/graph/overview. Nothing in this file
// touches Cypher or HTTP.

// overviewSeed is a Vulnerability with the properties the ranking uses. A nil
// score is a missing property and sorts last.
type overviewSeed struct {
	CVE            string
	Exploitability *float64
	V3             *float64
	V2             *float64
}

// nodeRef names a domain node by label and raw key value.
type nodeRef struct {
	Label string
	Key   any
}

// ID is the node id used in responses: "Label:key", as in the neighborhood endpoint.
func (n nodeRef) ID() string { return n.Label + ":" + fmt.Sprint(n.Key) }

// cmpDescNullsLast orders larger values first and missing values last.
func cmpDescNullsLast(a, b *float64) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	case *a > *b:
		return -1
	case *a < *b:
		return 1
	}
	return 0
}

// seedLess is the ranking rule: exploitability desc, v3baseScore desc,
// v2baseScore desc (nulls last in each), then cveID asc.
func seedLess(a, b overviewSeed) bool {
	if c := cmpDescNullsLast(a.Exploitability, b.Exploitability); c != 0 {
		return c < 0
	}
	if c := cmpDescNullsLast(a.V3, b.V3); c != 0 {
		return c < 0
	}
	if c := cmpDescNullsLast(a.V2, b.V2); c != 0 {
		return c < 0
	}
	return a.CVE < b.CVE
}

// rankSeeds returns a ranked copy of seeds.
func rankSeeds(seeds []overviewSeed) []overviewSeed {
	out := append([]overviewSeed(nil), seeds...)
	sort.SliceStable(out, func(i, j int) bool { return seedLess(out[i], out[j]) })
	return out
}

// selectOverview walks the ranked seeds. For each it adds the Vulnerability
// and then its directly connected nodes (in id order), skipping nodes already
// selected, until limit nodes are selected. It returns the nodes in selection
// order. nbrs maps a CVE id to its neighbours.
func selectOverview(seeds []overviewSeed, nbrs map[string][]nodeRef, limit int) []nodeRef {
	var out []nodeRef
	seen := map[string]bool{}
	add := func(n nodeRef) {
		if len(out) < limit && !seen[n.ID()] {
			seen[n.ID()] = true
			out = append(out, n)
		}
	}
	for _, s := range rankSeeds(seeds) {
		if len(out) >= limit {
			break
		}
		add(nodeRef{Label: "Vulnerability", Key: s.CVE})
		ns := append([]nodeRef(nil), nbrs[s.CVE]...)
		sort.Slice(ns, func(i, j int) bool { return ns[i].ID() < ns[j].ID() })
		for _, n := range ns {
			add(n)
		}
	}
	return out
}
