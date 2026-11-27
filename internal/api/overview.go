package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/model"
)

const (
	overviewDefaultLimit = 5000
	overviewMaxLimit     = 5000
	// overviewEdgesPerNode bounds the edge list: limit * 5 edges at most.
	overviewEdgesPerNode = 5
	// overviewPerSeed bounds the neighbours read per Vulnerability.
	overviewPerSeed = 500
	// overviewRowsPerNode bounds the neighbour rows read: limit * 4.
	overviewRowsPerNode = 4
	// overviewMaxCached bounds how many distinct limits are cached.
	overviewMaxCached = 8
)

// Overview queries are generated at start-up from the schema registry (label,
// key and type names never come from a request) and registered in allQueries
// for the read-only lint. Every query is bounded by a LIMIT parameter.
var (
	overviewNodeQueries  = map[string]string{} // all nodes of one label
	overviewPropsQueries = map[string]string{} // nodes of one label by key list
	overviewEdgeQueries  = map[string]string{} // relationships of one type between key lists
)

// cypherOverviewSeeds ranks Vulnerabilities (rule: seedLess). A boolean sorts
// false before true, so "IS NULL ASC" puts missing values last, which the
// plain DESC order would put first.
const cypherOverviewSeeds = `
MATCH (v:Vulnerability)
RETURN v.cveID AS cveID, v.exploitability AS exploitability, v.v3baseScore AS v3baseScore, v.v2baseScore AS v2baseScore
ORDER BY (v.exploitability IS NULL) ASC, v.exploitability DESC,
  (v.v3baseScore IS NULL) ASC, v.v3baseScore DESC,
  (v.v2baseScore IS NULL) ASC, v.v2baseScore DESC, cveID ASC
LIMIT $limit`

// cypherOverviewNeighbours returns up to $perSeed directly connected domain
// nodes of each given Vulnerability, at most $rowCap rows in total.
var cypherOverviewNeighbours string

func init() {
	for _, l := range model.Labels {
		if l.Kind != model.Domain {
			continue
		}
		q1 := fmt.Sprintf("MATCH (n:%[1]s) RETURN n.%[2]s AS key, properties(n) AS props ORDER BY key LIMIT $limit", l.Name, l.Key)
		q2 := fmt.Sprintf("UNWIND $keys AS k MATCH (n:%[1]s {%[2]s: k}) RETURN n.%[2]s AS key, properties(n) AS props LIMIT $limit", l.Name, l.Key)
		overviewNodeQueries[l.Name], overviewPropsQueries[l.Name] = q1, q2
		allQueries = append(allQueries, q1, q2)
	}
	for _, r := range model.Rels {
		from, _ := model.LabelByName(r.From)
		to, _ := model.LabelByName(r.To)
		q := fmt.Sprintf(`MATCH (a:%[1]s)-[r:%[2]s]->(b:%[3]s)
WHERE a.%[4]s IN $fromKeys AND b.%[5]s IN $toKeys AND coalesce(r.removed, false) = false
RETURN a.%[4]s AS src, b.%[5]s AS dst, r.viewID AS viewID
LIMIT $limit`, r.From, r.Name, r.To, from.Key, to.Key)
		overviewEdgeQueries[r.Name] = q
		allQueries = append(allQueries, q)
	}
	keyRaw := keyExpr
	cypherOverviewNeighbours = fmt.Sprintf(`
UNWIND $cves AS cve
MATCH (v:Vulnerability {cveID: cve})
CALL {
  WITH v
  MATCH (v)-[r]-(a)
  WHERE a <> v AND coalesce(r.removed, false) = false
    AND any(l IN labels(a) WHERE l IN $domainLabels)
  WITH DISTINCT a, head([l IN labels(a) WHERE l IN $domainLabels]) AS alabel, toString(%[1]s) AS akey
  ORDER BY alabel, akey
  LIMIT $perSeed
  RETURN alabel, %[1]s AS rawKey
}
RETURN cve, alabel AS label, rawKey AS key
LIMIT $rowCap`, keyRaw("a"))
	allQueries = append(allQueries, cypherOverviewSeeds, cypherOverviewNeighbours)
}

// overviewResult is the cached body of GET /v1/graph/overview.
type overviewResult struct {
	Nodes      []nbNode
	Edges      []nbEdge
	Truncated  bool
	TotalNodes int64 // total domain nodes
	TotalRels  int64 // total relationships
}

func numPtr(v any) *float64 {
	switch n := v.(type) {
	case int64:
		f := float64(n)
		return &f
	case int:
		f := float64(n)
		return &f
	case float64:
		return &n
	}
	return nil
}

// computeOverview builds the overview with at most limit nodes. run is one
// read transaction in production.
func computeOverview(ctx context.Context, run queryFunc, limit, maxPhase int) (*overviewResult, error) {
	res := &overviewResult{}
	for _, l := range model.Labels {
		if q, ok := labelCountQueries[l.Name]; ok && l.Phase <= maxPhase {
			rows, err := run(ctx, q, nil)
			if err != nil {
				return nil, err
			}
			if len(rows) > 0 {
				res.TotalNodes += asInt(rows[0]["n"])
			}
		}
	}
	for _, r := range model.Rels {
		if q, ok := relCountQueries[r.Name]; ok && r.Phase <= maxPhase {
			rows, err := run(ctx, q, nil)
			if err != nil {
				return nil, err
			}
			if len(rows) > 0 {
				res.TotalRels += asInt(rows[0]["n"])
			}
		}
	}

	var nodes map[string]nbNode
	var refs []nodeRef
	var err error
	if res.TotalNodes <= int64(limit) {
		nodes, refs, err = overviewAllNodes(ctx, run, limit, maxPhase)
	} else {
		res.Truncated = true
		nodes, refs, err = overviewRankedNodes(ctx, run, limit, maxPhase)
	}
	if err != nil {
		return nil, err
	}
	if len(refs) > limit { // the graph grew between the count and the read
		sort.Slice(refs, func(i, j int) bool { return refs[i].ID() < refs[j].ID() })
		for _, r := range refs[limit:] {
			delete(nodes, r.ID())
		}
		refs = refs[:limit]
		res.Truncated = true
	}

	edges, capped, err := overviewEdges(ctx, run, refs, nodes, limit, maxPhase)
	if err != nil {
		return nil, err
	}
	res.Edges = edges
	res.Truncated = res.Truncated || capped
	res.Nodes = make([]nbNode, 0, len(nodes))
	for _, n := range nodes {
		res.Nodes = append(res.Nodes, n)
	}
	sort.Slice(res.Nodes, func(i, j int) bool { return res.Nodes[i].ID < res.Nodes[j].ID })
	if !res.Truncated {
		res.TotalNodes, res.TotalRels = int64(len(res.Nodes)), int64(len(res.Edges))
	}
	return res, nil
}

func makeNode(label string, key any, props map[string]any) (nodeRef, nbNode) {
	ref := nodeRef{Label: label, Key: key}
	k := fmt.Sprint(key)
	return ref, nbNode{ID: ref.ID(), Type: label, Key: k, Label: cutRunes(k, maxNodeLabelLen), Properties: scalarProps(props)}
}

// overviewAllNodes reads every domain node up to maxPhase (at most limit+1 per label).
func overviewAllNodes(ctx context.Context, run queryFunc, limit, maxPhase int) (map[string]nbNode, []nodeRef, error) {
	nodes := map[string]nbNode{}
	var refs []nodeRef
	for _, l := range model.Labels {
		q, ok := overviewNodeQueries[l.Name]
		if !ok || l.Phase > maxPhase {
			continue
		}
		rows, err := run(ctx, q, map[string]any{"limit": int64(limit + 1)})
		if err != nil {
			return nil, nil, err
		}
		for _, r := range rows {
			if r["key"] == nil {
				continue
			}
			ref, n := makeNode(l.Name, r["key"], asProps(r["props"]))
			nodes[n.ID] = n
			refs = append(refs, ref)
		}
	}
	return nodes, refs, nil
}

// overviewRankedNodes selects the ranked subset (see selectOverview) and reads
// the properties of the selected nodes.
func overviewRankedNodes(ctx context.Context, run queryFunc, limit, maxPhase int) (map[string]nbNode, []nodeRef, error) {
	rows, err := run(ctx, cypherOverviewSeeds, map[string]any{"limit": int64(limit)})
	if err != nil {
		return nil, nil, err
	}
	seeds := make([]overviewSeed, 0, len(rows))
	cves := make([]string, 0, len(rows))
	for _, r := range rows {
		id, _ := r["cveID"].(string)
		if id == "" {
			continue
		}
		seeds = append(seeds, overviewSeed{CVE: id, Exploitability: numPtr(r["exploitability"]), V3: numPtr(r["v3baseScore"]), V2: numPtr(r["v2baseScore"])})
		cves = append(cves, id)
	}
	nbrs := map[string][]nodeRef{}
	if len(cves) > 0 {
		rows, err = run(ctx, cypherOverviewNeighbours, map[string]any{
			"cves": cves, "domainLabels": model.DomainLabels(maxPhase),
			"perSeed": int64(overviewPerSeed), "rowCap": int64(limit * overviewRowsPerNode),
		})
		if err != nil {
			return nil, nil, err
		}
		for _, r := range rows {
			cve, _ := r["cve"].(string)
			label, _ := r["label"].(string)
			if label == "" || r["key"] == nil {
				continue
			}
			nbrs[cve] = append(nbrs[cve], nodeRef{Label: label, Key: r["key"]})
		}
	}
	selected := selectOverview(seeds, nbrs, limit)
	byLabel := map[string][]any{}
	for _, n := range selected {
		byLabel[n.Label] = append(byLabel[n.Label], n.Key)
	}
	nodes := map[string]nbNode{}
	var refs []nodeRef
	for _, l := range model.Labels {
		keys := byLabel[l.Name]
		q, ok := overviewPropsQueries[l.Name]
		if !ok || len(keys) == 0 {
			continue
		}
		rows, err := run(ctx, q, map[string]any{"keys": keys, "limit": int64(len(keys))})
		if err != nil {
			return nil, nil, err
		}
		for _, r := range rows {
			if r["key"] == nil {
				continue
			}
			ref, n := makeNode(l.Name, r["key"], asProps(r["props"]))
			nodes[n.ID] = n
			refs = append(refs, ref)
		}
	}
	return nodes, refs, nil
}

// overviewEdges reads the relationships among the selected nodes. capped is
// true when the edge list was cut at limit * overviewEdgesPerNode.
func overviewEdges(ctx context.Context, run queryFunc, refs []nodeRef, nodes map[string]nbNode, limit, maxPhase int) ([]nbEdge, bool, error) {
	keys := map[string][]any{}
	for _, r := range refs {
		keys[r.Label] = append(keys[r.Label], r.Key)
	}
	maxEdges := limit * overviewEdgesPerNode
	edges := []nbEdge{}
	seen := map[string]bool{}
	for _, rt := range model.Rels {
		q, ok := overviewEdgeQueries[rt.Name]
		if !ok || rt.Phase > maxPhase || len(keys[rt.From]) == 0 || len(keys[rt.To]) == 0 {
			continue
		}
		rows, err := run(ctx, q, map[string]any{"fromKeys": keys[rt.From], "toKeys": keys[rt.To], "limit": int64(maxEdges + 1)})
		if err != nil {
			return nil, false, err
		}
		for _, r := range rows {
			if r["src"] == nil || r["dst"] == nil {
				continue
			}
			src := nodeRef{Label: rt.From, Key: r["src"]}.ID()
			dst := nodeRef{Label: rt.To, Key: r["dst"]}.ID()
			if _, ok := nodes[src]; !ok {
				continue
			}
			if _, ok := nodes[dst]; !ok {
				continue
			}
			e := nbEdge{ID: src + "|" + rt.Name + "|" + dst, Source: src, Target: dst, Type: rt.Name}
			if vid := r["viewID"]; vid != nil {
				e.ViewID = vid
				e.ID += "|" + fmt.Sprint(vid)
			}
			if !seen[e.ID] {
				seen[e.ID] = true
				edges = append(edges, e)
			}
		}
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
	capped := len(edges) > maxEdges
	if capped {
		edges = edges[:maxEdges]
	}
	return edges, capped, nil
}

// overviewCaches holds one flightCache per limit, at most overviewMaxCached;
// the oldest entry is dropped when a new limit arrives.
type overviewCaches struct {
	mu      sync.Mutex
	m       map[int]*flightCache[*overviewResult]
	order   []int
	ttl     time.Duration
	timeout time.Duration
	now     func() time.Time
	compute func(ctx context.Context, limit int) (*overviewResult, error)
}

func (c *overviewCaches) forLimit(limit int) *flightCache[*overviewResult] {
	c.mu.Lock()
	defer c.mu.Unlock()
	if fc, ok := c.m[limit]; ok {
		return fc
	}
	if c.m == nil {
		c.m = map[int]*flightCache[*overviewResult]{}
	}
	if len(c.order) >= overviewMaxCached {
		delete(c.m, c.order[0])
		c.order = c.order[1:]
	}
	fc := &flightCache[*overviewResult]{
		ttl: c.ttl, timeout: c.timeout, now: c.now,
		compute: func(ctx context.Context) (*overviewResult, error) { return c.compute(ctx, limit) },
	}
	c.m[limit] = fc
	c.order = append(c.order, limit)
	return fc
}

func parseOverviewLimit(r *http.Request) (int, error) {
	s := r.URL.Query().Get("limit")
	if s == "" {
		return overviewDefaultLimit, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > overviewMaxLimit {
		return 0, bad("limit", "must be an integer from 1 to 5000")
	}
	return n, nil
}

func (o *ops) overview(w http.ResponseWriter, r *http.Request) {
	limit, err := parseOverviewLimit(r)
	if err != nil {
		o.s.writeParamError(w, r, err)
		return
	}
	res, _, err := o.overviewCache.forLimit(limit).get(r.Context())
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		o.s.WriteGraphError(w, r, err)
		return
	}
	o.s.WriteJSON(w, r, http.StatusOK, map[string]any{
		"nodes":     nonNil(res.Nodes),
		"edges":     nonNil(res.Edges),
		"truncated": res.Truncated,
		"total":     map[string]int64{"nodes": res.TotalNodes, "relationships": res.TotalRels},
	})
}
