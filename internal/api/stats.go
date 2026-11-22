package api

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/checkpoint"
	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/model"
)

// Count queries are generated at start-up from the schema registry for every
// phase; computeStats runs only those up to the applied phase. Label and
// type names come from internal/model, never from a request.
var (
	labelCountQueries = map[string]string{}
	relCountQueries   = map[string]string{}
)

func init() {
	for _, l := range model.Labels {
		if l.Kind == model.Domain {
			q := fmt.Sprintf("MATCH (n:%s) RETURN count(n) AS n", l.Name)
			labelCountQueries[l.Name] = q
			allQueries = append(allQueries, q)
		}
	}
	for _, r := range model.Rels {
		q := fmt.Sprintf("MATCH ()-[r:%s]->() RETURN count(r) AS n", r.Name)
		relCountQueries[r.Name] = q
		allQueries = append(allQueries, q)
	}
}

// Severity buckets in display order.
var severityOrder = []string{"UNSCORED", "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

type nameCount struct {
	Label string `json:"label,omitempty"`
	Type  string `json:"type,omitempty"`
	Count int64  `json:"count"`
}

type yearCount struct {
	Year  int64 `json:"year"`
	Count int64 `json:"count"`
}

type severityCount struct {
	Severity string `json:"severity"`
	Count    int64  `json:"count"`
}

type keyCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

type exploitedShare struct {
	Exploited int64   `json:"exploited"`
	Total     int64   `json:"total"`
	Ratio     float64 `json:"ratio"`
}

// StatsResult is the cached part of GET /v1/stats.
type StatsResult struct {
	GeneratedAt      time.Time       `json:"generatedAt"`
	Labels           []nameCount     `json:"labels"`
	Relationships    []nameCount     `json:"relationships"`
	CVEsByYear       []yearCount     `json:"cvesByYear"`
	CVSSDistribution []severityCount `json:"cvssDistribution"`
	TopWeaknesses    []keyCount      `json:"topWeaknesses"`
	TopVendors       []keyCount      `json:"topVendors"`
	TopProducts      []keyCount      `json:"topProducts"`
	ExploitedShare   exploitedShare  `json:"exploitedShare"`
	KEVCount         int64           `json:"kevCount"` // Vulnerabilities with kev = true
	EPSSHigh         int64           `json:"epssHigh"` // Vulnerabilities with epssScore >= 0.1
}

func asInt(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	}
	return 0
}

// computeStats runs every statistics query through run (one read transaction
// in production) and derives the result. Labels and relationship types of a
// phase above maxPhase are not counted.
func computeStats(ctx context.Context, run queryFunc, now time.Time, maxPhase int) (*StatsResult, error) {
	res := &StatsResult{GeneratedAt: now.UTC()}
	count := func(q string) (int64, error) {
		rows, err := run(ctx, q, nil)
		if err != nil {
			return 0, err
		}
		if len(rows) == 0 {
			return 0, nil
		}
		return asInt(rows[0]["n"]), nil
	}
	for _, l := range model.Labels {
		q, ok := labelCountQueries[l.Name]
		if !ok || l.Phase > maxPhase {
			continue
		}
		n, err := count(q)
		if err != nil {
			return nil, err
		}
		res.Labels = append(res.Labels, nameCount{Label: l.Name, Count: n})
	}
	for _, r := range model.Rels {
		q, ok := relCountQueries[r.Name]
		if !ok || r.Phase > maxPhase {
			continue
		}
		n, err := count(q)
		if err != nil {
			return nil, err
		}
		res.Relationships = append(res.Relationships, nameCount{Type: r.Name, Count: n})
	}
	var err error
	if res.KEVCount, err = count(cypherStatsKevCount); err != nil {
		return nil, err
	}
	if res.EPSSHigh, err = count(cypherStatsEpssHigh); err != nil {
		return nil, err
	}
	rows, err := run(ctx, cypherStatsScan, nil)
	if err != nil {
		return nil, err
	}
	res.CVEsByYear, res.CVSSDistribution, res.ExploitedShare = deriveScan(rows)
	for _, t := range []struct {
		q   string
		dst *[]keyCount
	}{
		{cypherStatsTopWeaknesses, &res.TopWeaknesses},
		{cypherStatsTopVendors, &res.TopVendors},
		{cypherStatsTopProducts, &res.TopProducts},
	} {
		rows, err := run(ctx, t.q, nil)
		if err != nil {
			return nil, err
		}
		out := []keyCount{}
		for _, r := range rows {
			k, _ := r["key"].(string)
			out = append(out, keyCount{Key: k, Count: asInt(r["n"])})
		}
		*t.dst = out
	}
	return res, nil
}

// deriveScan sums the (year, severity, exploitability) groups into the three views.
func deriveScan(rows []Row) ([]yearCount, []severityCount, exploitedShare) {
	years := map[int64]int64{}
	sev := map[string]int64{}
	var share exploitedShare
	for _, r := range rows {
		n := asInt(r["n"])
		if _, ok := r["year"].(int64); ok {
			years[asInt(r["year"])] += n
		}
		s, _ := r["severity"].(string)
		sev[s] += n
		share.Total += n
		if asInt(r["exploitability"]) == 1 {
			share.Exploited += n
		}
	}
	ys := make([]yearCount, 0, len(years))
	for y, n := range years {
		ys = append(ys, yearCount{Year: y, Count: n})
	}
	sort.Slice(ys, func(i, j int) bool { return ys[i].Year < ys[j].Year })
	ss := make([]severityCount, 0, len(severityOrder))
	for _, name := range severityOrder {
		ss = append(ss, severityCount{Severity: name, Count: sev[name]})
	}
	if share.Total > 0 {
		share.Ratio = math.Round(float64(share.Exploited)/float64(share.Total)*1e4) / 1e4
	}
	return ys, ss, share
}

// flightCache caches the last result of one computation and makes concurrent
// computations share one run (single flight).
type flightCache[T any] struct {
	ttl     time.Duration
	timeout time.Duration
	now     func() time.Time
	compute func(ctx context.Context) (T, error)

	mu     sync.Mutex
	val    T
	has    bool
	at     time.Time
	flight *cacheFlight[T]
}

// statsCache caches the /v1/stats computation.
type statsCache = flightCache[*StatsResult]

type cacheFlight[T any] struct {
	done chan struct{}
	res  T
	err  error
}

// get returns the cached value. stale is true when the computation failed and
// the previous result is served instead. The computation is detached from the
// caller's cancellation so that one impatient client does not fail the others.
func (c *flightCache[T]) get(ctx context.Context) (res T, stale bool, err error) {
	c.mu.Lock()
	if c.has && c.now().Sub(c.at) < c.ttl {
		v := c.val
		c.mu.Unlock()
		return v, false, nil
	}
	f := c.flight
	if f == nil {
		f = &cacheFlight[T]{done: make(chan struct{})}
		c.flight = f
		go c.run(ctx, f)
	}
	c.mu.Unlock()
	var zero T
	select {
	case <-f.done:
	case <-ctx.Done():
		return zero, false, ctx.Err()
	}
	if f.err == nil {
		return f.res, false, nil
	}
	c.mu.Lock()
	prev, has := c.val, c.has
	c.mu.Unlock()
	if has {
		return prev, true, nil
	}
	return zero, false, f.err
}

func (c *flightCache[T]) run(parent context.Context, f *cacheFlight[T]) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), c.timeout)
	defer cancel()
	res, err := c.compute(ctx)
	c.mu.Lock()
	if err == nil {
		c.val, c.has, c.at = res, true, c.now()
	}
	c.flight = nil
	c.mu.Unlock()
	f.res, f.err = res, err
	close(f.done)
}

// BatchFunc runs fn with a queryFunc bound to one read transaction.
type BatchFunc func(ctx context.Context, fn func(q queryFunc) error) error

// ReadBatch returns the production BatchFunc: one read transaction.
func ReadBatch(g *graph.Client) BatchFunc {
	return func(ctx context.Context, fn func(q queryFunc) error) error {
		_, err := g.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
			q := func(ctx context.Context, query string, params map[string]any) ([]Row, error) {
				res, err := tx.Run(ctx, query, params)
				if err != nil {
					return nil, err
				}
				rows := []Row{}
				for res.Next(ctx) {
					rows = append(rows, res.Record().AsMap())
				}
				return rows, res.Err()
			}
			return nil, fn(q)
		})
		return err
	}
}

// statsBody is the response: the cached result plus the fields read per request.
func (o *ops) stats(w http.ResponseWriter, r *http.Request) {
	res, stale, err := o.cache.get(r.Context())
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		o.s.WriteGraphError(w, r, err)
		return
	}
	body := map[string]any{
		"generatedAt":      res.GeneratedAt,
		"statsStale":       stale,
		"labels":           nonNil(res.Labels),
		"relationships":    nonNil(res.Relationships),
		"cvesByYear":       nonNil(res.CVEsByYear),
		"cvssDistribution": nonNil(res.CVSSDistribution),
		"topWeaknesses":    nonNil(res.TopWeaknesses),
		"topVendors":       nonNil(res.TopVendors),
		"topProducts":      nonNil(res.TopProducts),
		"exploitedShare":   res.ExploitedShare,
		"kevCount":         res.KEVCount,
		"epssHigh":         res.EPSSHigh,
		"sync":             nil,
		"coverage":         []coverageJSON{},
	}
	// Live fields, never cached. A failure here does not fail the statistics.
	ctx, cancel := o.s.QueryContext(r)
	defer cancel()
	if st, err := o.status(ctx); err == nil {
		body["sync"] = st.Sources
		body["buildState"] = st.BuildState
		body["buildMode"] = st.BuildMode
		body["coverage"] = o.coverage(ctx, st.raw)
	}
	o.s.WriteJSON(w, r, http.StatusOK, body)
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// coverageJSON is one entry of the "coverage" block of GET /v1/stats.
type coverageJSON struct {
	Source     string           `json:"source"`
	Upstream   map[string]int64 `json:"upstream"` // null until the source recorded totals
	UpstreamAt *time.Time       `json:"upstreamAt"`
	InGraph    map[string]int64 `json:"inGraph"` // null when the graph counts could not be read
}

// coverageQueries maps a source to its constant in-graph count query. Every
// column of a result row is one metric; its alias is the metric name.
var coverageQueries = map[string]string{
	"nvd":       cypherCoverageVulns,
	"cwe":       cypherCoverageWeaknesses,
	"exploitdb": cypherCoverageExploits,
	"kev":       cypherCoverageKEV,
	"epss":      cypherCoverageEPSS,
	"osv":       cypherCoverageOSV,
	"ghsa":      cypherCoverageGHSA,
	"attack":    cypherCoverageAttack,
	"atlas":     cypherCoverageAtlas,
	"capec":     cypherCoverageCAPEC,
}

// coveragePhase is the schema phase a source's in-graph count needs; a source
// missing here needs phase 1. Below it the count is not run and inGraph is {}.
var coveragePhase = map[string]int{"attack": 3, "atlas": 3, "capec": 3}

// coverage returns one entry per enabled source, in configured order. It is
// read per request and never cached. A failing count query leaves inGraph
// null and does not fail the statistics.
func (o *ops) coverage(ctx context.Context, srcs []checkpoint.SourceStatus) []coverageJSON {
	out := make([]coverageJSON, 0, len(srcs))
	phase := o.s.maxPhase(ctx)
	for _, s := range srcs {
		c := coverageJSON{Source: s.Source, UpstreamAt: tptr(s.UpstreamAt)}
		if len(s.Upstream) > 0 {
			c.Upstream = s.Upstream
		}
		c.InGraph = map[string]int64{}
		if q, ok := coverageQueries[s.Source]; ok && phase >= max(1, coveragePhase[s.Source]) {
			rows, err := o.q(ctx, q, nil)
			if err != nil {
				c.InGraph = nil
			} else if len(rows) > 0 {
				for k, v := range rows[0] {
					c.InGraph[k] = asInt(v)
				}
			}
		}
		out = append(out, c)
	}
	return out
}
