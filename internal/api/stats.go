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

	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/model"
)

// Count queries are generated at start-up from the schema registry. Label and
// type names come from internal/model, never from a request.
var (
	labelCountQueries = map[string]string{}
	relCountQueries   = map[string]string{}
)

func init() {
	for _, l := range model.Labels {
		if l.Kind == model.Domain && l.Phase <= 1 {
			q := fmt.Sprintf("MATCH (n:%s) RETURN count(n) AS n", l.Name)
			labelCountQueries[l.Name] = q
			allQueries = append(allQueries, q)
		}
	}
	for _, r := range model.Rels {
		if r.Phase <= 1 {
			q := fmt.Sprintf("MATCH ()-[r:%s]->() RETURN count(r) AS n", r.Name)
			relCountQueries[r.Name] = q
			allQueries = append(allQueries, q)
		}
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
// in production) and derives the result.
func computeStats(ctx context.Context, run queryFunc, now time.Time) (*StatsResult, error) {
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
		if !ok {
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
		if !ok {
			continue
		}
		n, err := count(q)
		if err != nil {
			return nil, err
		}
		res.Relationships = append(res.Relationships, nameCount{Type: r.Name, Count: n})
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
		"sync":             nil,
	}
	// Live fields, never cached. A failure here does not fail the statistics.
	ctx, cancel := o.s.QueryContext(r)
	defer cancel()
	if st, err := o.status(ctx); err == nil {
		body["sync"] = st.Sources
		body["buildState"] = st.BuildState
		body["buildMode"] = st.BuildMode
	}
	o.s.WriteJSON(w, r, http.StatusOK, body)
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
