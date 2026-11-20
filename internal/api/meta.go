package api

import (
	"context"
	"sync"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
)

// MetaCacheTTL is how long graph metadata is cached in memory.
const MetaCacheTTL = 2 * time.Second

// DefaultBuildState is reported until the Worker has written (:BuildMeta).
const DefaultBuildState = "migrating"

// Meta is the raw graph metadata behind the response envelope.
type Meta struct {
	BuildState  string
	LastSuccess map[string]*time.Time // per source; nil value = never succeeded
}

// MetaReader loads Meta. It is the seam later tasks fill; the Neo4j
// implementation is GraphMetaReader.
type MetaReader interface {
	Read(ctx context.Context) (Meta, error)
}

// Stale reports whether data is stale: true when there is no successful NVD
// run or the last one is older than threshold (Requirement 25.5).
func Stale(lastSuccess *time.Time, now time.Time, threshold time.Duration) bool {
	if lastSuccess == nil {
		return true
	}
	return now.Sub(*lastSuccess) > threshold
}

// GraphMeta is the "graph" object included in every response body.
type GraphMeta struct {
	Version    string                `json:"version"`
	BuildState string                `json:"buildState"`
	Stale      bool                  `json:"stale"`
	Sources    map[string]SourceMeta `json:"sources"`
}

// SourceMeta is one source's entry in GraphMeta.Sources.
type SourceMeta struct {
	LastSuccess *time.Time `json:"lastSuccess"`
}

// metaProvider builds GraphMeta from a MetaReader with a short cache. On a
// read failure it serves the last good value, or defaults when there is none,
// so error responses still carry the envelope.
type metaProvider struct {
	reader  MetaReader
	version string
	sources []string
	stale   time.Duration
	now     func() time.Time
	timeout time.Duration

	mu      sync.Mutex
	cached  GraphMeta
	have    bool
	expires time.Time
}

func (p *metaProvider) get(ctx context.Context) GraphMeta {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.have && now.Before(p.expires) {
		return p.cached
	}
	rctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	m, err := p.reader.Read(rctx)
	if err != nil {
		if p.have {
			return p.cached
		}
		return p.build(Meta{}, now) // not cached: retry on next request
	}
	p.cached = p.build(m, now)
	p.have = true
	p.expires = now.Add(MetaCacheTTL)
	return p.cached
}

func (p *metaProvider) build(m Meta, now time.Time) GraphMeta {
	state := m.BuildState
	if state == "" {
		state = DefaultBuildState
	}
	src := make(map[string]SourceMeta, len(p.sources))
	for _, name := range p.sources {
		src[name] = SourceMeta{LastSuccess: m.LastSuccess[name]}
	}
	return GraphMeta{
		Version:    p.version,
		BuildState: state,
		Stale:      Stale(m.LastSuccess["nvd"], now, p.stale),
		Sources:    src,
	}
}

// GraphMetaReader reads Meta from Neo4j with two constant read queries.
// Missing nodes give the defaults (state "migrating", no lastSuccess).
type GraphMetaReader struct {
	G *graph.Client
}

// Read implements MetaReader.
func (g GraphMetaReader) Read(ctx context.Context) (Meta, error) {
	v, err := g.G.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		m := Meta{BuildState: DefaultBuildState, LastSuccess: map[string]*time.Time{}}
		r, err := tx.Run(ctx, cypherBuildMeta, nil)
		if err != nil {
			return nil, err
		}
		if r.Next(ctx) {
			rec := r.Record().AsMap()
			if s, ok := rec["state"].(string); ok && s != "" {
				m.BuildState = s
			}
			if t, ok := asTime(rec["baseline"]); ok {
				m.LastSuccess["vulkg"] = &t
			}
		}
		if err := r.Err(); err != nil {
			return nil, err
		}
		r, err = tx.Run(ctx, cypherLastRuns, nil)
		if err != nil {
			return nil, err
		}
		for r.Next(ctx) {
			rec := r.Record().AsMap()
			name, _ := rec["source"].(string)
			if t, ok := asTime(rec["at"]); ok && name != "" {
				m.LastSuccess[name] = &t
			}
		}
		return m, r.Err()
	})
	if err != nil {
		return Meta{}, err
	}
	return v.(Meta), nil
}

func asTime(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t.UTC(), true
	case string:
		if p, err := time.Parse(time.RFC3339Nano, t); err == nil {
			return p.UTC(), true
		}
	}
	return time.Time{}, false
}
