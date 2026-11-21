package checkpoint

import (
	"context"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
)

// SourceStatus is the per-source line of `bskg sync status` and /v1/status.
// LastStatus is empty when the source never ran.
type SourceStatus struct {
	Source      string
	Checkpoint  Checkpoint
	LastStatus  string
	LastError   string
	LastStarted time.Time
	Step        string
	Processed   int64
	Total       int64
	LastSuccess time.Time // zero when none
	DeadLetters int64
	// Upstream holds the upstream database's own totals (properties
	// upstream_<name> of the Checkpoint); nil when none were recorded.
	Upstream   map[string]int64
	UpstreamAt time.Time // zero when none
}

const cypherStatus = `UNWIND $sources AS s
OPTIONAL MATCH (c:Checkpoint {source: s})
CALL { WITH s
  OPTIONAL MATCH (r:SyncRun {source: s})
  WITH r ORDER BY r.startedAt DESC LIMIT 1
  RETURN r AS last }
CALL { WITH s
  OPTIONAL MATCH (r:SyncRun {source: s}) WHERE r.status IN ['succeeded', 'succeeded_with_errors']
  RETURN max(r.endedAt) AS lastSuccess }
CALL { WITH s
  OPTIONAL MATCH (d:DeadLetter {source: s})
  RETURN count(d) AS dl }
RETURN s AS source, c IS NOT NULL AS found, c.watermark AS watermark, c.resume AS resume, c.version AS version,
  last.status AS status, last.error AS error, last.startedAt AS startedAt, last.step AS step,
  last.processed AS processed, last.total AS total, lastSuccess, dl, properties(c) AS props`

// ReadStatus returns one SourceStatus per given source, in the given order.
func ReadStatus(ctx context.Context, g *graph.Client, sources []string) ([]SourceStatus, error) {
	if len(sources) == 0 {
		return nil, nil
	}
	v, err := g.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, cypherStatus, map[string]any{"sources": sources})
		if err != nil {
			return nil, err
		}
		by := map[string]SourceStatus{}
		for r.Next(ctx) {
			m := r.Record().AsMap()
			var s SourceStatus
			s.Source, _ = m["source"].(string)
			s.Checkpoint.Found, _ = m["found"].(bool)
			s.Checkpoint.Watermark, _ = m["watermark"].(time.Time)
			s.Checkpoint.Resume, _ = m["resume"].(string)
			s.Checkpoint.Version, _ = m["version"].(string)
			s.LastStatus, _ = m["status"].(string)
			s.LastError, _ = m["error"].(string)
			s.LastStarted, _ = m["startedAt"].(time.Time)
			s.Step, _ = m["step"].(string)
			s.Processed, _ = m["processed"].(int64)
			s.Total, _ = m["total"].(int64)
			s.LastSuccess, _ = m["lastSuccess"].(time.Time)
			s.DeadLetters, _ = m["dl"].(int64)
			props, _ := m["props"].(map[string]any)
			s.Upstream, s.UpstreamAt = upstreamFromProps(props)
			by[s.Source] = s
		}
		if err := r.Err(); err != nil {
			return nil, err
		}
		out := make([]SourceStatus, 0, len(sources))
		for _, src := range sources {
			s, ok := by[src]
			if !ok {
				s = SourceStatus{Source: src}
			}
			out = append(out, s)
		}
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]SourceStatus), nil
}

// upstreamFromProps extracts the upstream_ integer properties and upstreamAt
// from the properties of a Checkpoint node. The map is nil when none exist.
func upstreamFromProps(props map[string]any) (map[string]int64, time.Time) {
	var out map[string]int64
	for k, v := range props {
		name, ok := strings.CutPrefix(k, UpstreamPrefix)
		if !ok || name == "" {
			continue
		}
		n, ok := v.(int64)
		if !ok {
			continue
		}
		if out == nil {
			out = map[string]int64{}
		}
		out[name] = n
	}
	at, _ := props["upstreamAt"].(time.Time)
	return out, at
}
