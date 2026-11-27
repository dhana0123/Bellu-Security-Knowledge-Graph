// Package checkpoint holds the graph-level build metadata and, in later
// tasks, checkpoints, locks, and sync run records.
package checkpoint

import (
	"context"
	"errors"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/graph"
)

// Build modes stored in (:BuildMeta).buildMode. The empty string means unset.
const (
	ModeSample = "sample"
	ModeFull   = "full"
)

// ErrFullGraphSample is returned when BSKG_SAMPLE_LIMIT is set on a graph
// that already has the build mode full (Requirement 12.12). The operator must
// run `bskg reset --confirm` first.
var ErrFullGraphSample = errors.New("the graph is a full build and cannot be reduced to a sample; unset BSKG_SAMPLE_LIMIT or run `bskg reset --confirm`")

// Decision is the build mode and sample limit to run with.
type Decision struct {
	Mode  string // ModeSample or ModeFull
	Limit int    // sample limit; 0 in full mode
}

// DecideBuildMode applies the build-mode table of the design. graphMode and
// graphLimit are the values stored in BuildMeta (empty and 0 when unset);
// envLimit is the parsed BSKG_SAMPLE_LIMIT (0 when unset).
func DecideBuildMode(graphMode string, graphLimit, envLimit int) (Decision, error) {
	_ = graphLimit // a changed limit is handled by the job records (queueLimit)
	switch {
	case graphMode == ModeFull && envLimit > 0:
		return Decision{}, ErrFullGraphSample
	case envLimit > 0:
		return Decision{Mode: ModeSample, Limit: envLimit}, nil
	default:
		return Decision{Mode: ModeFull}, nil
	}
}

// BuildMeta is the stored build metadata.
type BuildMeta struct {
	Mode  string
	Limit int
	Found bool // false when no BuildMeta node exists
}

const (
	cypherReadBuildMeta = `OPTIONAL MATCH (b:BuildMeta {id: 'build'})
RETURN b IS NOT NULL AS found, b.buildMode AS mode, b.sampleLimit AS limit`
	cypherWriteBuildMode = `MERGE (b:BuildMeta {id: 'build'})
SET b.buildMode = $mode, b.sampleLimit = $limit`
)

// ReadBuildMeta reads the build mode and sample limit.
func ReadBuildMeta(ctx context.Context, g *graph.Client) (BuildMeta, error) {
	v, err := g.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, cypherReadBuildMeta, nil)
		if err != nil {
			return nil, err
		}
		rec, err := r.Single(ctx)
		if err != nil {
			return nil, err
		}
		m := rec.AsMap()
		bm := BuildMeta{}
		bm.Found, _ = m["found"].(bool)
		bm.Mode, _ = m["mode"].(string)
		if n, ok := m["limit"].(int64); ok {
			bm.Limit = int(n)
		}
		return bm, nil
	})
	if err != nil {
		return BuildMeta{}, err
	}
	return v.(BuildMeta), nil
}

// WriteBuildMode stores the build mode and sample limit.
func WriteBuildMode(ctx context.Context, g *graph.Client, d Decision) error {
	_, err := g.WriteRetry(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, cypherWriteBuildMode, map[string]any{"mode": d.Mode, "limit": int64(d.Limit)})
		if err != nil {
			return nil, err
		}
		_, err = r.Consume(ctx)
		return nil, err
	})
	return err
}
