package checkpoint

import (
	"context"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
)

// Checkpoint is the stored per-source cursor. Zero values mean unset.
type Checkpoint struct {
	Watermark time.Time
	Resume    string
	Version   string
	Found     bool
}

const (
	cypherReadCheckpoint = `OPTIONAL MATCH (c:Checkpoint {source: $source})
RETURN c IS NOT NULL AS found, c.watermark AS watermark, c.resume AS resume, c.version AS version`

	// The watermark is only set when given; resume is always replaced.
	cypherWriteCursor = `MERGE (c:Checkpoint {source: $source})
SET c.resume = $resume, c.updatedAt = datetime(),
    c.watermark = coalesce($watermark, c.watermark)`

	cypherWriteVersion = `MERGE (c:Checkpoint {source: $source})
SET c.version = $version, c.updatedAt = datetime()`

	// Raises the watermark to w when w is later than the stored value.
	cypherRaiseWatermark = `MERGE (c:Checkpoint {source: $source})
SET c.watermark = CASE WHEN c.watermark IS NULL OR c.watermark < $watermark
                       THEN $watermark ELSE c.watermark END,
    c.updatedAt = datetime()`
)

func runTx(ctx context.Context, tx neo4j.ManagedTransaction, cypher string, params map[string]any) error {
	r, err := tx.Run(ctx, cypher, params)
	if err != nil {
		return err
	}
	_, err = r.Consume(ctx)
	return err
}

// ReadCheckpoint reads the checkpoint of a source (Found is false if none).
func ReadCheckpoint(ctx context.Context, g *graph.Client, source string) (Checkpoint, error) {
	v, err := g.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, cypherReadCheckpoint, map[string]any{"source": source})
		if err != nil {
			return nil, err
		}
		rec, err := r.Single(ctx)
		if err != nil {
			return nil, err
		}
		m := rec.AsMap()
		var cp Checkpoint
		cp.Found, _ = m["found"].(bool)
		cp.Watermark, _ = m["watermark"].(time.Time)
		cp.Resume, _ = m["resume"].(string)
		cp.Version, _ = m["version"].(string)
		return cp, nil
	})
	if err != nil {
		return Checkpoint{}, err
	}
	return v.(Checkpoint), nil
}

// WriteCursor stores the cursor of the last committed record inside the
// caller's batch transaction. A zero watermark leaves the stored one as is.
// The pipeline must not call it when SampleLimit > 0.
func WriteCursor(ctx context.Context, tx neo4j.ManagedTransaction, source, resume string, watermark time.Time) error {
	var w any
	if !watermark.IsZero() {
		w = watermark
	}
	return runTx(ctx, tx, cypherWriteCursor, map[string]any{"source": source, "resume": resume, "watermark": w})
}

// RaiseWatermark sets the watermark to w if w is later than the stored one.
func RaiseWatermark(ctx context.Context, tx neo4j.ManagedTransaction, source string, w time.Time) error {
	return runTx(ctx, tx, cypherRaiseWatermark, map[string]any{"source": source, "watermark": w})
}

// WriteVersion stores the snapshot version after a successful run.
func WriteVersion(ctx context.Context, tx neo4j.ManagedTransaction, source, version string) error {
	return runTx(ctx, tx, cypherWriteVersion, map[string]any{"source": source, "version": version})
}
