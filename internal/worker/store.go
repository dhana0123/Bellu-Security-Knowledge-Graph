package worker

import (
	"context"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/graph"
)

const (
	cypherLoadJob = `MATCH (j:Job {name: $name})
RETURN j.queueState AS state, j.queueAttempts AS attempts, j.queueError AS err,
  j.queueMode AS mode, j.queueLimit AS limit, j.queueOrder AS sampleOrder`
	// queueStartedAt is set when attempt 1 starts; queueEndedAt when the job is
	// no longer running.
	cypherSaveJob = `MERGE (j:Job {name: $name})
SET j.queueState = $state, j.queueAttempts = $attempts, j.queueError = $err,
  j.queueMode = $mode, j.queueLimit = $limit, j.queueOrder = $sampleOrder, j.queueUpdatedAt = datetime(),
  j.queueStartedAt = CASE WHEN $attempts = 1 AND $state = 'running' THEN datetime() ELSE j.queueStartedAt END,
  j.queueEndedAt = CASE WHEN $state = 'running' THEN null ELSE datetime() END`
	cypherSetBuildState = `MERGE (b:BuildMeta {id: 'build'})
SET b.buildState = $state`
	cypherSetQueueComplete = `MERGE (b:BuildMeta {id: 'build'})
SET b.queueComplete = $complete`
)

// GraphStore persists queue state in Neo4j.
type GraphStore struct{ G *graph.Client }

func (s GraphStore) write(ctx context.Context, cypher string, params map[string]any) error {
	_, err := s.G.WriteRetry(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		_, err = r.Consume(ctx)
		return nil, err
	})
	return err
}

// LoadJob reads the queue properties of a job. A missing node or missing
// properties yield the zero record.
func (s GraphStore) LoadJob(ctx context.Context, name string) (JobRecord, error) {
	v, err := s.G.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, cypherLoadJob, map[string]any{"name": name})
		if err != nil {
			return nil, err
		}
		rec := JobRecord{}
		if r.Next(ctx) {
			m := r.Record().AsMap()
			rec.State, _ = m["state"].(string)
			if a, ok := m["attempts"].(int64); ok {
				rec.Attempts = int(a)
			}
			rec.Error, _ = m["err"].(string)
			rec.Mode, _ = m["mode"].(string)
			if l, ok := m["limit"].(int64); ok {
				rec.Limit = int(l)
			}
			rec.Order, _ = m["sampleOrder"].(string)
		}
		return rec, r.Err()
	})
	if err != nil {
		return JobRecord{}, err
	}
	return v.(JobRecord), nil
}

// SaveJob writes only the queue* properties of the job node.
func (s GraphStore) SaveJob(ctx context.Context, name string, rec JobRecord) error {
	return s.write(ctx, cypherSaveJob, map[string]any{
		"name": name, "state": rec.State, "attempts": int64(rec.Attempts), "err": rec.Error,
		"mode": rec.Mode, "limit": int64(rec.Limit), "sampleOrder": order(rec.Order),
	})
}

// SetBuildState writes BuildMeta.buildState.
func (s GraphStore) SetBuildState(ctx context.Context, state string) error {
	return s.write(ctx, cypherSetBuildState, map[string]any{"state": state})
}

// SetQueueComplete writes BuildMeta.queueComplete.
func (s GraphStore) SetQueueComplete(ctx context.Context, complete bool) error {
	return s.write(ctx, cypherSetQueueComplete, map[string]any{"complete": complete})
}
