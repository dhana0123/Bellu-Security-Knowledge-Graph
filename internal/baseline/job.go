package baseline

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
)

// JobName is the (:Job) key of the baseline load.
const JobName = "baseline-load"

// Constant Cypher for job progress.
const (
	cypherJobBegin = `MERGE (j:Job {name: $name})
SET j.currentStep = $step, j.rowsDone = 0, j.rowsTotal = $total`
	cypherJobProgress = `MERGE (j:Job {name: $name})
SET j.currentStep = $step, j.rowsDone = $done, j.rowsTotal = $total`
	cypherJobComplete = `MERGE (j:Job {name: $name})
SET j.lastCompletedStep = $step, j.currentStep = null, j.rowsDone = j.rowsTotal`
	cypherJobRead = `OPTIONAL MATCH (j:Job {name: $name})
RETURN j.lastCompletedStep AS last, j.currentStep AS cur, j.rowsDone AS done, j.rowsTotal AS total`
)

// Progress is the stored state of the baseline load job.
type Progress struct {
	LastCompletedStep string
	CurrentStep       string
	RowsDone          int64
	RowsTotal         int64
}

// Jobs reads and writes the baseline-load Job node.
type Jobs struct{ C *graph.Client }

func runJob(ctx context.Context, tx neo4j.ManagedTransaction, q string, p map[string]any) error {
	res, err := tx.Run(ctx, q, p)
	if err != nil {
		return err
	}
	_, err = res.Consume(ctx)
	return err
}

// Begin records the start (or restart from row 0) of step.
func (j Jobs) Begin(ctx context.Context, step string, total int64) error {
	_, err := j.C.WriteRetry(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		return nil, runJob(ctx, tx, cypherJobBegin, map[string]any{"name": JobName, "step": step, "total": total})
	})
	return err
}

// Complete records step as the last completed step.
func (j Jobs) Complete(ctx context.Context, step string) error {
	_, err := j.C.WriteRetry(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		return nil, runJob(ctx, tx, cypherJobComplete, map[string]any{"name": JobName, "step": step})
	})
	return err
}

// Read returns the stored progress; the zero Progress means no job yet.
func (j Jobs) Read(ctx context.Context) (Progress, error) {
	v, err := j.C.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypherJobRead, map[string]any{"name": JobName})
		if err != nil {
			return nil, err
		}
		rec, err := res.Single(ctx)
		if err != nil {
			return nil, err
		}
		var p Progress
		if s, ok := rec.Values[0].(string); ok {
			p.LastCompletedStep = s
		}
		if s, ok := rec.Values[1].(string); ok {
			p.CurrentStep = s
		}
		if n, ok := rec.Values[2].(int64); ok {
			p.RowsDone = n
		}
		if n, ok := rec.Values[3].(int64); ok {
			p.RowsTotal = n
		}
		return p, nil
	})
	if err != nil {
		return Progress{}, fmt.Errorf("read baseline job: %w", err)
	}
	return v.(Progress), nil
}
