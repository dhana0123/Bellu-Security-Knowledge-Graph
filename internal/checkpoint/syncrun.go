package checkpoint

import (
	"context"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/change"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/graph"
)

// SyncRun statuses.
const (
	StatusRunning             = "running"
	StatusSucceeded           = "succeeded"
	StatusSucceededWithErrors = "succeeded_with_errors"
	StatusFailed              = "failed"
)

// MaxWarningIDs caps the warning ids stored on a SyncRun.
const MaxWarningIDs = 100

// Counters are the SyncRun record counters. The pipeline accumulates them in
// memory and writes absolute values.
type Counters struct {
	Fetched       int64
	Created       int64
	Updated       int64
	Unchanged     int64
	Skipped       int64
	Failed        int64
	MissingFields int64
	Unresolved    int64
	Warnings      int64
	WarningIDs    []string // first MaxWarningIDs ids
}

// AddWarning counts a warning and keeps the id while under the cap.
func (c *Counters) AddWarning(id string) {
	c.Warnings++
	if len(c.WarningIDs) < MaxWarningIDs {
		c.WarningIDs = append(c.WarningIDs, id)
	}
}

// Progress is the step and record progress. Total is 0 when unknown.
type Progress struct {
	Step      string
	Processed int64
	Total     int64
}

const (
	cypherStartRun = `CREATE (r:SyncRun {id: $id, source: $source, startedAt: $startedAt, status: 'running',
  fetched: 0, created: 0, updated: 0, unchanged: 0, skipped: 0, failed: 0,
  missingFields: 0, unresolved: 0, warnings: 0, warningIds: [], step: '', processed: 0})`

	cypherUpdateRun = `MATCH (r:SyncRun {id: $id})
SET r.fetched = $fetched, r.created = $created, r.updated = $updated, r.unchanged = $unchanged,
    r.skipped = $skipped, r.failed = $failed, r.missingFields = $missingFields,
    r.unresolved = $unresolved, r.warnings = $warnings, r.warningIds = $warningIds,
    r.step = $step, r.processed = $processed, r.total = $total`

	cypherFinishRun = `MATCH (r:SyncRun {id: $id})
SET r.status = $status, r.endedAt = $endedAt, r.error = $error`
)

// NewRunID returns a ULID for a SyncRun.
func NewRunID(t time.Time) (string, error) { return change.NewID(t) }

// StartRun creates a SyncRun in status running.
func StartRun(ctx context.Context, g *graph.Client, id, source string, at time.Time) error {
	_, err := g.WriteRetry(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		return nil, runTx(ctx, tx, cypherStartRun, map[string]any{"id": id, "source": source, "startedAt": at})
	})
	return err
}

// UpdateRun writes counters and progress inside the caller's batch transaction.
func UpdateRun(ctx context.Context, tx neo4j.ManagedTransaction, id string, c Counters, p Progress) error {
	ids := c.WarningIDs
	if ids == nil {
		ids = []string{}
	}
	if len(ids) > MaxWarningIDs {
		ids = ids[:MaxWarningIDs]
	}
	var total any
	if p.Total > 0 {
		total = p.Total
	}
	return runTx(ctx, tx, cypherUpdateRun, map[string]any{
		"id": id, "fetched": c.Fetched, "created": c.Created, "updated": c.Updated,
		"unchanged": c.Unchanged, "skipped": c.Skipped, "failed": c.Failed,
		"missingFields": c.MissingFields, "unresolved": c.Unresolved,
		"warnings": c.Warnings, "warningIds": ids,
		"step": p.Step, "processed": p.Processed, "total": total,
	})
}

// FinishRun sets the final status. errMsg may be empty.
func FinishRun(ctx context.Context, g *graph.Client, id, status, errMsg string, at time.Time) error {
	var e any
	if errMsg != "" {
		e = errMsg
	}
	_, err := g.WriteRetry(context.WithoutCancel(ctx), func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		return nil, runTx(ctx, tx, cypherFinishRun, map[string]any{"id": id, "status": status, "endedAt": at, "error": e})
	})
	return err
}

// FinalStatus picks the end status of a run that was not aborted.
func FinalStatus(c Counters) string {
	if c.Failed > 0 {
		return StatusSucceededWithErrors
	}
	return StatusSucceeded
}
