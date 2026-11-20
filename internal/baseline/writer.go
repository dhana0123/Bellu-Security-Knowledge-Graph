package baseline

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
)

// Batch size limits (Requirement 4.2).
const (
	MinBatchSize = 1
	MaxBatchSize = 10000
)

// ErrBatchSize is returned for a batch size outside 1 to 10000.
var ErrBatchSize = errors.New("baseline batch size must be between 1 and 10000")

// RowMapper turns a CSV row into the map bound as one element of $rows.
// Returning (nil, nil) skips the row (it still counts toward progress).
type RowMapper func(Row) (map[string]any, error)

// StepSpec describes one UNWIND-batched statement.
//
// Cypher must be constant text that starts from `UNWIND $rows AS row`. Extra
// parameters (such as $runID, $at, $ref, $run) are bound unchanged for every
// batch. The statement may return one row with an integer column "matched",
// the number of rows whose MATCH found every endpoint; the writer then
// reports the remainder as missing endpoints.
type StepSpec struct {
	Name   string
	Cypher string
	Params map[string]any
	Map    RowMapper
}

// StepResult counts what a step wrote.
type StepResult struct {
	Rows    int64 // CSV rows read
	Sent    int64 // rows sent to Neo4j (after skips)
	Matched int64 // rows reported matched (only when the Cypher returns it)
	Missing int64 // Sent - Matched, when the Cypher returns "matched"
}

// Writer streams CSV rows into Neo4j in batches. Job progress is updated in the
// same transaction as each batch.
type Writer struct {
	C         *graph.Client
	BatchSize int
}

// ValidateBatchSize checks the 1 to 10000 range.
func ValidateBatchSize(n int) error {
	if n < MinBatchSize || n > MaxBatchSize {
		return fmt.Errorf("%w (got %d)", ErrBatchSize, n)
	}
	return nil
}

// RunStep reads path and applies spec batch by batch. total is the expected
// row count for progress (use CountRows). The step restarts from row 0, which
// is safe because every step is idempotent.
func (w Writer) RunStep(ctx context.Context, path string, total int64, spec StepSpec, required ...string) (StepResult, error) {
	var res StepResult
	if err := ValidateBatchSize(w.BatchSize); err != nil {
		return res, err
	}
	if spec.Map == nil {
		return res, errors.New("step has no row mapper")
	}
	r, err := OpenCSV(path, required...)
	if err != nil {
		return res, err
	}
	defer r.Close()
	if err := (Jobs{C: w.C}).Begin(ctx, spec.Name, total); err != nil {
		return res, fmt.Errorf("step %s: %w", spec.Name, err)
	}
	for {
		rows, err := r.NextBatch(w.BatchSize)
		if err != nil && !errors.Is(err, io.EOF) {
			return res, fmt.Errorf("step %s: %w", spec.Name, err)
		}
		if len(rows) == 0 {
			break
		}
		mapped := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			m, merr := spec.Map(row)
			if merr != nil {
				return res, fmt.Errorf("step %s: %w", spec.Name, merr)
			}
			if m != nil {
				mapped = append(mapped, m)
			}
		}
		done := res.Rows + int64(len(rows))
		matched, hasMatched, werr := w.writeBatch(ctx, spec, mapped, done, total)
		if werr != nil {
			return res, fmt.Errorf("step %s: %w", spec.Name, werr)
		}
		res.Rows = done
		res.Sent += int64(len(mapped))
		if hasMatched {
			res.Matched += matched
			res.Missing += int64(len(mapped)) - matched
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return res, nil
}

func (w Writer) writeBatch(ctx context.Context, spec StepSpec, rows []map[string]any, done, total int64) (int64, bool, error) {
	type out struct {
		matched int64
		has     bool
	}
	v, err := w.C.WriteRetry(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		params := make(map[string]any, len(spec.Params)+1)
		for k, val := range spec.Params {
			params[k] = val
		}
		params["rows"] = rows
		var o out
		if len(rows) > 0 {
			res, err := tx.Run(ctx, spec.Cypher, params)
			if err != nil {
				return nil, err
			}
			recs, err := res.Collect(ctx)
			if err != nil {
				return nil, err
			}
			if len(recs) == 1 {
				if m, ok := recs[0].Get("matched"); ok {
					if n, ok := m.(int64); ok {
						o = out{matched: n, has: true}
					}
				}
			}
		}
		err := runJob(ctx, tx, cypherJobProgress, map[string]any{
			"name": JobName, "step": spec.Name, "done": done, "total": total,
		})
		return o, err
	})
	if err != nil {
		return 0, false, err
	}
	o := v.(out)
	return o.matched, o.has, nil
}
