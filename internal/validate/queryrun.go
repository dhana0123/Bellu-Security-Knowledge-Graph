package validate

import (
	"context"
	"fmt"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
)

// RunQueries executes the representative queries in READ transactions with a
// 30 s timeout each. params holds the parameters of each query by name; a
// query without an entry is not run. The client must have been created with a
// timeout of at least QueryTimeout. Every query runs even when an earlier one
// fails (Requirement 19).
func RunQueries(ctx context.Context, c *graph.Client, params map[string]map[string]any) ([]QueryResult, error) {
	if c.Timeout() < QueryTimeout {
		return nil, fmt.Errorf("validate: graph client timeout %s is below the %s query timeout", c.Timeout(), QueryTimeout)
	}
	qs, err := Queries()
	if err != nil {
		return nil, err
	}
	out := make([]QueryResult, 0, len(qs))
	for _, q := range qs {
		p, ok := params[q.Name]
		if !ok {
			continue
		}
		tbl, qerr := RunQuery(ctx, c, q, p)
		res := QueryResult{Name: q.Name, Passed: qerr == nil, Rows: len(tbl.Rows)}
		if qerr != nil {
			res.Message = "query failed: " + qerr.Error()
		}
		out = append(out, res)
	}
	return out, nil
}

// RunQuery executes one query with params and returns its table.
func RunQuery(ctx context.Context, c *graph.Client, q Query, params map[string]any) (Table, error) {
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	res, err := c.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, q.Cypher, params)
		if err != nil {
			return nil, err
		}
		recs, err := r.Collect(ctx)
		if err != nil {
			return nil, err
		}
		t := Table{Rows: [][]any{}}
		if keys, kerr := r.Keys(); kerr == nil {
			t.Columns = keys
		}
		for _, rec := range recs {
			row := make([]any, len(rec.Values))
			for i, v := range rec.Values {
				row[i] = jsonValue(v)
			}
			t.Rows = append(t.Rows, row)
		}
		return t, nil
	})
	if err != nil {
		return Table{}, err
	}
	return res.(Table), nil
}

// jsonValue converts driver values that JSON cannot encode as expected.
func jsonValue(v any) any {
	switch x := v.(type) {
	case neo4j.Date:
		return x.Time().Format("2006-01-02")
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = jsonValue(x[i])
		}
		return out
	default:
		return v
	}
}
