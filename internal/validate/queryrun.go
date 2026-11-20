package validate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
)

// RunQueries executes the nine representative queries in READ transactions
// with a 30 s timeout each and compares them with the recorded results. The
// client must have been created with a timeout of at least QueryTimeout.
// Every query runs even when an earlier one fails (Requirement 6.1).
func RunQueries(ctx context.Context, c *graph.Client, p Profile) ([]QueryResult, error) {
	if c.Timeout() < QueryTimeout {
		return nil, fmt.Errorf("validate: graph client timeout %s is below the %s query timeout", c.Timeout(), QueryTimeout)
	}
	qs, err := Queries()
	if err != nil {
		return nil, err
	}
	out := make([]QueryResult, 0, len(qs))
	for _, q := range qs {
		tbl, qerr := RunQuery(ctx, c, p, q)
		r, err := EvaluateQuery(p, q.Name, tbl, qerr)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// RunQuery executes one query and returns its table.
func RunQuery(ctx context.Context, c *graph.Client, p Profile, q Query) (Table, error) {
	params, err := QueryParams(p, q.Name)
	if err != nil {
		return Table{}, err
	}
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

// UpdateExpected runs every query and writes the observed results as the
// expected files of the profile under dir (the internal/validate directory).
// The CLI flag --update-expected (task 6.4) calls it.
func UpdateExpected(ctx context.Context, c *graph.Client, p Profile, dir string) error {
	if c.Timeout() < QueryTimeout {
		return fmt.Errorf("validate: graph client timeout %s is below the %s query timeout", c.Timeout(), QueryTimeout)
	}
	qs, err := Queries()
	if err != nil {
		return err
	}
	for _, q := range qs {
		t, err := RunQuery(ctx, c, p, q)
		if err != nil {
			return fmt.Errorf("query %s: %w", q.Name, err)
		}
		b, err := EncodeExpected(p, t)
		if err != nil {
			return err
		}
		path := filepath.Join(dir, ExpectedFileName(p, q.Name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			return err
		}
	}
	return nil
}
