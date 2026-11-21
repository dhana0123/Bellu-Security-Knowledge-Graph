package validate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/bellu/bskg/internal/graph"
)

// DefaultOut is the report path used when Options.Out is empty.
const DefaultOut = "validation-report.json"

// Options control Execute.
type Options struct {
	// Out is the report file; empty means DefaultOut.
	Out string
	// QueryParams holds the parameters of the representative queries by name.
	// Queries without an entry are not run.
	QueryParams map[string]map[string]any
}

// Execute runs the validation against the graph, writes the report JSON and
// returns it. A non-nil error means validation could not be completed
// (connection, query infrastructure or write failure); a failed validation is
// reported through Report.Passed() with a nil error. If the report was built
// but could not be written, both are returned.
func Execute(ctx context.Context, c *graph.Client, opts Options) (Report, error) {
	rep, err := Run(ctx, c)
	if err != nil {
		return Report{}, err
	}
	if len(opts.QueryParams) > 0 {
		qs, err := RunQueries(ctx, c, opts.QueryParams)
		if err != nil {
			return Report{}, err
		}
		AttachQueries(&rep, qs)
	}
	out := opts.Out
	if out == "" {
		out = DefaultOut
	}
	if err := WriteReport(out, rep); err != nil {
		return rep, err
	}
	return rep, nil
}

// AttachQueries stores query results in the report and fails the report for
// every query that did not pass.
func AttachQueries(r *Report, qs []QueryResult) {
	r.Queries = qs
	for _, q := range qs {
		if !q.Passed {
			r.Failed = append(r.Failed, "query:"+q.Name)
		}
	}
	sort.Strings(r.Failed)
	r.Status = "passed"
	if len(r.Failed) > 0 {
		r.Status = "failed"
	}
}

// WriteReport writes the report as indented JSON.
func WriteReport(path string, r Report) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}
