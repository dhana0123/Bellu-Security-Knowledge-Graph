package validate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/bellu/bskg/internal/graph"
)

// ProfileIntegrity runs the schema, duplicate, endpoint and REJECT checks
// only. It is the profile operators run after NVD data exists.
const ProfileIntegrity Profile = "integrity"

// DefaultOut is the report path used when Options.Out is empty.
const DefaultOut = "validation-report.json"

// Options control Execute.
type Options struct {
	// Out is the report file; empty means DefaultOut.
	Out string
	// UpdateExpected rewrites the representative-query expected files under
	// ExpectedDir from the live graph before the queries are evaluated.
	// It is not allowed for the integrity profile.
	UpdateExpected bool
	// ExpectedDir is the internal/validate source directory (default
	// "internal/validate").
	ExpectedDir string
}

// Execute runs a validation profile against the graph, writes the report
// JSON and returns it. The client needs Timeout >= QueryTimeout for the
// baseline and fixture profiles. A non-nil error means validation could not
// be completed (connection, query infrastructure or write failure); a failed
// validation is reported through Report.Passed() with a nil error.
// If the report was built but could not be written, both are returned.
func Execute(ctx context.Context, c *graph.Client, profile Profile, opts Options) (Report, error) {
	var exp *Expected
	if profile != ProfileIntegrity {
		e, err := LoadExpected(profile) // errors for unknown profiles
		if err != nil {
			return Report{}, err
		}
		exp = &e
	}
	if opts.UpdateExpected && profile == ProfileIntegrity {
		return Report{}, fmt.Errorf("--update-expected does not apply to the %q profile", profile)
	}
	disc, err := LoadDiscrepancies()
	if err != nil {
		return Report{}, err
	}
	if opts.UpdateExpected {
		dir := opts.ExpectedDir
		if dir == "" {
			dir = "internal/validate"
		}
		if err := UpdateExpected(ctx, c, profile, dir); err != nil {
			return Report{}, fmt.Errorf("update expected: %w", err)
		}
	}
	rep, err := Run(ctx, c, string(profile), exp, disc)
	if err != nil {
		return Report{}, err
	}
	if profile != ProfileIntegrity {
		qs, err := RunQueries(ctx, c, profile)
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
