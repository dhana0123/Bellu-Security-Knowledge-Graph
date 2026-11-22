package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"syscall"

	"github.com/bellu/bskg/internal/config"
	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/validate"
)

// validateExit maps an Execute outcome to the process exit code (Requirements
// 13.11 to 13.13): 0 passed, 1 failed validation or any error.
func validateExit(rep validate.Report, err error) int {
	if err != nil || !rep.Passed() {
		return 1
	}
	return 0
}

// printSummary writes the stdout summary.
func printSummary(w io.Writer, rep validate.Report, out string) {
	mode := rep.BuildMode
	if mode == "" {
		mode = "unset"
	}
	fmt.Fprintf(w, "validation %s\n", rep.Status)
	fmt.Fprintf(w, "build mode: %s\n", mode)
	fmt.Fprintf(w, "failed checks: %d\n", len(rep.Failed))
	for _, f := range rep.Failed {
		fmt.Fprintf(w, "  failed: %s\n", f)
	}
	for _, m := range rep.Warnings {
		fmt.Fprintf(w, "  warning: %s\n", m)
	}
	if rep.Smoke != nil {
		names := make([]string, 0, len(rep.Smoke.Counts))
		for k := range rep.Smoke.Counts {
			names = append(names, k)
		}
		sort.Strings(names)
		fmt.Fprintln(w, "smoke counts:")
		for _, k := range names {
			fmt.Fprintf(w, "  %s: %d\n", k, rep.Smoke.Counts[k])
		}
	}
	fmt.Fprintf(w, "report: %s\n", out)
}

// runValidate implements `bskg validate [--out file]`.
func runValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", validate.DefaultOut, "report file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(config.ScopeCore)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: validate: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c, err := graph.New(graph.Params{URI: cfg.Neo4jURI, User: cfg.Neo4jUser, Password: cfg.Neo4jPassword.Value(), Timeout: validate.QueryTimeout})
	if err != nil {
		fmt.Fprintf(stderr, "bskg: validate: connect: %v\n", err)
		return 1
	}
	defer c.Close(context.WithoutCancel(ctx))
	if err := c.Verify(ctx); err != nil {
		fmt.Fprintf(stderr, "bskg: validate: connect: %v\n", err)
		return 1
	}
	rep, err := validate.Execute(ctx, c, validate.Options{Out: *out})
	if err != nil {
		fmt.Fprintf(stderr, "bskg: validate: %v\n", err)
	}
	if err == nil {
		printSummary(stdout, rep, *out)
	}
	return validateExit(rep, err)
}
