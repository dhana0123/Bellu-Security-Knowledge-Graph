package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bellu/bskg/internal/config"
	"github.com/bellu/bskg/internal/maint"
)

// resetCheckTimeout bounds the active-run check; the refusal must come within 5 s.
const resetCheckTimeout = 5 * time.Second

// runReset implements `bskg reset --confirm`.
func runReset(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("reset", flag.ContinueOnError)
	fs.SetOutput(stderr)
	confirm := fs.Bool("confirm", false, "delete the graph content; schema, migrations, and API keys stay")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "bskg: reset: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if !*confirm {
		fmt.Fprintf(stderr, "bskg: reset: %v\n", maint.ErrNotConfirmed)
		return 1
	}
	cfg, err := config.Load(config.ScopeCore)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: reset: %v\n", err)
		return 1
	}
	log, err := config.NewJSONLogger(stderr, cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: reset: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cctx, cancel := context.WithTimeout(ctx, resetCheckTimeout)
	c, err := connect(cctx, cfg, syncTimeout)
	cancel()
	if err != nil {
		fmt.Fprintf(stderr, "bskg: reset: connect: %v\n", err)
		return 1
	}
	defer c.Close(context.WithoutCancel(ctx))

	res, err := maint.Reset(ctx, maint.GraphStore{G: c}, true)
	if err != nil {
		log.Error("reset", "outcome", "failed", "nodesDeleted", res.Nodes, "relationshipsDeleted", res.Relationships)
		fmt.Fprintf(stderr, "bskg: reset: %v\n", err)
		return 1
	}
	log.Info("reset", "outcome", "ok", "nodesDeleted", res.Nodes, "relationshipsDeleted", res.Relationships)
	fmt.Fprintf(stdout, "deleted %d nodes and %d relationships\n", res.Nodes, res.Relationships)
	return 0
}
