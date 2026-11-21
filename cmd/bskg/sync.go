package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/bellu/bskg/internal/checkpoint"
	"github.com/bellu/bskg/internal/config"
	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/pipeline"
	"github.com/bellu/bskg/internal/worker"
)

// syncTimeout bounds one batch transaction.
const syncTimeout = 5 * time.Minute

// statusTimeout bounds `bskg sync status` (Requirement 8.11 style: answer
// within 5 s).
const statusTimeout = 5 * time.Second

// connect opens and verifies a Neo4j client.
func connect(ctx context.Context, cfg *config.Config, timeout time.Duration) (*graph.Client, error) {
	c, err := graph.New(graph.Params{URI: cfg.Neo4jURI, User: cfg.Neo4jUser, Password: cfg.Neo4jPassword.Value(), Timeout: timeout})
	if err != nil {
		return nil, err
	}
	if err := c.Verify(ctx); err != nil {
		c.Close(context.WithoutCancel(ctx))
		return nil, err
	}
	activeGraph.Store(c)
	return c, nil
}

// runSync implements `bskg sync`, `bskg sync status`, and `bskg sync purge-changes`.
func runSync(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "status":
			return runSyncStatus(args[1:], stdout, stderr)
		case "purge-changes":
			fmt.Fprintln(stderr, "bskg: sync purge-changes: not implemented yet")
			return 1
		default:
			fmt.Fprintf(stderr, "bskg: sync: unknown argument %q\n", args[0])
			return 2
		}
	}
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	srcName := fs.String("source", "", "source to sync, an adapter name such as cwe, nvd, or exploitdb (default: all enabled sources)")
	since := fs.String("since", "", "window start for this run, RFC 3339 timestamp")
	replay := fs.Bool("replay-dead-letter", false, "reprocess the dead letters of the source instead of fetching")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "bskg: sync: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	var sinceT time.Time
	if *since != "" {
		t, err := time.Parse(time.RFC3339, *since)
		if err != nil {
			fmt.Fprintf(stderr, "bskg: sync: --since must be an RFC 3339 timestamp: %v\n", err)
			return 2
		}
		sinceT = t.UTC()
	}
	cfg, err := config.Load(config.ScopeWorker)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: sync: %v\n", err)
		return 1
	}
	log, err := config.NewJSONLogger(stderr, cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: sync: %v\n", err)
		return 1
	}
	registerAdapters(cfg)

	explicit := *srcName != ""
	names := worker.OrderedSources(cfg.EnabledSources)
	if explicit {
		names = []string{*srcName}
	}
	if !explicit && (!sinceT.IsZero() || *replay) {
		fmt.Fprintln(stderr, "bskg: sync: --since and --replay-dead-letter need --source")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c, err := connect(ctx, cfg, syncTimeout)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: sync: connect: %v\n", err)
		return 1
	}
	defer c.Close(context.WithoutCancel(ctx))

	bm, err := checkpoint.ReadBuildMeta(ctx, c)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: sync: read build metadata: %v\n", err)
		return 1
	}
	dec, err := checkpoint.DecideBuildMode(bm.Mode, bm.Limit, cfg.SampleLimit)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: sync: %v\n", err)
		return 1
	}

	store := pipeline.NewGraphStore(c)
	code := 0
	for _, name := range names {
		ad, ok := pipeline.Default.Get(name)
		if !ok {
			if explicit {
				fmt.Fprintf(stderr, "bskg: sync: %s: no adapter is registered for this source yet\n", name)
				code = 1
			} else {
				fmt.Fprintf(stdout, "%s: skipped, no adapter registered\n", name)
			}
			continue
		}
		res, err := pipeline.Run(ctx, store, ad, pipeline.Options{
			SampleLimit: dec.Limit, SampleOrder: sampleOrder(dec.Limit, cfg.SampleOrder), BatchSize: cfg.BatchSize, Since: sinceT,
			ReplayDeadLetters: *replay, Log: log,
		})
		switch {
		case errors.Is(err, checkpoint.ErrLocked):
			fmt.Fprintf(stderr, "bskg: sync: %s: a Sync_Run is already active for this source\n", name)
			code = 1
		case err != nil:
			fmt.Fprintf(stderr, "bskg: sync: %v\n", err)
			code = 1
		default:
			printRun(stdout, name, res)
		}
	}
	return code
}

func printRun(w io.Writer, name string, r pipeline.Result) {
	c := r.Counters
	fmt.Fprintf(w, "%s: %s run=%s fetched=%d created=%d updated=%d unchanged=%d skipped=%d failed=%d\n",
		name, r.Status, r.RunID, c.Fetched, c.Created, c.Updated, c.Unchanged, c.Skipped, c.Failed)
}

// runSyncStatus implements `bskg sync status`.
func runSyncStatus(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintf(stderr, "bskg: sync status: unexpected argument %q\n", args[0])
		return 2
	}
	cfg, err := config.Load(config.ScopeWorker)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: sync status: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), statusTimeout)
	defer cancel()
	c, err := connect(ctx, cfg, statusTimeout)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: sync status: connect: %v\n", err)
		return 1
	}
	defer c.Close(context.WithoutCancel(ctx))
	rows, err := checkpoint.ReadStatus(ctx, c, cfg.EnabledSources)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: sync status: %v\n", err)
		return 1
	}
	bm, err := checkpoint.ReadBuildMeta(ctx, c)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: sync status: %v\n", err)
		return 1
	}
	mode := bm.Mode
	if mode == "" {
		mode = "unset"
	}
	fmt.Fprintf(stdout, "buildMode: %s\n", mode)
	writeStatusTable(stdout, rows)
	return 0
}

func writeStatusTable(w io.Writer, rows []checkpoint.SourceStatus) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE\tLAST STATUS\tLAST SUCCESS\tPROGRESS\tDEAD LETTERS\tWATERMARK\tVERSION\tERROR")
	for _, s := range rows {
		last := s.LastStatus
		if last == "" {
			last = "never run"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", s.Source, last, ts(s.LastSuccess),
			progress(s), s.DeadLetters, ts(s.Checkpoint.Watermark), dash(s.Checkpoint.Version), dash(s.LastError))
	}
	tw.Flush()
}

func progress(s checkpoint.SourceStatus) string {
	if s.LastStatus == "" {
		return "-"
	}
	step := dash(s.Step)
	if s.Total > 0 {
		return fmt.Sprintf("%s %d/%d", step, s.Processed, s.Total)
	}
	return fmt.Sprintf("%s %d", step, s.Processed)
}

func ts(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// syncJob returns the worker job body for a source. Until its adapter is
// registered the job fails with worker.ErrNotImplemented.
func syncJob(reg *pipeline.Registry, store pipeline.Store, source string, batch int, log *slog.Logger) func(context.Context, worker.RunOptions) error {
	return func(ctx context.Context, o worker.RunOptions) error {
		ad, ok := reg.Get(source)
		if !ok {
			return fmt.Errorf("%s: %w", source, worker.ErrNotImplemented)
		}
		deadline := time.Now().Add(lockWait)
		for {
			_, err := pipeline.Run(ctx, store, ad, pipeline.Options{SampleLimit: o.Limit, SampleOrder: o.Order, BatchSize: batch, Log: log})
			// A lock left by a crashed process expires 10 minutes after its last
			// renewal, so the worker waits for it before it fails the job.
			if !errors.Is(err, checkpoint.ErrLocked) || time.Now().Add(lockPoll).After(deadline) {
				return err
			}
			log.Info("source is locked; waiting", "source", source)
			t := time.NewTimer(lockPoll)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		}
	}
}

// Lock wait of a worker job (variables so tests can shorten them).
var (
	lockWait = 11 * time.Minute
	lockPoll = 15 * time.Second
)

// sampleOrder returns the configured order for a sample and "first" otherwise.
func sampleOrder(limit int, order string) string {
	if limit > 0 && order != "" {
		return order
	}
	return "first"
}
