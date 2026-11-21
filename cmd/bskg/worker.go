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
	"syscall"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/bellu/bskg/internal/checkpoint"
	"github.com/bellu/bskg/internal/config"
	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/migrate"
	"github.com/bellu/bskg/internal/pipeline"
	"github.com/bellu/bskg/internal/worker"
)

// runWorker implements `bskg worker [--healthcheck]`: it runs the build queue
// and then, in full mode, the daily schedule (Requirement 11).
func runWorker(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	health := fs.Bool("healthcheck", false, "exit 0 when the worker heartbeat is fresh")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *health {
		if err := worker.Healthy(worker.HeartbeatPath, time.Now(), worker.HeartbeatMaxAge); err != nil {
			fmt.Fprintf(stderr, "bskg: worker: %v\n", err)
			return 1
		}
		return 0
	}
	cfg, err := config.Load(config.ScopeWorker)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: worker: %v\n", err)
		return 1
	}
	log, err := config.NewJSONLogger(stderr, cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: worker: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go worker.KeepAlive(ctx, worker.HeartbeatPath, worker.HeartbeatInterval)

	c, err := graph.New(graph.Params{URI: cfg.Neo4jURI, User: cfg.Neo4jUser, Password: cfg.Neo4jPassword.Value(), Timeout: migrateTimeout})
	if err != nil {
		fmt.Fprintf(stderr, "bskg: worker: connect: %v\n", err)
		return 1
	}
	defer c.Close(context.WithoutCancel(ctx))
	if err := c.Verify(ctx); err != nil {
		fmt.Fprintf(stderr, "bskg: worker: connect: %v\n", err)
		return 1
	}

	// The build mode is decided from the graph and BSKG_SAMPLE_LIMIT. BuildMeta
	// can be read and written before the migrations ran (MERGE needs no
	// constraint), so this works on an empty volume.
	bm, err := checkpoint.ReadBuildMeta(ctx, c)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: worker: read build metadata: %v\n", err)
		return 1
	}
	dec, err := checkpoint.DecideBuildMode(bm.Mode, bm.Limit, cfg.SampleLimit)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: worker: %v\n", err)
		return 1
	}
	if err := checkpoint.WriteBuildMode(ctx, c, dec); err != nil {
		fmt.Fprintf(stderr, "bskg: worker: write build mode: %v\n", err)
		return 1
	}
	opts := worker.RunOptions{Mode: dec.Mode, Limit: dec.Limit, Order: "first"}
	if dec.Limit > 0 {
		opts.Order = cfg.SampleOrder // the order only matters for a sample
	}
	log.Info("worker starting", "buildMode", dec.Mode, "sampleLimit", dec.Limit, "sampleOrder", opts.Order)

	q := &worker.Queue{
		Jobs:  buildJobs(c, cfg, log),
		Store: worker.GraphStore{G: c},
		Opts:  opts,
		Log:   log,
	}
	out, err := q.Run(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return 0
		}
		fmt.Fprintf(stderr, "bskg: worker: %v\n", err)
		return 1
	}
	if !out.Complete {
		if out.StoppedAt == worker.JobMigrate {
			fmt.Fprintf(stderr, "bskg: worker: migrate failed: %v\n", out.Err)
			return 1
		}
		// Other jobs stop the queue but leave the worker running so that
		// `bskg sync status` and the API keep working.
		log.Error("build queue stopped; worker stays up", "job", out.StoppedAt, "error", out.Err.Error())
		<-ctx.Done()
		return 0
	}
	if dec.Mode == checkpoint.ModeSample {
		log.Info("sample build complete; no daily schedule in sample mode")
		<-ctx.Done()
		return 0
	}
	log.Info("build queue complete; starting the daily schedule", "time", cfg.NVDSyncTime)
	store := pipeline.NewGraphStore(c)
	runNow := missedSchedule(ctx, c, cfg, time.Now())
	err = worker.Daily(ctx, cfg.NVDSyncTime, runNow, func(ctx context.Context) error {
		return dailySync(ctx, pipeline.Default, store, cfg.EnabledSources, cfg.BatchSize, log)
	}, func(err error) { log.Warn("daily sync failed", "error", err.Error()) })
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "bskg: worker: %v\n", err)
		return 1
	}
	return 0
}

// buildJobs returns the build queue: migrate, cwe, nvd-catch-up, exploitdb,
// then each enabled and registered later source in worker.SourceJobs order.
// The job name is the adapter name (nvd: "nvd-catch-up").
func buildJobs(c *graph.Client, cfg *config.Config, log *slog.Logger) []worker.Job {
	registerAdapters(cfg)
	activeGraph.Store(c)
	store := pipeline.NewGraphStore(c)
	jobs := []worker.Job{
		{Name: worker.JobMigrate, BuildState: worker.StateMigrating, Run: func(ctx context.Context, _ worker.RunOptions) error {
			files, err := migrate.Embedded()
			if err != nil {
				return err
			}
			r := &migrate.Runner{Store: migrate.GraphStore{C: c}, Files: files, Owner: ulid.Make().String(), Log: log}
			_, err = r.Run(ctx)
			return err
		}},
	}
	return append(jobs, sourceJobs(pipeline.Default, store, cfg.EnabledSources, cfg.BatchSize, log)...)
}

// sourceJobs returns the queue jobs of the sources. The first three (cwe, nvd,
// exploitdb) are always listed. Another source is listed when it is enabled
// and its adapter is registered; an enabled source without an adapter is
// skipped with a warning.
func sourceJobs(reg *pipeline.Registry, store pipeline.Store, enabled []string, batch int, log *slog.Logger) []worker.Job {
	on := map[string]bool{}
	for _, n := range enabled {
		on[n] = true
	}
	var jobs []worker.Job
	for _, sj := range worker.SourceJobs {
		if !worker.IsCoreSource(sj.Source) {
			if !on[sj.Source] {
				continue
			}
			if _, ok := reg.Get(sj.Source); !ok {
				log.Warn("source is enabled but no adapter is registered; skipped", "source", sj.Source)
				continue
			}
		}
		jobs = append(jobs, worker.Job{
			Name: sj.Job, BuildState: sj.BuildState, ModeSpecific: sj.ModeSpecific,
			Run: syncJob(reg, store, sj.Source, batch, log),
		})
	}
	return jobs
}

// dailySync runs the enabled, registered sources in worker.SourceJobs order. Each run is
// independent: one failure does not stop the others (Requirement 3.10). It
// returns the joined errors.
func dailySync(ctx context.Context, reg *pipeline.Registry, store pipeline.Store, sources []string, batch int, log *slog.Logger) error {
	var errs []error
	for _, name := range worker.OrderedSources(sources) {
		ad, ok := reg.Get(name)
		if !ok {
			log.Warn("daily sync: source is enabled but no adapter is registered; skipped", "source", name)
			continue
		}
		if _, err := pipeline.Run(ctx, store, ad, pipeline.Options{BatchSize: batch, Log: log}); err != nil {
			log.Warn("daily sync failed", "source", name, "error", err.Error())
			errs = append(errs, err)
		}
		if ctx.Err() != nil {
			break
		}
	}
	return errors.Join(errs...)
}

// missedSchedule reports whether a scheduled run time passed without a
// successful run of an enabled, registered source.
func missedSchedule(ctx context.Context, c *graph.Client, cfg *config.Config, now time.Time) bool {
	var names []string
	for _, n := range cfg.EnabledSources {
		if _, ok := pipeline.Default.Get(n); ok {
			names = append(names, n)
		}
	}
	rows, err := checkpoint.ReadStatus(ctx, c, names)
	if err != nil {
		return false
	}
	for _, r := range rows {
		if m, err := worker.Missed(now, cfg.NVDSyncTime, r.LastSuccess); err == nil && m {
			return true
		}
	}
	return false
}
