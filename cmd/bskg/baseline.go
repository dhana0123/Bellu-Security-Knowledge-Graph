package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/bellu/bskg/internal/baseline"
	"github.com/bellu/bskg/internal/config"
	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/httpx"
)

// runBaselineLoad implements `bskg baseline load`.
func runBaselineLoad(stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintf(stderr, "bskg: baseline load: %v\n", err)
		return 1
	}
	cfg, err := config.Load(config.ScopeCore, config.ScopeBaselineFetch, config.ScopeBaselineLoad)
	if err != nil {
		return fail(err)
	}
	log, err := config.NewJSONLogger(stderr, cfg.LogLevel)
	if err != nil {
		return fail(err)
	}
	m, err := baseline.LoadManifest(cfg.BaselineManifest)
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	f := &baseline.Fetcher{
		LocalDir: cfg.BaselineDir, CacheDir: cfg.BaselineCacheDir,
		Retry: httpx.DownloadPolicy, Clock: httpx.RealClock{}, Log: log,
	}
	if cfg.BaselineDir == "" {
		if cfg.BaselineBucket != "" {
			m.Bucket.Name = cfg.BaselineBucket
		}
		s, err := baseline.NewS3Store(ctx, cfg.AWSRegion)
		if err != nil {
			return fail(err)
		}
		f.Store = s
	}
	// The loader runs whole-graph statements that take minutes on the full
	// baseline, so it has its own client with a long query timeout.
	c, err := graph.New(graph.Params{URI: cfg.Neo4jURI, User: cfg.Neo4jUser, Password: cfg.Neo4jPassword.Value(), Timeout: baseline.LoadTimeout})
	if err != nil {
		return fail(fmt.Errorf("connect: %w", err))
	}
	defer c.Close(context.WithoutCancel(ctx))
	if err := c.Verify(ctx); err != nil {
		return fail(fmt.Errorf("connect: %w", err))
	}
	st, err := baseline.Load(ctx, baseline.LoadOptions{
		Manifest: m, Fetcher: f, Client: c, BatchSize: cfg.BaselineBatchSize, Log: log,
	})
	if err != nil {
		return fail(err)
	}
	fmt.Fprintf(stdout, "baseline loaded: run %s, commit %s\n", st.RunID, st.Commit)
	return 0
}
