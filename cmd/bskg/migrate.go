package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/config"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/graph"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/migrate"
)

// migrateTimeout bounds one statement, including db.awaitIndexes(300).
const migrateTimeout = 6 * time.Minute

// runMigrate implements `bskg migrate`.
func runMigrate(stdout, stderr io.Writer) int {
	cfg, err := config.Load(config.ScopeCore)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: migrate: %v\n", err)
		return 1
	}
	log, err := config.NewJSONLogger(stderr, cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: migrate: %v\n", err)
		return 1
	}
	files, err := migrate.Embedded()
	if err != nil {
		fmt.Fprintf(stderr, "bskg: migrate: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	c, err := graph.New(graph.Params{URI: cfg.Neo4jURI, User: cfg.Neo4jUser, Password: cfg.Neo4jPassword.Value(), Timeout: migrateTimeout})
	if err != nil {
		fmt.Fprintf(stderr, "bskg: migrate: connect: %v\n", err)
		return 1
	}
	defer c.Close(context.WithoutCancel(ctx))
	if err := c.Verify(ctx); err != nil {
		fmt.Fprintf(stderr, "bskg: migrate: connect: %v\n", err)
		return 1
	}
	r := &migrate.Runner{Store: migrate.GraphStore{C: c}, Files: files, Owner: ulid.Make().String(), Log: log}
	res, err := r.Run(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: migrate: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "applied %d migrations\n", len(res.Applied))
	return 0
}
