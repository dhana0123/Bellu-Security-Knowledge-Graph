package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bellu/bskg/internal/apikey"
	"github.com/bellu/bskg/internal/config"
	"github.com/bellu/bskg/internal/graph"
)

const apikeyUsage = "usage: bskg apikey create <name> | bskg apikey revoke <name>\n"

// runAPIKey implements `bskg apikey create|revoke <name>`. The new key is
// printed once on stdout and never stored in plaintext.
func runAPIKey(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || (args[0] != "create" && args[0] != "revoke") {
		fmt.Fprint(stderr, apikeyUsage)
		return 2
	}
	action, name := args[0], args[1]
	if err := apikey.ValidateName(name); err != nil {
		fmt.Fprintf(stderr, "bskg: apikey: %v\n", err)
		return 1
	}
	cfg, err := config.Load(config.ScopeCore)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: apikey: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	g, err := graph.New(graph.Params{URI: cfg.Neo4jURI, User: cfg.Neo4jUser, Password: cfg.Neo4jPassword.Value(), Timeout: 30 * time.Second})
	if err != nil {
		fmt.Fprintf(stderr, "bskg: apikey: connect: %v\n", err)
		return 1
	}
	defer g.Close(context.WithoutCancel(ctx))
	if err := g.Verify(ctx); err != nil {
		fmt.Fprintf(stderr, "bskg: apikey: connect: %v\n", err)
		return 1
	}
	store := apikey.NewStore(g, nil)
	switch action {
	case "create":
		key, err := store.Create(ctx, name)
		if err != nil {
			fmt.Fprintf(stderr, "bskg: apikey: %v\n", describeKeyErr(err))
			return 1
		}
		fmt.Fprintln(stdout, key)
		fmt.Fprintln(stderr, "Store this key now. It cannot be shown again.")
	default:
		if err := store.Revoke(ctx, name); err != nil {
			fmt.Fprintf(stderr, "bskg: apikey: %v\n", describeKeyErr(err))
			return 1
		}
		fmt.Fprintf(stdout, "revoked %s\n", name)
	}
	return 0
}

func describeKeyErr(err error) error {
	switch {
	case errors.Is(err, apikey.ErrInvalidName), errors.Is(err, apikey.ErrDuplicateName), errors.Is(err, apikey.ErrNotFound):
		return err
	}
	return fmt.Errorf("graph store error: %w", err)
}
