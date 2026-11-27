package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/api"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/apikey"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/config"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/graph"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/migrate"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/ui"
)

const shutdownTimeout = 15 * time.Second

// runServe implements `bskg serve [--healthcheck]`.
func runServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	health := fs.Bool("healthcheck", false, "exit 0 when the local /healthz answers 200")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "bskg: serve: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *health {
		if err := healthcheck(os.Getenv); err != nil {
			fmt.Fprintf(stderr, "bskg: serve: %v\n", err)
			return 1
		}
		return 0
	}
	cfg, err := config.Load(config.ScopeCore, config.ScopeServe, config.ScopeSync)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: serve: %v\n", err)
		return 1
	}
	log, err := config.NewJSONLogger(stderr, cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(stderr, "bskg: serve: %v\n", err)
		return 1
	}
	files, err := migrate.Embedded()
	if err != nil || len(files) == 0 {
		fmt.Fprintf(stderr, "bskg: serve: embedded migrations: %v\n", err)
		return 1
	}
	want := files[len(files)-1].Version

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The client timeout caps every transaction, so it must cover the
	// statistics computation; request handlers use their own, shorter context.
	clientTimeout := max(cfg.QueryTimeout, cfg.StatsTimeout)
	g, err := graph.New(graph.Params{URI: cfg.Neo4jURI, User: cfg.Neo4jUser, Password: cfg.Neo4jPassword.Value(), Timeout: clientTimeout})
	if err != nil {
		fmt.Fprintf(stderr, "bskg: serve: connect: %v\n", err)
		return 1
	}
	defer g.Close(context.WithoutCancel(ctx))

	q := api.ReadQueries(g)
	// The schema phase follows the applied migrations (V1xx is phase 2, V2xx
	// phase 3). It is read once here and refreshed with the migration cache.
	phase := api.MigrationPhase(q)
	startPhase := 1
	pctx, pcancel := context.WithTimeout(ctx, 10*time.Second)
	if v, err := phase(pctx); err == nil {
		startPhase = v
	} else {
		log.Warn("schema phase unavailable at start; assuming phase 1", "error", err.Error())
	}
	pcancel()
	srv := api.New(api.Config{
		MaxPhase:     startPhase,
		Phase:        phase,
		Version:      version,
		Auth:         apikey.NewVerifier(apikey.NewStore(g, nil), nil),
		Limiter:      api.NewKeyRateLimiter(cfg.APIRateLimit, nil),
		Meta:         api.GraphMetaReader{G: g},
		Ping:         g.Verify,
		Logger:       log,
		QueryTimeout: cfg.QueryTimeout,
		StaleAfter:   time.Duration(cfg.StaleAfterHours) * time.Hour,
		Sources:      cfg.EnabledSources,
		Pending:      api.MigrationPending(q, want),
		UI:           ui.Files,
	})
	api.Routes(srv, q, []byte(cfg.CursorSecret.Value()))
	api.CoExploitRoutes(srv, q, cfg.CoExploitation, 0)
	api.OpsRoutes(srv, api.OpsConfig{
		Q: q, Batch: api.ReadBatch(g), SourceStatus: api.ReadSourceStatus(g),
		StatsTTL: cfg.StatsTTL, StatsTimeout: cfg.StatsTimeout,
	})

	hs := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      clientTimeout + 15*time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	useTLS := cfg.TLSCertFile != ""
	if useTLS {
		hs.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("api listening", "addr", cfg.APIAddr, "tls", useTLS, "version", version)
		if useTLS {
			errc <- hs.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			errc <- hs.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "bskg: serve: %v\n", err)
			return 1
		}
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := hs.Shutdown(sctx); err != nil {
			fmt.Fprintf(stderr, "bskg: serve: shutdown: %v\n", err)
			return 1
		}
		log.Info("api stopped")
	}
	return 0
}

// healthcheckURL builds the local /healthz URL from the environment.
func healthcheckURL(getenv func(string) string) string {
	addr := strings.TrimSpace(getenv(config.EnvAPIAddr))
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = "", "8080"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	scheme := "http"
	if strings.TrimSpace(getenv(config.EnvAPITLSCertFile)) != "" {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, port) + "/healthz"
}

func healthcheck(getenv func(string) string) error {
	u := healthcheckURL(getenv)
	c := &http.Client{
		Timeout: 3 * time.Second,
		// The check talks to this process over loopback; the certificate
		// name may not cover 127.0.0.1.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}, //nolint:gosec
	}
	resp, err := c.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz answered %d", resp.StatusCode)
	}
	return nil
}
