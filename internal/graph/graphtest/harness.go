//go:build integration

package graphtest

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/graph"
)

// Image is the pinned Neo4j test image.
const Image = "neo4j:2026.10.2-community"

const (
	password    = "bskg-test-password"
	memoryLimit = 2 << 30 // 2 GB
)

var (
	mu       sync.Mutex
	started  bool
	startErr error
	ctr      testcontainers.Container
	boltAddr string // host:port reachable from the test process
	client   *graph.Client
)

// Main runs the package's tests and then terminates the shared container.
// Call it from TestMain.
func Main(m *testing.M) {
	code := m.Run()
	Stop()
	os.Exit(code)
}

// start launches the shared container once per process.
func start(ctx context.Context) error {
	mu.Lock()
	defer mu.Unlock()
	if started {
		return startErr
	}
	started = true
	startErr = launch(ctx)
	return startErr
}

func launch(ctx context.Context) error {
	port := nat.Port("7687/tcp")
	req := testcontainers.ContainerRequest{
		Image:        Image,
		ExposedPorts: []string{string(port)},
		Env: map[string]string{
			"NEO4J_AUTH":                             "neo4j/" + password,
			"NEO4J_server_memory_heap_initial__size": "512M",
			"NEO4J_server_memory_heap_max__size":     "512M",
			"NEO4J_server_memory_pagecache_size":     "512M",
			"NEO4J_server_http_enabled":              "false",
			"NEO4J_ACCEPT_LICENSE_AGREEMENT":         "yes",
		},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.Memory = memoryLimit
			hc.MemorySwap = memoryLimit // no swap
		},
		WaitingFor: wait.ForListeningPort(port).WithStartupTimeout(3 * time.Minute),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	if err != nil {
		return fmt.Errorf("graphtest: start %s: %w", Image, err)
	}
	ctr = c
	host, err := c.Host(ctx)
	if err != nil {
		return err
	}
	mp, err := c.MappedPort(ctx, port)
	if err != nil {
		return err
	}
	boltAddr = net.JoinHostPort(host, mp.Port())
	cl, err := graph.New(graph.Params{URI: "bolt://" + boltAddr, User: "neo4j", Password: password, Timeout: 30 * time.Second})
	if err != nil {
		return err
	}
	// Bolt listens before the database accepts queries; wait for readiness.
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if err = cl.Verify(ctx); err == nil {
			if _, err = cl.Auto(ctx, "RETURN 1", nil); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("graphtest: neo4j not ready: %w", err)
		}
		time.Sleep(time.Second)
	}
	client = cl
	return nil
}

// Stop closes the client and terminates the shared container. Safe to call
// when nothing was started.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if client != nil {
		_ = client.Close(ctx)
		client = nil
	}
	if ctr != nil {
		_ = ctr.Terminate(ctx)
		ctr = nil
	}
}

// New returns a client on the shared container with an empty database
// (data, constraints, and non-lookup indexes removed). The test is skipped
// with a clear message when Docker is unavailable.
func New(t *testing.T) *graph.Client {
	t.Helper()
	testcontainers.SkipIfProviderIsNotHealthy(t)
	ctx := context.Background()
	if err := start(ctx); err != nil {
		t.Fatalf("graphtest: %v", err)
	}
	if err := Reset(ctx, client); err != nil {
		t.Fatalf("graphtest: reset: %v", err)
	}
	return client
}

// URI returns the Bolt URI of the running container ("" before start).
func URI() string {
	mu.Lock()
	defer mu.Unlock()
	if boltAddr == "" {
		return ""
	}
	return "bolt://" + boltAddr
}

// Password returns the container's neo4j password.
func Password() string { return password }

// Reset empties the database: deletes all nodes in batches, then drops every
// constraint and every non-LOOKUP index so migrations can be re-applied.
func Reset(ctx context.Context, c *graph.Client) error {
	if _, err := c.Auto(ctx, "MATCH (n) CALL { WITH n DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS", nil); err != nil {
		return err
	}
	for _, q := range []struct{ show, drop string }{
		{"SHOW CONSTRAINTS YIELD name RETURN name", "DROP CONSTRAINT %s IF EXISTS"},
		{"SHOW INDEXES YIELD name, type WHERE type <> 'LOOKUP' RETURN name", "DROP INDEX %s IF EXISTS"},
	} {
		names, err := c.Read(ctx, func(ctx context.Context, tx neo4jTx) (any, error) {
			res, err := tx.Run(ctx, q.show, nil)
			if err != nil {
				return nil, err
			}
			var out []string
			for res.Next(ctx) {
				out = append(out, res.Record().Values[0].(string))
			}
			return out, res.Err()
		})
		if err != nil {
			return err
		}
		for _, n := range names.([]string) {
			// Names come from the server's own catalog; quote with backticks.
			if _, err := c.Auto(ctx, fmt.Sprintf(q.drop, "`"+n+"`"), nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// BlockedDialContext returns a DialContext that refuses every connection
// except those to the allowed host:port addresses (normally URI's address).
func BlockedDialContext(allow ...string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	set := map[string]bool{}
	for _, a := range allow {
		set[a] = true
	}
	var d net.Dialer
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !set[addr] {
			return nil, fmt.Errorf("graphtest: outbound connection to %q blocked", addr)
		}
		return d.DialContext(ctx, network, addr)
	}
}

// BlockOutboundHTTP makes http.DefaultTransport refuse every host except the
// allowed host:port addresses, and returns a function that restores it.
// Code under test should use http clients that derive from DefaultTransport
// (or take a Doer built from BlockedDialContext).
func BlockOutboundHTTP(allow ...string) (restore func()) {
	old := http.DefaultTransport
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.DialContext = BlockedDialContext(allow...)
	http.DefaultTransport = t
	return func() { http.DefaultTransport = old }
}
