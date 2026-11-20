// Package graph is the Neo4j access layer: read/write/auto-commit helpers,
// per-call query timeout, and error classification. It never logs query
// parameters. It uses plain Cypher only (no APOC, no GDS).
package graph

import (
	"context"
	"errors"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Params are the plain connection parameters.
type Params struct {
	URI      string
	User     string
	Password string
	Timeout  time.Duration // per-query timeout; 0 means 10s
}

// DefaultTimeout is the default per-query timeout.
const DefaultTimeout = 10 * time.Second

// Client wraps a Neo4j driver.
type Client struct {
	driver  neo4j.DriverWithContext
	timeout time.Duration
}

// New creates a Client. It does not contact the server; call Verify.
func New(p Params) (*Client, error) {
	if p.URI == "" {
		return nil, errors.New("graph: empty URI")
	}
	d, err := neo4j.NewDriverWithContext(p.URI, neo4j.BasicAuth(p.User, p.Password, ""))
	if err != nil {
		// The driver error can echo the URI but not the password.
		return nil, wrap(err)
	}
	t := p.Timeout
	if t <= 0 {
		t = DefaultTimeout
	}
	return &Client{driver: d, timeout: t}, nil
}

// Timeout returns the per-query timeout.
func (c *Client) Timeout() time.Duration { return c.timeout }

// Verify checks connectivity.
func (c *Client) Verify(ctx context.Context) error {
	return wrap(c.driver.VerifyConnectivity(ctx))
}

// Close releases driver resources.
func (c *Client) Close(ctx context.Context) error { return c.driver.Close(ctx) }

// TxFunc runs inside a managed transaction.
type TxFunc func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error)

func (c *Client) run(ctx context.Context, mode neo4j.AccessMode, fn TxFunc) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	s := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: mode})
	defer s.Close(context.WithoutCancel(ctx))
	wrapped := func(tx neo4j.ManagedTransaction) (any, error) { return fn(ctx, tx) }
	var res any
	var err error
	if mode == neo4j.AccessModeRead {
		res, err = s.ExecuteRead(ctx, wrapped, neo4j.WithTxTimeout(c.timeout))
	} else {
		res, err = s.ExecuteWrite(ctx, wrapped, neo4j.WithTxTimeout(c.timeout))
	}
	return res, wrap(err)
}

// Read runs fn in a READ-mode managed transaction. Neo4j rejects writes in it.
func (c *Client) Read(ctx context.Context, fn TxFunc) (any, error) {
	return c.run(ctx, neo4j.AccessModeRead, fn)
}

// Write runs fn in a WRITE-mode managed transaction.
func (c *Client) Write(ctx context.Context, fn TxFunc) (any, error) {
	return c.run(ctx, neo4j.AccessModeWrite, fn)
}

// Auto runs one auto-commit statement (schema statements, CALL {} IN
// TRANSACTIONS) and returns the consumed summary. The cypher text must be
// constant; values go in params only.
func (c *Client) Auto(ctx context.Context, cypher string, params map[string]any) (neo4j.ResultSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	s := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer s.Close(context.WithoutCancel(ctx))
	r, err := s.Run(ctx, cypher, params, neo4j.WithTxTimeout(c.timeout))
	if err != nil {
		return nil, wrap(err)
	}
	sum, err := r.Consume(ctx)
	return sum, wrap(err)
}

// WriteRetry runs Write with the batch retry policy for transient errors.
func (c *Client) WriteRetry(ctx context.Context, fn TxFunc) (any, error) {
	var out any
	err := Retry(ctx, BatchPolicy, nil, func(ctx context.Context) error {
		var e error
		out, e = c.Write(ctx, fn)
		return e
	})
	return out, err
}
