//go:build integration

package graphtest_test

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/graph/graphtest"
)

func TestMain(m *testing.M) { graphtest.Main(m) }

func TestReturnOneAndReset(t *testing.T) {
	c := graphtest.New(t)
	ctx := context.Background()
	v, err := c.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, "RETURN 1 AS x", nil)
		if err != nil {
			return nil, err
		}
		rec, err := r.Single(ctx)
		if err != nil {
			return nil, err
		}
		return rec.Values[0], nil
	})
	if err != nil || v.(int64) != 1 {
		t.Fatalf("RETURN 1 = %v, %v", v, err)
	}
	if _, err := c.Auto(ctx, "CREATE CONSTRAINT t_unique IF NOT EXISTS FOR (n:T) REQUIRE n.id IS UNIQUE", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Auto(ctx, "CREATE (:T {id: 1})", nil); err != nil {
		t.Fatal(err)
	}
}

func TestResetBetweenTests(t *testing.T) {
	c := graphtest.New(t)
	ctx := context.Background()
	v, err := c.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, "MATCH (n) RETURN count(n)", nil)
		if err != nil {
			return nil, err
		}
		rec, err := r.Single(ctx)
		if err != nil {
			return nil, err
		}
		return rec.Values[0], nil
	})
	if err != nil || v.(int64) != 0 {
		t.Fatalf("expected empty database, got %v, %v", v, err)
	}
}

func TestDialerBlocksOthers(t *testing.T) {
	d := graphtest.BlockedDialContext("127.0.0.1:1")
	_, err := d(context.Background(), "tcp", "example.com:443")
	if err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("expected blocked error, got %v", err)
	}
	_ = net.Dialer{}
}
