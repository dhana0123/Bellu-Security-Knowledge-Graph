//go:build integration

package graph_test

import (
	"context"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/graph"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/graph/graphtest"
)

func TestMain(m *testing.M) { graphtest.Main(m) }

// Requirement 17.13: a write statement sent through the read helper is
// rejected by Neo4j, and nothing is written.
func TestReadRejectsWrites(t *testing.T) {
	c := graphtest.New(t)
	ctx := context.Background()

	_, err := c.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, "CREATE (:X)", nil)
		if err != nil {
			return nil, err
		}
		_, err = res.Consume(ctx)
		return nil, err
	})
	if err == nil {
		t.Fatal("expected Neo4j to reject a write in a read transaction")
	}
	if got := graph.Classify(err); got != graph.ClassClient {
		t.Fatalf("error class = %v, want client: %v", got, err)
	}

	v, err := c.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, "MATCH (n:X) RETURN count(n)", nil)
		if err != nil {
			return nil, err
		}
		rec, err := res.Single(ctx)
		if err != nil {
			return nil, err
		}
		return rec.Values[0], nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := v.(int64); n != 0 {
		t.Fatalf("count(:X) = %v, want 0", v)
	}
}
