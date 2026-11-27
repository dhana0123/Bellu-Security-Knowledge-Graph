// Package maint holds operator maintenance commands. Reset implements
// `bskg reset --confirm` (Requirement 12.13 to 12.19).
package maint

import (
	"context"
	"errors"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/graph"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/model"
)

// BatchLimit is the largest number of items one reset transaction deletes.
const BatchLimit = 10000

// Errors returned by Reset.
var (
	ErrNotConfirmed = errors.New("reset changes nothing without the --confirm flag")
	ErrActive       = errors.New("a Sync_Run or Worker job is active; reset refused")
)

// Result counts what Reset deleted.
type Result struct {
	Nodes         int64
	Relationships int64
}

// Store is the graph seam of Reset.
type Store interface {
	// Active reports whether a live lock or a running Worker job exists.
	Active(ctx context.Context) (bool, error)
	// DeleteRels deletes up to limit relationships and returns the count.
	DeleteRels(ctx context.Context, limit int) (int64, error)
	// DeleteNodes deletes up to limit nodes of label and returns the count.
	// The label comes from the model registry.
	DeleteNodes(ctx context.Context, label string, limit int) (int64, error)
}

// Reset deletes the graph content except Migration and ApiKey nodes. It keeps
// constraints and indexes. On a failure it returns what was deleted so far
// together with the error; a second run completes the reset.
func Reset(ctx context.Context, st Store, confirm bool) (Result, error) {
	var res Result
	if !confirm {
		return res, ErrNotConfirmed
	}
	active, err := st.Active(ctx)
	if err != nil {
		return res, fmt.Errorf("reset: check active runs: %w", err)
	}
	if active {
		return res, ErrActive
	}
	for {
		n, err := st.DeleteRels(ctx, BatchLimit)
		res.Relationships += n
		if err != nil {
			return res, partial(res, err)
		}
		if n == 0 {
			break
		}
	}
	for _, label := range model.ResetLabels() {
		for {
			n, err := st.DeleteNodes(ctx, label, BatchLimit)
			res.Nodes += n
			if err != nil {
				return res, partial(res, err)
			}
			if n == 0 {
				break
			}
		}
	}
	return res, nil
}

func partial(r Result, err error) error {
	return fmt.Errorf("reset failed after deleting %d nodes and %d relationships: %w", r.Nodes, r.Relationships, err)
}

// GraphStore implements Store on Neo4j.
type GraphStore struct{ G *graph.Client }

const cypherActive = `CALL { MATCH (l:Lock) WHERE l.expiresAt > datetime() RETURN count(l) AS locks }
CALL { MATCH (j:Job) WHERE j.queueState = 'running' RETURN count(j) AS jobs }
RETURN locks + jobs AS n`

func (s GraphStore) Active(ctx context.Context) (bool, error) {
	v, err := s.G.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, cypherActive, nil)
		if err != nil {
			return nil, err
		}
		rec, err := r.Single(ctx)
		if err != nil {
			return nil, err
		}
		n, _ := rec.AsMap()["n"].(int64)
		return n > 0, nil
	})
	if err != nil {
		return false, err
	}
	return v.(bool), nil
}

func (s GraphStore) DeleteRels(ctx context.Context, limit int) (int64, error) {
	return s.del(ctx, "MATCH ()-[r]->() WITH r LIMIT $limit DELETE r", limit, true)
}

func (s GraphStore) DeleteNodes(ctx context.Context, label string, limit int) (int64, error) {
	l, ok := model.LabelByName(label)
	if !ok {
		return 0, fmt.Errorf("reset: unknown label %q", label)
	}
	// Relationships are already gone, so a plain DELETE is enough. The label
	// is a registry constant, never input.
	return s.del(ctx, fmt.Sprintf("MATCH (n:`%s`) WITH n LIMIT $limit DELETE n", l.Name), limit, false)
}

func (s GraphStore) del(ctx context.Context, cypher string, limit int, rels bool) (int64, error) {
	v, err := s.G.Write(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, cypher, map[string]any{"limit": int64(limit)})
		if err != nil {
			return nil, err
		}
		sum, err := r.Consume(ctx)
		if err != nil {
			return nil, err
		}
		if rels {
			return int64(sum.Counters().RelationshipsDeleted()), nil
		}
		return int64(sum.Counters().NodesDeleted()), nil
	})
	if err != nil {
		return 0, err
	}
	return v.(int64), nil
}
