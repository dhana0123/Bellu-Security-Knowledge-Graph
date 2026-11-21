package pipeline

import (
	"context"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/change"
	"github.com/bellu/bskg/internal/checkpoint"
	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/upsert"
)

// Lease is a held source lock. *checkpoint.Lock implements it.
type Lease interface {
	// Hold renews the lock in the background; the returned context is
	// cancelled when a renewal fails. Call stop to end the renewal.
	Hold(ctx context.Context) (context.Context, func())
	Release(ctx context.Context) error
}

// Tx is the set of statements one batch transaction may run. All of them
// commit or roll back together.
type Tx interface {
	Load(ctx context.Context, b upsert.Batch) (upsert.State, error)
	Apply(ctx context.Context, w upsert.Writes, recs []change.Record) error
	UpdateRun(ctx context.Context, id string, c checkpoint.Counters, p checkpoint.Progress) error
	// WriteCursor stores the resume token and raises the watermark.
	WriteCursor(ctx context.Context, source, resume string, watermark time.Time) error
	PutDeadLetter(ctx context.Context, d checkpoint.DeadLetter) error
	DeleteDeadLetter(ctx context.Context, source, recordID, kind string) error
}

// Store is the Graph_Store seam of the pipeline. GraphStore is the Neo4j
// implementation; tests use an in-memory fake.
type Store interface {
	Acquire(ctx context.Context, source, owner string) (Lease, error)
	ReadCheckpoint(ctx context.Context, source string) (checkpoint.Checkpoint, error)
	StartRun(ctx context.Context, id, source string, at time.Time) error
	FinishRun(ctx context.Context, id, status, errMsg string, at time.Time) error
	WriteVersion(ctx context.Context, source, version string) error
	// WriteUpstream stores the upstream totals and their time on the
	// source's Checkpoint node.
	WriteUpstream(ctx context.Context, source string, totals map[string]int64, at time.Time) error
	ListDeadLetters(ctx context.Context, source, kind string) ([]checkpoint.DeadLetter, error)
	// InTx runs fn in one write transaction. It does not retry; the
	// pipeline applies the batch retry policy.
	InTx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error
}

// GraphStore implements Store on a graph.Client.
type GraphStore struct{ G *graph.Client }

// NewGraphStore returns a Store backed by Neo4j.
func NewGraphStore(g *graph.Client) *GraphStore { return &GraphStore{G: g} }

func (s *GraphStore) Acquire(ctx context.Context, source, owner string) (Lease, error) {
	l, err := checkpoint.AcquireLock(ctx, s.G, source, owner)
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (s *GraphStore) ReadCheckpoint(ctx context.Context, source string) (checkpoint.Checkpoint, error) {
	return checkpoint.ReadCheckpoint(ctx, s.G, source)
}

func (s *GraphStore) StartRun(ctx context.Context, id, source string, at time.Time) error {
	return checkpoint.StartRun(ctx, s.G, id, source, at)
}

func (s *GraphStore) FinishRun(ctx context.Context, id, status, errMsg string, at time.Time) error {
	return checkpoint.FinishRun(ctx, s.G, id, status, errMsg, at)
}

func (s *GraphStore) WriteVersion(ctx context.Context, source, version string) error {
	_, err := s.G.WriteRetry(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		return nil, checkpoint.WriteVersion(ctx, tx, source, version)
	})
	return err
}

func (s *GraphStore) WriteUpstream(ctx context.Context, source string, totals map[string]int64, at time.Time) error {
	_, err := s.G.WriteRetry(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		return nil, checkpoint.WriteUpstream(ctx, tx, source, totals, at)
	})
	return err
}

func (s *GraphStore) ListDeadLetters(ctx context.Context, source, kind string) ([]checkpoint.DeadLetter, error) {
	return checkpoint.ListDeadLetters(ctx, s.G, source, kind)
}

func (s *GraphStore) InTx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error {
	_, err := s.G.Write(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		return nil, fn(ctx, graphTx{tx})
	})
	return err
}

type graphTx struct{ tx neo4j.ManagedTransaction }

func (t graphTx) Load(ctx context.Context, b upsert.Batch) (upsert.State, error) {
	return upsert.Load(ctx, t.tx, b)
}

func (t graphTx) Apply(ctx context.Context, w upsert.Writes, recs []change.Record) error {
	return upsert.Apply(ctx, t.tx, w, recs)
}

func (t graphTx) UpdateRun(ctx context.Context, id string, c checkpoint.Counters, p checkpoint.Progress) error {
	return checkpoint.UpdateRun(ctx, t.tx, id, c, p)
}

func (t graphTx) WriteCursor(ctx context.Context, source, resume string, w time.Time) error {
	if err := checkpoint.WriteCursor(ctx, t.tx, source, resume, time.Time{}); err != nil {
		return err
	}
	if w.IsZero() {
		return nil
	}
	return checkpoint.RaiseWatermark(ctx, t.tx, source, w)
}

func (t graphTx) PutDeadLetter(ctx context.Context, d checkpoint.DeadLetter) error {
	return checkpoint.PutDeadLetter(ctx, t.tx, d)
}

func (t graphTx) DeleteDeadLetter(ctx context.Context, source, id, kind string) error {
	return checkpoint.DeleteDeadLetter(ctx, t.tx, source, id, kind)
}
