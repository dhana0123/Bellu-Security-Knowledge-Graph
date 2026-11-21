package checkpoint

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
)

// Lock timing (design "Checkpoint rules").
const (
	LockTTL       = 10 * time.Minute
	RenewInterval = 60 * time.Second
)

// ErrLocked means a live lock held by another owner exists.
var ErrLocked = errors.New("checkpoint: source is locked by another run")

const (
	// One statement: take the lock only if it is free, expired, or ours.
	cypherAcquireLock = `MERGE (l:Lock {source: $source})
WITH l, (l.owner IS NULL OR l.expiresAt IS NULL OR l.expiresAt < datetime() OR l.owner = $owner) AS free
FOREACH (_ IN CASE WHEN free THEN [1] ELSE [] END |
  SET l.owner = $owner, l.expiresAt = datetime() + duration({seconds: $ttl}))
RETURN l.owner = $owner AS acquired`

	cypherRenewLock = `MATCH (l:Lock {source: $source, owner: $owner})
SET l.expiresAt = datetime() + duration({seconds: $ttl})
RETURN count(l) AS n`

	cypherReleaseLock = `MATCH (l:Lock {source: $source, owner: $owner}) DELETE l`
)

// Lock is a held source lock.
type Lock struct {
	g      *graph.Client
	Source string
	Owner  string
}

// AcquireLock takes the lock or returns ErrLocked.
func AcquireLock(ctx context.Context, g *graph.Client, source, owner string) (*Lock, error) {
	v, err := g.WriteRetry(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, cypherAcquireLock, map[string]any{"source": source, "owner": owner, "ttl": int64(LockTTL.Seconds())})
		if err != nil {
			return nil, err
		}
		rec, err := r.Single(ctx)
		if err != nil {
			return nil, err
		}
		ok, _ := rec.AsMap()["acquired"].(bool)
		return ok, nil
	})
	if err != nil {
		return nil, err
	}
	if !v.(bool) {
		return nil, ErrLocked
	}
	return &Lock{g: g, Source: source, Owner: owner}, nil
}

// Renew extends the lock; it fails if the lock was lost.
func (l *Lock) Renew(ctx context.Context) error {
	v, err := l.g.Write(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, cypherRenewLock, map[string]any{"source": l.Source, "owner": l.Owner, "ttl": int64(LockTTL.Seconds())})
		if err != nil {
			return nil, err
		}
		rec, err := r.Single(ctx)
		if err != nil {
			return nil, err
		}
		n, _ := rec.AsMap()["n"].(int64)
		return n, nil
	})
	if err != nil {
		return err
	}
	if v.(int64) == 0 {
		return ErrLocked
	}
	return nil
}

// Release deletes the lock if still owned. Uses a fresh context so it works
// after the run context was cancelled.
func (l *Lock) Release(ctx context.Context) error {
	ctx = context.WithoutCancel(ctx)
	_, err := l.g.Write(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		return nil, runTx(ctx, tx, cypherReleaseLock, map[string]any{"source": l.Source, "owner": l.Owner})
	})
	return err
}

// Hold starts a goroutine that renews the lock every RenewInterval. The
// returned context is cancelled when a renewal fails. Call stop to end the
// goroutine (it waits for it to exit).
func (l *Lock) Hold(ctx context.Context) (context.Context, func()) {
	return holdLoop(ctx, RenewInterval, l.Renew)
}

func holdLoop(ctx context.Context, every time.Duration, renew func(context.Context) error) (context.Context, func()) {
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-rctx.Done():
				return
			case <-t.C:
				if err := renew(rctx); err != nil && rctx.Err() == nil {
					cancel()
					return
				}
			}
		}
	}()
	var once sync.Once
	return rctx, func() {
		once.Do(func() { cancel(); <-done })
	}
}
