package migrate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
)

// LockSource is the (:Lock {source}) key held while migrating.
const LockSource = "migrate"

// Store is the graph access the Runner needs.
type Store interface {
	// Bootstrap creates the Migration and Lock uniqueness constraints.
	Bootstrap(ctx context.Context) error
	// Acquire takes the migrate lock for owner; false when another owner holds it.
	Acquire(ctx context.Context, owner string) (bool, error)
	Release(ctx context.Context, owner string) error
	Applied(ctx context.Context) ([]Applied, error)
	// Exec runs one auto-commit statement.
	Exec(ctx context.Context, stmt string) error
	// AwaitIndexes waits for indexes created by a migration to come online.
	AwaitIndexes(ctx context.Context) error
	Record(ctx context.Context, m Migration) error
}

// ErrLocked means another process holds the migrate lock.
var ErrLocked = errors.New("migrate: another migration run holds the lock")

// Result reports a run.
type Result struct {
	Applied []int // versions applied by this run, ascending
}

// Runner applies migrations through a Store.
type Runner struct {
	Store Store
	Files []Migration
	Owner string // lock owner id; must be unique per process
	Log   *slog.Logger
}

// Run applies every pending migration in ascending order. On failure it
// stops, does not record the failed version, and returns an error naming it.
func (r *Runner) Run(ctx context.Context) (Result, error) {
	var res Result
	log := r.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if err := r.Store.Bootstrap(ctx); err != nil {
		return res, fmt.Errorf("migrate: bootstrap: %w", err)
	}
	ok, err := r.Store.Acquire(ctx, r.Owner)
	if err != nil {
		return res, fmt.Errorf("migrate: acquire lock: %w", err)
	}
	if !ok {
		return res, ErrLocked
	}
	defer func() { _ = r.Store.Release(context.WithoutCancel(ctx), r.Owner) }()

	applied, err := r.Store.Applied(ctx)
	if err != nil {
		return res, fmt.Errorf("migrate: read applied: %w", err)
	}
	pending, err := Plan(r.Files, applied)
	if err != nil {
		return res, err
	}
	for _, m := range pending {
		log.Info("applying migration", "version", m.Version, "name", m.Name)
		for i, stmt := range m.Statements {
			if err := r.Store.Exec(ctx, stmt); err != nil {
				return res, fmt.Errorf("migrate: V%03d (%s) statement %d failed: %w", m.Version, m.Name, i+1, err)
			}
		}
		if err := r.Store.AwaitIndexes(ctx); err != nil {
			return res, fmt.Errorf("migrate: V%03d (%s) awaiting indexes failed: %w", m.Version, m.Name, err)
		}
		if err := r.Store.Record(ctx, m); err != nil {
			return res, fmt.Errorf("migrate: V%03d (%s) recording failed: %w", m.Version, m.Name, err)
		}
		res.Applied = append(res.Applied, m.Version)
	}
	return res, nil
}

// GraphStore is the Store backed by a graph.Client. Its client timeout must
// cover db.awaitIndexes (300 s).
type GraphStore struct{ C *graph.Client }

const (
	cypherMigrationConstraint = "CREATE CONSTRAINT bskg_migration_version IF NOT EXISTS FOR (n:Migration) REQUIRE n.version IS UNIQUE"
	// Same name and definition as V002, so the later IF NOT EXISTS is a no-op.
	cypherLockConstraint = "CREATE CONSTRAINT bskg_lock_source IF NOT EXISTS FOR (n:Lock) REQUIRE n.source IS UNIQUE"
)

// Bootstrap implements Store.
func (s GraphStore) Bootstrap(ctx context.Context) error {
	for _, q := range []string{cypherMigrationConstraint, cypherLockConstraint} {
		if _, err := s.C.Auto(ctx, q, nil); err != nil {
			return err
		}
	}
	return nil
}

// Acquire implements Store. The lock is free when unowned, expired, or
// already ours; it expires 10 minutes after acquisition.
func (s GraphStore) Acquire(ctx context.Context, owner string) (bool, error) {
	got, err := s.C.Write(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, `MERGE (l:Lock {source: $source})
WITH l WHERE l.owner IS NULL OR l.expiresAt < datetime() OR l.owner = $owner
SET l.owner = $owner, l.expiresAt = datetime() + duration('PT10M')
RETURN l.owner AS owner`, map[string]any{"source": LockSource, "owner": owner})
		if err != nil {
			return nil, err
		}
		return res.Next(ctx), res.Err()
	})
	if err != nil {
		return false, err
	}
	return got.(bool), nil
}

// Release implements Store.
func (s GraphStore) Release(ctx context.Context, owner string) error {
	_, err := s.C.Write(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, `MATCH (l:Lock {source: $source, owner: $owner})
REMOVE l.owner, l.expiresAt`, map[string]any{"source": LockSource, "owner": owner})
		if err != nil {
			return nil, err
		}
		_, err = res.Consume(ctx)
		return nil, err
	})
	return err
}

// Applied implements Store.
func (s GraphStore) Applied(ctx context.Context) ([]Applied, error) {
	out, err := s.C.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, "MATCH (m:Migration) RETURN m.version AS v, m.checksum AS c ORDER BY v", nil)
		if err != nil {
			return nil, err
		}
		var list []Applied
		for res.Next(ctx) {
			rec := res.Record()
			v, _ := rec.Get("v")
			c, _ := rec.Get("c")
			vi, ok := v.(int64)
			cs, ok2 := c.(string)
			if !ok || !ok2 {
				return nil, errors.New("malformed Migration node")
			}
			list = append(list, Applied{Version: int(vi), Checksum: cs})
		}
		return list, res.Err()
	})
	if err != nil {
		return nil, err
	}
	return out.([]Applied), nil
}

// Exec implements Store.
func (s GraphStore) Exec(ctx context.Context, stmt string) error {
	_, err := s.C.Auto(ctx, stmt, nil)
	return err
}

// AwaitIndexes implements Store.
func (s GraphStore) AwaitIndexes(ctx context.Context) error {
	_, err := s.C.Auto(ctx, "CALL db.awaitIndexes(300)", nil)
	return err
}

// Record implements Store.
func (s GraphStore) Record(ctx context.Context, m Migration) error {
	_, err := s.C.Write(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, `CREATE (:Migration {version: $v, name: $n, checksum: $c, appliedAt: datetime()})`,
			map[string]any{"v": m.Version, "n": m.Name, "c": m.Checksum})
		if err != nil {
			return nil, err
		}
		_, err = res.Consume(ctx)
		return nil, err
	})
	return err
}
