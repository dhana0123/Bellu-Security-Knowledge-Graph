package apikey

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
)

// Constant Cypher; values are bound as parameters only.
const (
	cypherCreate = `CREATE (k:ApiKey {id: $id, name: $name, salt: $salt, hash: $hash, createdAt: datetime($at)})`
	cypherRevoke = `MATCH (k:ApiKey {name: $name}) WHERE k.revokedAt IS NULL
SET k.revokedAt = datetime($at) RETURN count(k) AS n`
	cypherLookup = `MATCH (k:ApiKey {id: $id})
RETURN k.name AS name, k.salt AS salt, k.hash AS hash,
       toString(k.createdAt) AS createdAt, toString(k.revokedAt) AS revokedAt`
)

// Store persists keys as (:ApiKey) nodes and implements Lookup.
type Store struct {
	g   *graph.Client
	now func() time.Time
}

// NewStore returns a Store. now may be nil (time.Now).
func NewStore(g *graph.Client, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{g: g, now: now}
}

// Create generates and stores a key and returns the plaintext key, which is
// never stored. An invalid name returns ErrInvalidName and a duplicate name
// returns ErrDuplicateName; neither creates a key.
func (s *Store) Create(ctx context.Context, name string) (string, error) {
	key, rec, err := Generate(nil, name, s.now())
	if err != nil {
		return "", err
	}
	_, err = s.g.Auto(ctx, cypherCreate, map[string]any{
		"id": rec.ID, "name": rec.Name,
		"salt": hex.EncodeToString(rec.Salt), "hash": hex.EncodeToString(rec.Hash),
		"at": rec.CreatedAt.Format(time.RFC3339Nano),
	})
	if err != nil {
		var ge *graph.Error
		if errors.As(err, &ge) && strings.Contains(ge.Code, "ConstraintValidationFailed") {
			return "", ErrDuplicateName
		}
		return "", err
	}
	return key, nil
}

// Revoke marks the active key with the given name revoked at the current UTC
// time. An unknown or already revoked key returns ErrNotFound and changes
// nothing.
func (s *Store) Revoke(ctx context.Context, name string) error {
	v, err := s.g.Write(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, cypherRevoke, map[string]any{
			"name": name, "at": s.now().UTC().Format(time.RFC3339Nano),
		})
		if err != nil {
			return nil, err
		}
		rec, err := r.Single(ctx)
		if err != nil {
			return nil, err
		}
		return rec.Values[0], nil
	})
	if err != nil {
		return err
	}
	if n, _ := v.(int64); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Lookup implements Lookup. It returns (nil, nil) for an unknown id.
func (s *Store) Lookup(ctx context.Context, id string) (*Record, error) {
	v, err := s.g.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, cypherLookup, map[string]any{"id": id})
		if err != nil {
			return nil, err
		}
		if !r.Next(ctx) {
			return (*Record)(nil), r.Err()
		}
		m := r.Record().AsMap()
		rec := &Record{ID: id}
		rec.Name, _ = m["name"].(string)
		salt, _ := m["salt"].(string)
		hash, _ := m["hash"].(string)
		var derr error
		if rec.Salt, derr = hex.DecodeString(salt); derr != nil {
			return nil, derr
		}
		if rec.Hash, derr = hex.DecodeString(hash); derr != nil {
			return nil, derr
		}
		if s, ok := m["createdAt"].(string); ok {
			rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, s)
		}
		if s, ok := m["revokedAt"].(string); ok {
			if t, perr := time.Parse(time.RFC3339Nano, s); perr == nil {
				rec.RevokedAt = &t
			}
		}
		return rec, r.Err()
	})
	if err != nil {
		return nil, err
	}
	return v.(*Record), nil
}
