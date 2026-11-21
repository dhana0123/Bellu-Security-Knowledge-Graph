// Package change builds and writes Change records.
package change

import (
	"context"
	crand "crypto/rand"
	"sync"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/oklog/ulid/v2"
)

// Record is one (:Change) node.
type Record struct {
	ID        string
	EntityKey string
	Type      string
	Field     string
	OldValue  string
	NewValue  string // JSON text
	Source    string
	RunID     string
	At        time.Time
}

var (
	entropyMu sync.Mutex
	entropy   = ulid.Monotonic(crand.Reader, 0)
)

// NewID returns a monotonic ULID, so ordering by id equals creation order.
func NewID(t time.Time) (string, error) {
	entropyMu.Lock()
	defer entropyMu.Unlock()
	id, err := ulid.New(ulid.Timestamp(t), entropy)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

const cypherWrite = `MERGE (c:Change {id: $id})
ON CREATE SET c.entityKey = $entityKey, c.type = $type, c.field = $field,
  c.oldValue = $oldValue, c.newValue = $newValue, c.source = $source,
  c.runId = $runId, c.at = datetime($at)`

// Write stores r inside tx. It is idempotent on the record id.
func Write(ctx context.Context, tx neo4j.ManagedTransaction, r Record) error {
	res, err := tx.Run(ctx, cypherWrite, map[string]any{
		"id": r.ID, "entityKey": r.EntityKey, "type": r.Type, "field": r.Field,
		"oldValue": r.OldValue, "newValue": r.NewValue, "source": r.Source,
		"runId": r.RunID, "at": r.At.Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	_, err = res.Consume(ctx)
	return err
}
