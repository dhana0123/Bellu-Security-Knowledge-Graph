package checkpoint

import (
	"context"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
)

// Dead letter kinds.
const (
	KindFailed  = "failed"
	KindSkipped = "skipped"
)

// MaxPayload is the largest stored payload (1 MB).
const MaxPayload = 1 << 20

// DeadLetter is a record that could not be written.
type DeadLetter struct {
	Source   string
	RecordID string
	Kind     string
	Payload  []byte
	Error    string
	FailedAt time.Time
}

// DeadLetterID returns source:recordId:kind.
func DeadLetterID(source, recordID, kind string) string {
	return source + ":" + recordID + ":" + kind
}

// TruncatePayload cuts a payload to MaxPayload bytes.
func TruncatePayload(p []byte) []byte {
	if len(p) > MaxPayload {
		return p[:MaxPayload]
	}
	return p
}

const (
	cypherPutDeadLetter = `MERGE (d:DeadLetter {id: $id})
SET d.source = $source, d.recordId = $recordId, d.kind = $kind,
    d.payload = $payload, d.error = $error, d.failedAt = $failedAt`

	cypherDeleteDeadLetter = `MATCH (d:DeadLetter {id: $id}) DELETE d`

	cypherListDeadLetters = `MATCH (d:DeadLetter {source: $source, kind: $kind})
RETURN d.recordId AS recordId, d.payload AS payload, d.error AS error, d.failedAt AS failedAt
ORDER BY d.failedAt, d.recordId`
)

// PutDeadLetter upserts a dead letter inside the caller's transaction.
func PutDeadLetter(ctx context.Context, tx neo4j.ManagedTransaction, d DeadLetter) error {
	return runTx(ctx, tx, cypherPutDeadLetter, map[string]any{
		"id": DeadLetterID(d.Source, d.RecordID, d.Kind), "source": d.Source,
		"recordId": d.RecordID, "kind": d.Kind,
		"payload": string(TruncatePayload(d.Payload)), "error": d.Error, "failedAt": d.FailedAt,
	})
}

// DeleteDeadLetter removes a dead letter inside the caller's transaction.
func DeleteDeadLetter(ctx context.Context, tx neo4j.ManagedTransaction, source, recordID, kind string) error {
	return runTx(ctx, tx, cypherDeleteDeadLetter, map[string]any{"id": DeadLetterID(source, recordID, kind)})
}

// ListDeadLetters returns the source's dead letters of a kind.
func ListDeadLetters(ctx context.Context, g *graph.Client, source, kind string) ([]DeadLetter, error) {
	v, err := g.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, cypherListDeadLetters, map[string]any{"source": source, "kind": kind})
		if err != nil {
			return nil, err
		}
		var out []DeadLetter
		for r.Next(ctx) {
			m := r.Record().AsMap()
			d := DeadLetter{Source: source, Kind: kind}
			d.RecordID, _ = m["recordId"].(string)
			p, _ := m["payload"].(string)
			d.Payload = []byte(p)
			d.Error, _ = m["error"].(string)
			d.FailedAt, _ = m["failedAt"].(time.Time)
			out = append(out, d)
		}
		return out, r.Err()
	})
	if err != nil {
		return nil, err
	}
	return v.([]DeadLetter), nil
}
