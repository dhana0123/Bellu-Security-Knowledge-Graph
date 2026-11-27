// Package connectors defines the shared contract for vulnerability data sources.
package connectors

import (
	"context"
	"iter"
	"time"
)

// Mode selects between a complete fetch and an incremental one.
type Mode int

const (
	Full Mode = iota
	Incremental
)

// Item is one payload to store and normalize.
type Item struct {
	ID      string
	Payload []byte
}

// Source yields work items from one upstream data source.
type Source interface {
	Name() string
	Fetch(ctx context.Context, mode Mode, since time.Time) iter.Seq2[Item, error]
}
