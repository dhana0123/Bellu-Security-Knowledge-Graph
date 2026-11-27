package enrich

import (
	"bytes"
	"context"
	"iter"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/fetch"
)

// Source names.
const (
	NameKEV  = "kev"
	NameEPSS = "epss"
)

// Source downloads a full catalog file (KEV JSON or EPSS CSV, optionally .gz) and yields
// it as a single item. Both feeds publish full catalogs, so Incremental behaves as Full.
type Source struct {
	name     string
	Location string
	HTTP     *fetch.Client
	validate func([]byte) error
}

var _ connectors.Source = (*Source)(nil)

// NewKEV returns the "kev" source for location.
func NewKEV(location string) *Source {
	return &Source{name: NameKEV, Location: location, HTTP: fetch.NewClient(NameKEV, false),
		validate: func(b []byte) error { _, err := ParseKEV(bytes.NewReader(b)); return err }}
}

// NewEPSS returns the "epss" source for location.
func NewEPSS(location string) *Source {
	return &Source{name: NameEPSS, Location: location, HTTP: fetch.NewClient(NameEPSS, false),
		validate: func(b []byte) error { _, err := ParseEPSS(bytes.NewReader(b)); return err }}
}

func (s *Source) Name() string { return s.name }

// Fetch yields the catalog as one item whose ID is the source name. The payload is
// checked to parse before it is yielded.
func (s *Source) Fetch(ctx context.Context, _ connectors.Mode, _ time.Time) iter.Seq2[connectors.Item, error] {
	return func(yield func(connectors.Item, error) bool) {
		path, cleanup, err := fetch.LocalWith(ctx, s.HTTP, s.Location)
		if err != nil {
			yield(connectors.Item{}, err)
			return
		}
		defer cleanup()
		b, err := fetch.ReadFile(path)
		if err == nil {
			err = s.validate(b)
		}
		if err != nil {
			yield(connectors.Item{}, err)
			return
		}
		yield(connectors.Item{ID: s.name, Payload: b}, nil)
	}
}
