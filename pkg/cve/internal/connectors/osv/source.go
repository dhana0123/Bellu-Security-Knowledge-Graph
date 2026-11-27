package osv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/fetch"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// Source names.
const (
	NameOSV  = "osv"
	NameGHSA = "ghsa"
)

// Source reads OSV-schema advisories (OSV or GHSA) from a directory, .zip, single
// JSON file, or http(s) URL of a zip/JSON file.
type Source struct {
	name     string
	Location string
	HTTP     *fetch.Client
}

var _ connectors.Source = (*Source)(nil)

// NewOSV returns the "osv" source for location.
func NewOSV(location string) *Source { return newSource(NameOSV, location) }

// NewGHSA returns the "ghsa" source for location.
func NewGHSA(location string) *Source { return newSource(NameGHSA, location) }

func newSource(name, location string) *Source {
	return &Source{name: name, Location: location, HTTP: fetch.NewClient(name, false)}
}

func (s *Source) Name() string { return s.name }

var errStop = errors.New("stop")

// Fetch yields one item per advisory document. Incremental mode with a non-zero since
// yields only documents whose modified timestamp is after since; a zero since behaves as Full.
// Documents that cannot be read yield an error item and iteration continues.
func (s *Source) Fetch(ctx context.Context, mode connectors.Mode, since time.Time) iter.Seq2[connectors.Item, error] {
	return func(yield func(connectors.Item, error) bool) {
		path, cleanup, err := fetch.LocalWith(ctx, s.HTTP, s.Location)
		if err != nil {
			yield(connectors.Item{}, err)
			return
		}
		defer cleanup()
		filter := mode == connectors.Incremental && !since.IsZero()
		err = fetch.WalkJSON(path, func(name string, data []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			var h struct {
				ID       string `json:"id"`
				Modified string `json:"modified"`
			}
			if err := json.Unmarshal(data, &h); err != nil {
				if !yield(connectors.Item{}, fmt.Errorf("%s: %s: %w", s.name, name, err)) {
					return errStop
				}
				return nil
			}
			id := model.NormID(h.ID)
			if id == "" {
				if !yield(connectors.Item{}, fmt.Errorf("%s: %s: record without id", s.name, name)) {
					return errStop
				}
				return nil
			}
			if filter && !model.ParseTime(h.Modified).After(since) {
				return nil
			}
			if !yield(connectors.Item{ID: id, Payload: data}, nil) {
				return errStop
			}
			return nil
		})
		if err != nil && !errors.Is(err, errStop) {
			yield(connectors.Item{}, err)
		}
	}
}
