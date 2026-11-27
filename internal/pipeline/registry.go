package pipeline

import (
	"fmt"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
)

// Registry holds the registered adapters in registration order.
type Registry struct {
	order []string
	by    map[string]source.Adapter
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{by: map[string]source.Adapter{}} }

// Register adds an adapter. The name must be valid and unique.
func (r *Registry) Register(a source.Adapter) error {
	n := a.Name()
	if !source.ValidName(n) {
		return fmt.Errorf("pipeline: invalid adapter name %q", n)
	}
	if _, dup := r.by[n]; dup {
		return fmt.Errorf("pipeline: adapter %q registered twice", n)
	}
	r.by[n] = a
	r.order = append(r.order, n)
	return nil
}

// Get returns the adapter registered under name.
func (r *Registry) Get(name string) (source.Adapter, bool) {
	a, ok := r.by[name]
	return a, ok
}

// Names returns the registered names in registration order.
func (r *Registry) Names() []string { return append([]string(nil), r.order...) }

// Default is the adapter registry used by cmd/bskg. Each adapter package
// registers itself with one line in cmd/bskg/registry.go.
var Default = NewRegistry()
