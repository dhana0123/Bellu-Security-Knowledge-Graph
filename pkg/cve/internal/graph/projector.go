package graph

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
)

// SinkError attributes a failure to a named sink.
type SinkError struct {
	Sink string
	Err  error
}

func (e *SinkError) Error() string { return fmt.Sprintf("graph: sink %s: %v", e.Sink, e.Err) }
func (e *SinkError) Unwrap() error { return e.Err }

// NamedSink pairs a sink with the name used in errors.
type NamedSink struct {
	Name string
	Sink Sink
}

// HistoryWriter is implemented by sinks that can store history rows (SQLiteSink).
type HistoryWriter interface {
	WriteHistory(HistoryRow) error
}

// Clock supplies the time stamped into SinkMeta.CreatedAt.
type Clock interface{ Now() time.Time }

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

// Projector projects the canonical store into one or more sinks.
type Projector struct {
	CanonicalPath string
	Policy        Policy
	Sinks         []NamedSink
	History       bool // export source_record_version into sinks that support it
	Engine        string
	EngineVersion string
	Clock         Clock // nil means wall clock
	// ScratchDir holds the temporary id set used while building (a disk-backed set keeps memory
	// flat as the dataset grows). Empty means the directory of the first file sink, or
	// os.TempDir(). It must be a real disk: a RAM-backed tmpfs defeats the purpose.
	ScratchDir string
	// Incremental re-projects only the vulnerabilities changed since the previous incremental
	// projection into a copy of the previous graph.db, then swaps it in atomically. It needs
	// exactly one sink, the SQLite sink, and no History. When there is no valid previous
	// projection it falls back to a full build and records the state needed for the next run.
	Incremental bool
}

// Run executes the projection. The policy is validated and the canonical store
// opened read-only before any sink is touched, so failures there leave existing
// outputs untouched. On any later error every sink is aborted.
//
// Limitation: commits are sequential, not a distributed transaction. If one
// sink's Commit fails after earlier sinks committed, those earlier outputs stay
// in place; the remaining uncommitted sinks are aborted and the failing sink is
// reported.
func (p *Projector) Run(ctx context.Context) (Stats, error) {
	if err := p.Policy.Validate(); err != nil {
		return Stats{}, err
	}
	store, err := canonical.OpenReadOnly(p.CanonicalPath)
	if err != nil {
		return Stats{}, err
	}
	defer store.Close()

	clk := p.Clock
	if clk == nil {
		clk = wallClock{}
	}
	if p.Incremental {
		return p.runIncremental(ctx, store, clk)
	}
	return p.runStreaming(ctx, store, clk, nil)
}

// fullHooks lets incremental projection attach to a streaming full build.
type fullHooks struct {
	token  string
	owner  func(vulnID string, kind byte, id string) error
	before func() error // after Build, before the sinks commit
	after  func() error // after the sinks committed
	abort  func()       // on any failure before the sinks committed
}

func (p *Projector) scratchDir() string {
	if p.ScratchDir != "" {
		return p.ScratchDir
	}
	for _, s := range p.Sinks {
		if sq, ok := s.Sink.(*SQLiteSink); ok {
			return filepath.Dir(sq.path)
		}
	}
	return os.TempDir()
}

// runStreaming builds the whole projection from the canonical store into the sinks. Memory use
// does not grow with the dataset: vulnerabilities are read in pages, the shared-id set lives in a
// scratch SQLite file and the SQLite sink commits in batches.
func (p *Projector) runStreaming(ctx context.Context, store *canonical.Store, clk Clock, h *fullHooks) (Stats, error) {
	meta := SinkMeta{
		Level: p.Policy.Level, Ecosystems: p.Policy.Ecosystems,
		SchemaVersion: SchemaVersion, Engine: p.Engine, EngineVersion: p.EngineVersion,
		HasHistory: p.History,
		CreatedAt:  clk.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	if h != nil {
		meta.Token = h.token
	}
	aborted := false
	fatal := func(err error) (Stats, error) {
		if h != nil && h.abort != nil && !aborted {
			aborted = true
			h.abort()
		}
		return Stats{}, err
	}
	seen, err := NewDiskTracker(p.scratchDir())
	if err != nil {
		return fatal(err)
	}
	defer seen.Close()
	for _, s := range p.Sinks {
		if t, ok := s.Sink.(interface{ TrustUniqueIDs() }); ok {
			t.TrustUniqueIDs() // Build emits each id once
		}
	}
	begun := 0
	abortAll := func(from int) {
		for i := from; i < begun; i++ {
			_ = p.Sinks[i].Sink.Abort()
		}
	}
	for i, s := range p.Sinks {
		if err := s.Sink.Begin(ctx, meta); err != nil {
			begun = i + 1 // Begin may leave partial state; abort it too
			abortAll(0)
			return fatal(&SinkError{Sink: s.Name, Err: err})
		}
	}
	begun = len(p.Sinks)

	var failed string
	wrap := func(name string, err error) error {
		if err != nil && failed == "" {
			failed = name
		}
		return err
	}
	emitNode := func(n Node) error {
		for _, s := range p.Sinks {
			if err := wrap(s.Name, s.Sink.WriteNode(n)); err != nil {
				return err
			}
		}
		return nil
	}
	emitEdge := func(e Edge) error {
		for _, s := range p.Sinks {
			if err := wrap(s.Name, s.Sink.WriteEdge(e)); err != nil {
				return err
			}
		}
		return nil
	}
	fail := func(err error) (Stats, error) {
		abortAll(0)
		_, _ = fatal(nil)
		if failed != "" {
			var se *SinkError
			if !errors.As(err, &se) {
				err = &SinkError{Sink: failed, Err: err}
			}
		}
		return Stats{}, err
	}

	opts := BuildOptions{Seen: seen}
	if h != nil {
		opts.Owner = h.owner
	}
	stats, err := BuildWith(ctx, store, p.Policy, opts, emitNode, emitEdge)
	if err != nil {
		return fail(err)
	}
	if p.History {
		if err := p.exportHistory(ctx, store, wrap); err != nil {
			return fail(err)
		}
	}
	if h != nil && h.before != nil {
		if err := h.before(); err != nil {
			return fail(err)
		}
	}
	for i, s := range p.Sinks {
		if err := s.Sink.Commit(); err != nil {
			abortAll(i + 1)
			_ = s.Sink.Abort()
			return fatal(&SinkError{Sink: s.Name, Err: err})
		}
	}
	if h != nil && h.after != nil {
		if err := h.after(); err != nil {
			return Stats{}, err
		}
	}
	stats.Mode = "full"
	return stats, nil
}

func (p *Projector) exportHistory(ctx context.Context, store *canonical.Store, wrap func(string, error) error) error {
	var writers []struct {
		name string
		w    HistoryWriter
	}
	for _, s := range p.Sinks {
		if w, ok := s.Sink.(HistoryWriter); ok {
			writers = append(writers, struct {
				name string
				w    HistoryWriter
			}{s.Name, w})
		}
	}
	if len(writers) == 0 {
		return nil
	}
	rows, err := store.DB.QueryContext(ctx, `SELECT source, external_id, version, COALESCE(event_time,''), recorded_at, state, json
FROM source_record_version ORDER BY source, external_id, version`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var src, ext, ev, rec, state, payload string
		var ver int
		if err := rows.Scan(&src, &ext, &ver, &ev, &rec, &state, &payload); err != nil {
			return err
		}
		r := HistoryRow{EntityID: "src:" + src + ":" + ext, Version: ver, EventTime: ev, RecordedAt: rec, State: state, Payload: payload}
		for _, w := range writers {
			if err := wrap(w.name, w.w.WriteHistory(r)); err != nil {
				return err
			}
		}
	}
	return rows.Err()
}
