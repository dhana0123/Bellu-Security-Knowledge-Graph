// Package pipeline runs one Sync_Run for one source adapter: lock, SyncRun,
// checkpoint, fetch, then per batch normalize, resolve, load, plan, apply and
// record in a single transaction (Requirements 3 and 8).
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/bellu/bskg/internal/checkpoint"
	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/source"
	"github.com/bellu/bskg/internal/upsert"
)

// Batch size limits (Requirement 3.11).
const (
	DefaultBatchSize = 500
	MinBatchSize     = 1
	MaxBatchSize     = 10000
)

// StepUpsert is the SyncRun step written with every batch.
const StepUpsert = "upsert"

// Options are the per-run settings.
type Options struct {
	// SampleLimit > 0 is a Sample_Build: the pipeline writes no checkpoint
	// and no version (Requirement 12.7).
	SampleLimit int
	// BatchSize is 1 to 10000; 0 means DefaultBatchSize.
	BatchSize int
	// Since, when set, is the starting watermark of this run; the stored
	// resume token and version are ignored.
	Since time.Time
	// ReplayDeadLetters reprocesses the dead letters of kind failed instead
	// of fetching.
	ReplayDeadLetters bool

	// Optional seams.
	Owner string
	Now   func() time.Time
	Sleep graph.SleepFunc // batch retry wait; defaults to a timer
	Log   *slog.Logger
}

// Result is the outcome of a run that started.
type Result struct {
	RunID    string
	Status   string
	Counters checkpoint.Counters
}

// ValidateBatchSize checks the batch size range.
func ValidateBatchSize(n int) error {
	if n < MinBatchSize || n > MaxBatchSize {
		return fmt.Errorf("pipeline: batch size %d is outside the valid range %d to %d", n, MinBatchSize, MaxBatchSize)
	}
	return nil
}

type item struct {
	rec     source.Record
	d       *upsert.Desired
	dead    *checkpoint.DeadLetter
	replay  bool // a dead letter being replayed
	payload bool // counts as fetched
}

type runner struct {
	st   Store
	ad   source.Adapter
	o    Options
	id   string
	src  string
	bulk bool
	log  *slog.Logger

	committed checkpoint.Counters
	version   string
}

// Run executes one Sync_Run. It returns ErrLocked (from checkpoint) without
// touching the graph when a live lock exists. A run that started and ended
// `failed` returns its Result and a non-nil error.
func Run(ctx context.Context, st Store, ad source.Adapter, o Options) (Result, error) {
	if o.BatchSize == 0 {
		o.BatchSize = DefaultBatchSize
	}
	if err := ValidateBatchSize(o.BatchSize); err != nil {
		return Result{}, err
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.Owner == "" {
		o.Owner = ulid.Make().String()
	}
	log := o.Log
	if log == nil {
		log = slog.Default()
	}
	name := ad.Name()
	if !source.ValidName(name) {
		return Result{}, fmt.Errorf("pipeline: invalid adapter name %q", name)
	}

	lease, err := st.Acquire(ctx, name, o.Owner)
	if err != nil {
		return Result{}, err
	}
	defer lease.Release(ctx) //nolint:errcheck // Release uses its own context; a stale lock expires
	hctx, stop := lease.Hold(ctx)
	defer stop()

	id, err := checkpoint.NewRunID(o.Now())
	if err != nil {
		return Result{}, err
	}
	if err := st.StartRun(hctx, id, name, o.Now()); err != nil {
		return Result{}, fmt.Errorf("pipeline: start run: %w", err)
	}
	r := &runner{st: st, ad: ad, o: o, id: id, src: name, log: log.With("source", name, "runId", id)}
	r.log.Info("sync run started", "sampleLimit", o.SampleLimit, "replay", o.ReplayDeadLetters)

	runErr := r.execute(hctx)
	status := checkpoint.FinalStatus(r.committed)
	msg := ""
	if runErr != nil {
		status = checkpoint.StatusFailed
		msg = runErr.Error()
		if hctx.Err() != nil {
			msg = "cancelled"
		}
	}
	if err := st.FinishRun(ctx, id, status, msg, o.Now()); err != nil {
		r.log.Error("finish run failed", "error", err.Error())
		if runErr == nil {
			runErr = fmt.Errorf("pipeline: finish run: %w", err)
		}
	}
	res := Result{RunID: id, Status: status, Counters: r.committed}
	if runErr != nil {
		r.log.Error("sync run failed", "error", msg)
		return res, fmt.Errorf("pipeline: %s: %w", name, runErr)
	}
	if o.SampleLimit == 0 && !o.ReplayDeadLetters && r.version != "" {
		if err := st.WriteVersion(context.WithoutCancel(ctx), name, r.version); err != nil {
			return res, fmt.Errorf("pipeline: %s: store version: %w", name, err)
		}
	}
	r.log.Info("sync run finished", "status", status, "fetched", r.committed.Fetched, "failed", r.committed.Failed)
	return res, nil
}

func (r *runner) execute(ctx context.Context) error {
	cp, err := r.st.ReadCheckpoint(ctx, r.src)
	if err != nil {
		return fmt.Errorf("read checkpoint: %w", err)
	}
	r.bulk = cp.Watermark.IsZero() && cp.Version == ""
	if r.o.ReplayDeadLetters {
		return r.replay(ctx)
	}
	sc := source.Checkpoint{Watermark: cp.Watermark, Resume: cp.Resume, Version: cp.Version}
	if !r.o.Since.IsZero() {
		sc = source.Checkpoint{Watermark: r.o.Since}
	}
	it, err := r.ad.Fetch(ctx, sc, source.RunOptions{SampleLimit: r.o.SampleLimit})
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	var items []item
	payloads := 0
	for {
		rec, nerr := it.Next(ctx)
		if nerr != nil {
			if err := r.flush(ctx, items); err != nil {
				return err
			}
			if errors.Is(nerr, io.EOF) {
				return nil
			}
			return fmt.Errorf("fetch: %w", nerr)
		}
		if rec.Cursor.Version != "" {
			r.version = rec.Cursor.Version
		}
		items = append(items, r.normalize(rec, false))
		if len(rec.Payload) > 0 {
			payloads++
		}
		if payloads >= r.o.BatchSize {
			if err := r.flush(ctx, items); err != nil {
				return err
			}
			items, payloads = nil, 0
		}
	}
}

func (r *runner) replay(ctx context.Context) error {
	dls, err := r.st.ListDeadLetters(ctx, r.src, checkpoint.KindFailed)
	if err != nil {
		return fmt.Errorf("list dead letters: %w", err)
	}
	var items []item
	for i, d := range dls {
		items = append(items, r.normalize(source.Record{ID: d.RecordID, Payload: d.Payload}, true))
		if len(items) >= r.o.BatchSize || i == len(dls)-1 {
			if err := r.flush(ctx, items); err != nil {
				return err
			}
			items = nil
		}
	}
	return nil
}

// normalize runs the adapter's Normalize and classifies the record.
func (r *runner) normalize(rec source.Record, replay bool) item {
	it := item{rec: rec, replay: replay, payload: len(rec.Payload) > 0}
	if !it.payload {
		return it // cursor marker
	}
	n, err := r.ad.Normalize(rec)
	if err != nil {
		it.dead = r.deadLetter(rec, err)
		return it
	}
	it.d = &upsert.Desired{ID: rec.ID, N: n}
	return it
}

func (r *runner) deadLetter(rec source.Record, err error) *checkpoint.DeadLetter {
	return &checkpoint.DeadLetter{
		Source: r.src, RecordID: rec.ID, Kind: checkpoint.KindFailed,
		Payload: rec.Payload, Error: truncate(err.Error()), FailedAt: r.o.Now(),
	}
}

func truncate(s string) string {
	const max = 1000
	if len(s) > max {
		return s[:max]
	}
	return s
}

// flush commits items as one transaction. A non-transient client error
// replays the items one per transaction and dead-letters the failing record.
func (r *runner) flush(ctx context.Context, items []item) error {
	if len(items) == 0 {
		return nil
	}
	err := r.commit(ctx, items)
	if err == nil {
		return nil
	}
	if graph.Classify(err) != graph.ClassClient {
		return fmt.Errorf("batch: %w", err)
	}
	r.log.Warn("batch failed; replaying one record per transaction", "error", err.Error())
	for _, it := range items {
		err := r.commit(ctx, []item{it})
		if err == nil {
			continue
		}
		if graph.Classify(err) != graph.ClassClient || it.dead != nil || it.d == nil {
			return fmt.Errorf("record %s: %w", it.rec.ID, err)
		}
		it.dead = r.deadLetter(it.rec, err)
		it.d = nil
		if err := r.commit(ctx, []item{it}); err != nil {
			return fmt.Errorf("dead-letter record %s: %w", it.rec.ID, err)
		}
	}
	return nil
}

// commit runs one transaction for items with the batch retry policy and, on
// success, advances the in-memory counters.
func (r *runner) commit(ctx context.Context, items []item) error {
	var next checkpoint.Counters
	err := graph.Retry(ctx, graph.BatchPolicy, r.o.Sleep, func(ctx context.Context) error {
		return r.st.InTx(ctx, func(ctx context.Context, tx Tx) error {
			var b upsert.Batch
			for _, it := range items {
				if it.d != nil {
					b = append(b, *it.d)
				}
			}
			var cnt upsert.Counts
			if len(b) > 0 {
				state, err := tx.Load(ctx, b)
				if err != nil {
					return err
				}
				w, recs, c := upsert.Plan(state, b, upsert.RunContext{
					Source: r.src, RunID: r.id, Now: r.o.Now(), Bulk: r.bulk})
				cnt = c
				if len(w.Nodes) > 0 || len(w.Rels) > 0 || len(recs) > 0 || len(w.RecomputeCVEs) > 0 {
					if err := tx.Apply(ctx, w, recs); err != nil {
						return err
					}
				}
			}
			next = r.advance(items, cnt)
			if err := tx.UpdateRun(ctx, r.id, next, checkpoint.Progress{Step: StepUpsert, Processed: next.Fetched}); err != nil {
				return err
			}
			for _, it := range items {
				switch {
				case it.dead != nil:
					if err := tx.PutDeadLetter(ctx, *it.dead); err != nil {
						return err
					}
				case it.replay && it.d != nil:
					if err := tx.DeleteDeadLetter(ctx, r.src, it.rec.ID, checkpoint.KindFailed); err != nil {
						return err
					}
				}
			}
			last := items[len(items)-1]
			c := last.rec.Cursor
			if r.o.SampleLimit == 0 && !last.replay && (c.Resume != "" || !c.Watermark.IsZero()) {
				return tx.WriteCursor(ctx, r.src, c.Resume, c.Watermark)
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	r.committed = next
	return nil
}

// advance returns the committed counters plus the effect of items.
func (r *runner) advance(items []item, cnt upsert.Counts) checkpoint.Counters {
	c := r.committed
	c.WarningIDs = append([]string(nil), r.committed.WarningIDs...)
	c.Created += int64(cnt.Created)
	c.Updated += int64(cnt.Updated)
	c.Unchanged += int64(cnt.Unchanged)
	c.Skipped += int64(cnt.Skipped)
	c.MissingFields += int64(cnt.Missing)
	c.Unresolved += int64(cnt.Unresolved)
	c.Warnings += int64(cnt.Rejected) // rejected identifiers have no record-level id
	for _, it := range items {
		if it.payload {
			c.Fetched++
		}
		if it.dead != nil {
			c.Failed++
		}
		if it.d == nil {
			continue
		}
		for _, n := range it.d.N.Notes {
			switch n.Kind {
			case "warning":
				c.AddWarning(n.ID)
			case "unresolved":
				c.Unresolved++
			}
		}
	}
	return c
}
