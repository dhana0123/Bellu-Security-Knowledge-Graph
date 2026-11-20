package baseline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/change"
	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/provenance"
)

// StepFinalize is the last step: it writes the summary Change_Record and
// BuildMeta.baselineLoadedAt. A load is complete when this step is complete.
const StepFinalize = "finalize"

// StepRetries and StepRetryDelay are the loader's transient-failure policy
// (Requirement 4.15): 3 retries, 5 s apart.
const (
	StepRetries    = 3
	StepRetryDelay = 5 * time.Second
)

// LoadTimeout is the per-statement timeout of the loader's graph client. Whole-graph
// statements (steps 12 to 14) run for minutes on the full baseline.
const LoadTimeout = 30 * time.Minute

// Step is one named unit of the load. Run must be safe to rerun from its start.
type Step struct {
	Name string
	Run  func(ctx context.Context) error
}

func wrapRes(fn func(context.Context) (StepResult, error)) func(context.Context) error {
	return func(ctx context.Context) error { _, err := fn(ctx); return err }
}

// StepList returns the 14 VulKG steps followed by the finalize step, in order.
func (l Loader) StepList() []Step {
	return []Step{
		{StepVulnNodes, wrapRes(l.VulnNodes)},
		{StepExploitNodes, wrapRes(l.ExploitNodes)},
		{StepAuthorNodes, wrapRes(l.AuthorNodes)},
		{StepWrites, wrapRes(l.Writes)},
		{StepExploitsRel, wrapRes(l.ExploitsRel)},
		{StepWeaknessNodes, wrapRes(l.WeaknessNodes)},
		{StepExampleOf, wrapRes(l.ExampleOf)},
		{StepVulnAddProps, wrapRes(l.VulnAddProps)},
		{StepDomainRefers, wrapRes(l.DomainRefers)},
		{StepProductAffects, wrapRes(l.ProductAffects)},
		{StepVendorBelongs, wrapRes(l.VendorBelongs)},
		{StepAffectedVer, wrapRes(l.AffectedVersion)},
		{StepRejectDelete, wrapRes(l.RejectDelete)},
		{StepExploitability, wrapRes(l.Exploitability)},
		{StepFinalize, l.Finalize},
	}
}

// RunState is the identity and progress of one load, stored on the Job node.
type RunState struct {
	RunID         string // the load's single Sync_Run id
	Commit        string // upstream commit of the manifest
	StartedAt     time.Time
	LastCompleted string
}

// JobStore persists RunState.
type JobStore interface {
	// Read returns the stored state; ok is false when no load was started.
	Read(ctx context.Context) (st RunState, ok bool, err error)
	// Start resets the job (clearing every counter) and records a new run.
	Start(ctx context.Context, st RunState) error
	Complete(ctx context.Context, step string) error
}

// GraphJobStore is the Neo4j-backed JobStore.
type GraphJobStore struct{ C *graph.Client }

const (
	cypherRunStart = `MERGE (j:Job {name: $name})
SET j = {name: $name, runId: $runId, commit: $commit, startedAt: $at}`
	cypherRunRead = `OPTIONAL MATCH (j:Job {name: $name})
RETURN j.runId AS runId, j.commit AS commit, j.startedAt AS at, j.lastCompletedStep AS last`
)

// Read implements JobStore.
func (s GraphJobStore) Read(ctx context.Context) (RunState, bool, error) {
	v, err := s.C.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypherRunRead, map[string]any{"name": JobName})
		if err != nil {
			return nil, err
		}
		rec, err := res.Single(ctx)
		if err != nil {
			return nil, err
		}
		var st RunState
		id, _ := rec.Values[0].(string)
		st.RunID = id
		st.Commit, _ = rec.Values[1].(string)
		if at, ok := rec.Values[2].(string); ok {
			st.StartedAt, _ = time.Parse(time.RFC3339Nano, at)
		}
		st.LastCompleted, _ = rec.Values[3].(string)
		return st, nil
	})
	if err != nil {
		return RunState{}, false, fmt.Errorf("read baseline job: %w", err)
	}
	st := v.(RunState)
	return st, st.RunID != "", nil
}

// Start implements JobStore.
func (s GraphJobStore) Start(ctx context.Context, st RunState) error {
	_, err := s.C.WriteRetry(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		return nil, runJob(ctx, tx, cypherRunStart, map[string]any{
			"name": JobName, "runId": st.RunID, "commit": st.Commit,
			"at": st.StartedAt.UTC().Format(time.RFC3339Nano),
		})
	})
	if err != nil {
		return fmt.Errorf("start baseline job: %w", err)
	}
	return nil
}

// Complete implements JobStore.
func (s GraphJobStore) Complete(ctx context.Context, step string) error {
	return (Jobs{C: s.C}).Complete(ctx, step)
}

// Runner executes an ordered step list, skipping completed steps and
// retrying transient failures.
type Runner struct {
	Store  JobStore
	Commit string
	// Build returns the step list bound to the run (the Loader carries RunID and At).
	Build func(st RunState) []Step
	// NewRunID returns a fresh Sync_Run id.
	NewRunID func(at time.Time) (string, error)
	Now      func() time.Time

	Retries int           // default StepRetries
	Delay   time.Duration // default StepRetryDelay
	Sleep   graph.SleepFunc
	Log     *slog.Logger
}

// Run performs the load and returns its state. A load is resumed when the
// stored job belongs to the same commit and did not finish; otherwise a new
// load starts. Completed steps are skipped, and the interrupted step reruns
// from its start.
func (r Runner) Run(ctx context.Context) (RunState, error) {
	log := r.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	retries, delay := r.Retries, r.Delay
	if retries == 0 {
		retries = StepRetries
	}
	if delay == 0 {
		delay = StepRetryDelay
	}
	sleep := r.Sleep
	if sleep == nil {
		sleep = graph.RealSleep
	}
	now := r.Now
	if now == nil {
		now = time.Now
	}

	st, ok, err := r.Store.Read(ctx)
	if err != nil {
		return RunState{}, err
	}
	resume := ok && st.Commit == r.Commit && st.LastCompleted != StepFinalize && !st.StartedAt.IsZero()
	if !resume {
		at := now().UTC().Truncate(time.Millisecond)
		id, err := r.NewRunID(at)
		if err != nil {
			return RunState{}, fmt.Errorf("new run id: %w", err)
		}
		st = RunState{RunID: id, Commit: r.Commit, StartedAt: at}
	}
	steps := r.Build(st)
	start := 0
	if resume && st.LastCompleted != "" {
		start = -1
		for i, s := range steps {
			if s.Name == st.LastCompleted {
				start = i + 1
				break
			}
		}
		if start < 0 {
			return st, fmt.Errorf("stored last completed step %q is not a known step", st.LastCompleted)
		}
	}
	if start == 0 {
		// No completed step: clear every counter left by an earlier attempt.
		st.LastCompleted = ""
		if err := r.Store.Start(ctx, st); err != nil {
			return st, err
		}
		log.Info("baseline load started", "runId", st.RunID, "commit", st.Commit)
	} else {
		log.Info("baseline load resumed", "runId", st.RunID, "afterStep", st.LastCompleted)
	}
	for _, s := range steps[start:] {
		if err := r.runStep(ctx, s, retries, delay, sleep, log); err != nil {
			return st, err
		}
		if err := r.Store.Complete(ctx, s.Name); err != nil {
			return st, fmt.Errorf("step %s: mark complete: %w", s.Name, err)
		}
		st.LastCompleted = s.Name
	}
	return st, nil
}

// runStep runs one step, retrying transient errors. A non-transient error or
// the last transient error fails the load and names the step.
func (r Runner) runStep(ctx context.Context, s Step, retries int, delay time.Duration, sleep graph.SleepFunc, log *slog.Logger) error {
	for attempt := 0; ; attempt++ {
		log.Info("baseline step", "step", s.Name, "attempt", attempt+1)
		err := s.Run(ctx)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("baseline load stopped in step %s: %w", s.Name, err)
		}
		if graph.Classify(err) != graph.ClassTransient || attempt >= retries {
			return fmt.Errorf("baseline load failed in step %s: %w", s.Name, err)
		}
		log.Warn("baseline step failed, retrying", "step", s.Name, "attempt", attempt+1, "retryIn", delay.String())
		if serr := sleep(ctx, delay); serr != nil {
			return fmt.Errorf("baseline load stopped in step %s: %w", s.Name, errors.Join(err, serr))
		}
	}
}

// Summary queries (constant text; labels and types are the VulKG schema).
var (
	summaryLabels = []struct{ name, q string }{
		{"Vulnerability", `MATCH (n:Vulnerability) RETURN count(n)`},
		{"Exploit", `MATCH (n:Exploit) RETURN count(n)`},
		{"Author", `MATCH (n:Author) RETURN count(n)`},
		{"Weakness", `MATCH (n:Weakness) RETURN count(n)`},
		{"Domain", `MATCH (n:Domain) RETURN count(n)`},
		{"Product", `MATCH (n:Product) RETURN count(n)`},
		{"Vendor", `MATCH (n:Vendor) RETURN count(n)`},
	}
	summaryTypes = []struct{ name, q string }{
		{"WRITES", `MATCH ()-[r:WRITES]->() RETURN count(r)`},
		{"EXPLOITS", `MATCH ()-[r:EXPLOITS]->() RETURN count(r)`},
		{"EXAMPLE_OF", `MATCH ()-[r:EXAMPLE_OF]->() RETURN count(r)`},
		{"REFERS_TO", `MATCH ()-[r:REFERS_TO]->() RETURN count(r)`},
		{"AFFECTS", `MATCH ()-[r:AFFECTS]->() RETURN count(r)`},
		{"BELONGS_TO", `MATCH ()-[r:BELONGS_TO]->() RETURN count(r)`},
	}

	cypherChangeExists = `MATCH (c:Change {entityKey: $key, type: $type}) RETURN count(c)`
	cypherBaselineMeta = `MERGE (b:BuildMeta {id: 'build'})
SET b.baselineLoadedAt = datetime($at)`
)

func (l Loader) count(ctx context.Context, q string) (int64, error) {
	v, err := l.W.C.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, q, nil)
		if err != nil {
			return nil, err
		}
		rec, err := res.Single(ctx)
		if err != nil {
			return nil, err
		}
		n, _ := rec.Values[0].(int64)
		return n, nil
	})
	if err != nil {
		return 0, err
	}
	return v.(int64), nil
}

// Finalize counts the loaded graph, then writes the single baselineLoad
// Change_Record and BuildMeta.baselineLoadedAt in one transaction. A rerun
// does not write a second record for the same run.
func (l Loader) Finalize(ctx context.Context) error {
	sum := change.BaselineSummary{Commit: l.Ref, NodesByLabel: map[string]int64{}, RelsByType: map[string]int64{}}
	for _, s := range summaryLabels {
		n, err := l.count(ctx, s.q)
		if err != nil {
			return fmt.Errorf("count %s: %w", s.name, err)
		}
		sum.NodesByLabel[s.name] = n
		sum.Nodes += n
	}
	for _, s := range summaryTypes {
		n, err := l.count(ctx, s.q)
		if err != nil {
			return fmt.Errorf("count %s: %w", s.name, err)
		}
		sum.RelsByType[s.name] = n
		sum.Relationships += n
	}
	at := l.At
	if at.IsZero() {
		at = time.Now()
	}
	rec, err := change.NewBaselineLoad(l.RunID, provenance.SourceVulKG, sum, at)
	if err != nil {
		return err
	}
	loaded := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = l.W.C.WriteRetry(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypherChangeExists, map[string]any{"key": rec.EntityKey, "type": rec.Type})
		if err != nil {
			return nil, err
		}
		r, err := res.Single(ctx)
		if err != nil {
			return nil, err
		}
		if n, _ := r.Values[0].(int64); n == 0 {
			if err := change.Write(ctx, tx, rec); err != nil {
				return nil, err
			}
		}
		return nil, runJob(ctx, tx, cypherBaselineMeta, map[string]any{"at": loaded})
	})
	if err != nil {
		return fmt.Errorf("write baseline summary: %w", err)
	}
	return nil
}

// LoadOptions configures Load.
type LoadOptions struct {
	Manifest  *Manifest
	Fetcher   *Fetcher
	Client    *graph.Client // should use LoadTimeout
	BatchSize int
	Log       *slog.Logger
	Sleep     graph.SleepFunc // tests only
	RetryWait time.Duration   // tests only; default StepRetryDelay
}

// Load fetches and verifies the baseline files, then runs (or resumes) the load.
func Load(ctx context.Context, o LoadOptions) (RunState, error) {
	if err := ValidateBatchSize(o.BatchSize); err != nil {
		return RunState{}, err
	}
	files, err := o.Fetcher.Fetch(ctx, o.Manifest)
	if err != nil {
		return RunState{}, err
	}
	commit := o.Manifest.Upstream.Commit
	r := Runner{
		Store:  GraphJobStore{C: o.Client},
		Commit: commit,
		Build: func(st RunState) []Step {
			return Loader{
				W:     Writer{C: o.Client, BatchSize: o.BatchSize},
				Files: files, RunID: st.RunID, Ref: commit, At: st.StartedAt,
			}.StepList()
		},
		NewRunID: change.NewID,
		Sleep:    o.Sleep,
		Delay:    o.RetryWait,
		Log:      o.Log,
	}
	return r.Run(ctx)
}
