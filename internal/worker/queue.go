// Package worker runs the Build_Job_Queue: an ordered list of named jobs
// (migrate, cwe, nvd-catch-up, exploitdb) with retry, persisted state, and a
// buildState value written at every transition (Requirement 11).
//
// Persistence: each job is a (:Job {name}) node with the properties
// queueState, queueAttempts, queueError, queueMode, queueLimit, queueOrder,
// queueStartedAt, queueEndedAt, queueUpdatedAt. buildState lives on
// (:BuildMeta {id:"build"}).
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Job names in queue order.
const (
	JobMigrate  = "migrate"
	JobCWE      = "cwe"
	JobNVD      = "nvd-catch-up"
	JobExploits = "exploitdb"
)

// Build states written to (:BuildMeta).buildState. The value names the job
// that is running. A stopped queue keeps the state of the job that failed.
const (
	StateMigrating      = "migrating"
	StateLoadingCWE     = "loading_cwe"
	StateNVDCatchUp     = "nvd_catch_up"
	StateLoadingExploit = "loading_exploits"
	StateReady          = "ready"
)

// Queue job states stored in (:Job).queueState.
const (
	JobRunning   = "running"
	JobSucceeded = "succeeded"
	JobFailed    = "failed"
)

// MaxRetries is the number of retries after the first attempt.
const MaxRetries = 3

// RetryDelays are the waits before retry 1, 2 and 3 (Requirement 11.5).
var RetryDelays = [MaxRetries]time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second}

// ErrNotImplemented is returned by a job whose source adapter does not exist
// yet. It is not retried: the queue stops and the failure is reported.
var ErrNotImplemented = errors.New("job not implemented")

// RunOptions are the build mode and sample limit a job runs with.
type RunOptions struct {
	Mode  string
	Limit int
	// Order is the sample order, "first" or "latest". Empty means "first".
	Order string
}

// order returns the sample order with the default applied.
func order(s string) string {
	if s == "" {
		return "first"
	}
	return s
}

// Job is one named step of the queue.
type Job struct {
	Name       string
	BuildState string // written to BuildMeta before the job starts
	// ModeSpecific jobs are done only for the build mode and sample limit
	// they succeeded with (NVD and Exploit-DB).
	ModeSpecific bool
	Run          func(ctx context.Context, opts RunOptions) error
}

// JobRecord is the persisted queue state of a job.
type JobRecord struct {
	State    string // "" when the job never ran
	Attempts int
	Error    string
	Mode     string // build mode of the last run
	Limit    int    // sample limit of the last run
	Order    string // sample order of the last run; empty means "first"
}

// Store persists queue state.
type Store interface {
	LoadJob(ctx context.Context, name string) (JobRecord, error)
	SaveJob(ctx context.Context, name string, rec JobRecord) error
	SetBuildState(ctx context.Context, state string) error
	SetQueueComplete(ctx context.Context, complete bool) error
}

// Outcome is the result of a queue pass.
type Outcome struct {
	Complete  bool   // every job done; buildState is ready
	StoppedAt string // job name that stopped the queue, empty when Complete
	Err       error  // reason it stopped
}

// Queue runs jobs in order.
type Queue struct {
	Jobs  []Job
	Store Store
	Opts  RunOptions
	Log   *slog.Logger
	// Sleep waits for d or until ctx is done. Defaults to a timer wait.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Done reports whether a job is finished for the given mode and limit and may
// be skipped.
func Done(j Job, r JobRecord, opts RunOptions) bool {
	if r.State != JobSucceeded {
		return false
	}
	if j.ModeSpecific {
		return r.Mode == opts.Mode && r.Limit == opts.Limit && order(r.Order) == order(opts.Order)
	}
	return true
}

// Next returns the index of the first job that is not done, or len(jobs) when
// all are done. It is pure: recs[i] is the persisted record of jobs[i].
func Next(jobs []Job, recs []JobRecord, opts RunOptions) int {
	for i, j := range jobs {
		if !Done(j, recs[i], opts) {
			return i
		}
	}
	return len(jobs)
}

// Delay returns the wait before the given retry (1-based), or false when
// retries are exhausted.
func Delay(retry int) (time.Duration, bool) {
	if retry < 1 || retry > MaxRetries {
		return 0, false
	}
	return RetryDelays[retry-1], true
}

func sleepTimer(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (q *Queue) logger() *slog.Logger {
	if q.Log != nil {
		return q.Log
	}
	return slog.Default()
}

// Run executes the queue once. Jobs already done are skipped. A job starts
// only after its predecessor is done. It returns an error only for
// persistence failures or cancellation; a stopped queue is reported in Outcome.
func (q *Queue) Run(ctx context.Context) (Outcome, error) {
	sleep := q.Sleep
	if sleep == nil {
		sleep = sleepTimer
	}
	log := q.logger()
	recs := make([]JobRecord, len(q.Jobs))
	for i, j := range q.Jobs {
		r, err := q.Store.LoadJob(ctx, j.Name)
		if err != nil {
			return Outcome{}, fmt.Errorf("worker: load job %s: %w", j.Name, err)
		}
		recs[i] = r
	}
	first := Next(q.Jobs, recs, q.Opts)
	if first < len(q.Jobs) {
		if err := q.Store.SetQueueComplete(ctx, false); err != nil {
			return Outcome{}, err
		}
	}
	for i := first; i < len(q.Jobs); i++ {
		j := q.Jobs[i]
		if Done(j, recs[i], q.Opts) {
			continue
		}
		if err := q.Store.SetBuildState(ctx, j.BuildState); err != nil {
			return Outcome{}, err
		}
		rec, err := q.runJob(ctx, j, sleep, log)
		if err != nil {
			return Outcome{}, err
		}
		recs[i] = rec
		if rec.State != JobSucceeded {
			log.Error("build queue stopped", "job", j.Name, "state", rec.State)
			return Outcome{StoppedAt: j.Name, Err: errors.New(rec.Error)}, nil
		}
	}
	if err := q.Store.SetBuildState(ctx, StateReady); err != nil {
		return Outcome{}, err
	}
	if err := q.Store.SetQueueComplete(ctx, true); err != nil {
		return Outcome{}, err
	}
	return Outcome{Complete: true}, nil
}

// runJob runs one job with up to MaxRetries retries. The returned error is
// for persistence or cancellation only.
func (q *Queue) runJob(ctx context.Context, j Job, sleep func(context.Context, time.Duration) error, log *slog.Logger) (JobRecord, error) {
	rec := JobRecord{}
	for attempt := 1; ; attempt++ {
		rec = JobRecord{State: JobRunning, Attempts: attempt, Mode: q.Opts.Mode, Limit: q.Opts.Limit, Order: order(q.Opts.Order)}
		if err := q.Store.SaveJob(ctx, j.Name, rec); err != nil {
			return rec, err
		}
		runErr := j.Run(ctx, q.Opts)
		if ctx.Err() != nil {
			return rec, ctx.Err() // cancelled: leave the job "running" so it resumes
		}
		if runErr == nil {
			rec.State = JobSucceeded
			return rec, q.Store.SaveJob(ctx, j.Name, rec)
		}
		rec.Error = truncate(runErr.Error())
		d, ok := Delay(attempt)
		if !ok || errors.Is(runErr, ErrNotImplemented) {
			rec.State = JobFailed
			return rec, q.Store.SaveJob(ctx, j.Name, rec)
		}
		if err := q.Store.SaveJob(ctx, j.Name, rec); err != nil {
			return rec, err
		}
		log.Warn("job attempt failed; retrying", "job", j.Name, "attempt", attempt, "delay", d.String())
		if err := sleep(ctx, d); err != nil {
			return rec, err
		}
	}
}

func truncate(s string) string {
	const max = 500
	if len(s) > max {
		return s[:max]
	}
	return s
}
