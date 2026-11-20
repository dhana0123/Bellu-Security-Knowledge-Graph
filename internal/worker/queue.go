// Package worker runs the Build_Job_Queue: an ordered list of named jobs
// (migrate, baseline-load, baseline-validate, later nvd-catch-up) with retry,
// persisted state, and a buildState value written at every transition.
//
// Persistence: each job is a (:Job {name}) node. The baseline loader already
// owns (:Job {name:"baseline-load"}) for step progress (currentStep,
// rowsDone, ...). The queue therefore writes only properties prefixed with
// "queue" (queueState, queueAttempts, queueError, queueUpdatedAt) and never
// touches the loader's properties. buildState lives on (:BuildMeta {id:"build"}).
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
	JobMigrate          = "migrate"
	JobBaselineLoad     = "baseline-load"
	JobBaselineValidate = "baseline-validate"
)

// Build states written to (:BuildMeta).buildState. A stopped queue keeps the
// state of the job that failed, so there is no separate failed state.
const (
	StateMigrating   = "migrating"
	StateLoadingBase = "loading_baseline"
	StateValidating  = "validating"
	StateNVDCatchUp  = "nvd_catch_up"
	StateReady       = "ready"
)

// Queue job states stored in (:Job).queueState.
const (
	JobRunning   = "running"
	JobSucceeded = "succeeded"
	JobFailed    = "failed"
	// JobValidationFailed means the job ran to completion but its report
	// failed. It is not retried. It counts as done only when the continue
	// flag is set.
	JobValidationFailed = "validation_failed"
)

// MaxRetries is the number of retries after the first attempt.
const MaxRetries = 3

// RetryDelays are the waits before retry 1, 2 and 3 (Requirement 26.4).
var RetryDelays = [MaxRetries]time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second}

// ErrValidationFailed is returned (possibly wrapped) by a job whose run
// completed with a failed report. It is a result, not an error: no retry.
var ErrValidationFailed = errors.New("validation report failed")

// Job is one named step of the queue.
type Job struct {
	Name       string
	BuildState string // written to BuildMeta before the job starts
	Run        func(ctx context.Context) error
}

// JobRecord is the persisted queue state of a job.
type JobRecord struct {
	State    string // "" when the job never ran
	Attempts int
	Error    string
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
	Jobs                     []Job
	Store                    Store
	ContinueOnValidationFail bool
	Log                      *slog.Logger
	// Sleep waits for d or until ctx is done. Defaults to a timer wait.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Next returns the index of the first job that is not done, or len(jobs)
// when all are done. It is pure: recs[i] is the persisted record of jobs[i].
func Next(recs []JobRecord, continueOnValidationFail bool) int {
	for i, r := range recs {
		if !Done(r, continueOnValidationFail) {
			return i
		}
	}
	return len(recs)
}

// Done reports whether a job is finished and may be skipped.
func Done(r JobRecord, continueOnValidationFail bool) bool {
	switch r.State {
	case JobSucceeded:
		return true
	case JobValidationFailed:
		return continueOnValidationFail
	}
	return false
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
	if err := q.Store.SetQueueComplete(ctx, false); err != nil {
		return Outcome{}, err
	}
	for i := Next(recs, q.ContinueOnValidationFail); i < len(q.Jobs); i++ {
		if Done(recs[i], q.ContinueOnValidationFail) {
			continue // done jobs after the first pending one cannot occur; defensive
		}
		j := q.Jobs[i]
		if err := q.Store.SetBuildState(ctx, j.BuildState); err != nil {
			return Outcome{}, err
		}
		rec, err := q.runJob(ctx, j, recs[i], sleep, log)
		if err != nil {
			return Outcome{}, err
		}
		recs[i] = rec
		if !Done(rec, q.ContinueOnValidationFail) {
			log.Error("build queue stopped", "job", j.Name, "state", rec.State)
			return Outcome{StoppedAt: j.Name, Err: errors.New(rec.Error)}, nil
		}
		if rec.State == JobValidationFailed {
			log.Warn("validation failed; continuing because BSKG_CONTINUE_ON_VALIDATION_FAILURE is set", "job", j.Name)
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
func (q *Queue) runJob(ctx context.Context, j Job, prev JobRecord, sleep func(context.Context, time.Duration) error, log *slog.Logger) (JobRecord, error) {
	rec := JobRecord{}
	for attempt := 1; ; attempt++ {
		rec = JobRecord{State: JobRunning, Attempts: attempt}
		if err := q.Store.SaveJob(ctx, j.Name, rec); err != nil {
			return rec, err
		}
		runErr := j.Run(ctx)
		if ctx.Err() != nil {
			return rec, ctx.Err() // cancelled: leave the job "running" so it resumes
		}
		switch {
		case runErr == nil:
			rec.State = JobSucceeded
			return rec, q.Store.SaveJob(ctx, j.Name, rec)
		case errors.Is(runErr, ErrValidationFailed):
			rec.State, rec.Error = JobValidationFailed, truncate(runErr.Error())
			return rec, q.Store.SaveJob(ctx, j.Name, rec)
		}
		rec.Error = truncate(runErr.Error())
		d, ok := Delay(attempt)
		if !ok {
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
