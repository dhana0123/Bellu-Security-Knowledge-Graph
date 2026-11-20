package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"pgregory.net/rapid"
)

type fakeStore struct {
	jobs     map[string]JobRecord
	states   []string
	complete bool
}

func newStore() *fakeStore { return &fakeStore{jobs: map[string]JobRecord{}} }

func (f *fakeStore) LoadJob(_ context.Context, n string) (JobRecord, error) { return f.jobs[n], nil }
func (f *fakeStore) SaveJob(_ context.Context, n string, r JobRecord) error {
	f.jobs[n] = r
	return nil
}
func (f *fakeStore) SetBuildState(_ context.Context, s string) error {
	f.states = append(f.states, s)
	return nil
}
func (f *fakeStore) SetQueueComplete(_ context.Context, c bool) error { f.complete = c; return nil }

type harness struct {
	st     *fakeStore
	calls  []string
	sleeps []time.Duration
	q      *Queue
}

// newHarness builds the three-job queue; outcomes[name] gives the error for
// each successive attempt (nil = success; missing = success).
func newHarness(st *fakeStore, outcomes map[string][]error, cont bool) *harness {
	h := &harness{st: st}
	count := map[string]int{}
	mk := func(name, state string) Job {
		return Job{Name: name, BuildState: state, Run: func(context.Context) error {
			h.calls = append(h.calls, name)
			i := count[name]
			count[name]++
			if o := outcomes[name]; i < len(o) {
				return o[i]
			}
			return nil
		}}
	}
	h.q = &Queue{
		Jobs:  []Job{mk(JobMigrate, StateMigrating), mk(JobBaselineLoad, StateLoadingBase), mk(JobBaselineValidate, StateValidating)},
		Store: st, ContinueOnValidationFail: cont,
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sleep: func(_ context.Context, d time.Duration) error { h.sleeps = append(h.sleeps, d); return nil },
	}
	return h
}

func TestHappyPath(t *testing.T) {
	h := newHarness(newStore(), nil, false)
	out, err := h.q.Run(context.Background())
	if err != nil || !out.Complete {
		t.Fatalf("%+v %v", out, err)
	}
	if !reflect.DeepEqual(h.calls, []string{JobMigrate, JobBaselineLoad, JobBaselineValidate}) {
		t.Fatal(h.calls)
	}
	if !reflect.DeepEqual(h.st.states, []string{StateMigrating, StateLoadingBase, StateValidating, StateReady}) || !h.st.complete {
		t.Fatal(h.st.states)
	}
}

func TestRetrySchedule(t *testing.T) {
	boom := errors.New("boom")
	h := newHarness(newStore(), map[string][]error{JobBaselineLoad: {boom, boom, boom}}, false)
	out, _ := h.q.Run(context.Background())
	if !out.Complete {
		t.Fatalf("%+v", out)
	}
	if !reflect.DeepEqual(h.sleeps, []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second}) {
		t.Fatal(h.sleeps)
	}
	if h.st.jobs[JobBaselineLoad].Attempts != 4 {
		t.Fatal(h.st.jobs[JobBaselineLoad])
	}
}

func TestExhaustedStopsQueue(t *testing.T) {
	boom := errors.New("boom")
	h := newHarness(newStore(), map[string][]error{JobBaselineLoad: {boom, boom, boom, boom, boom}}, false)
	out, err := h.q.Run(context.Background())
	if err != nil || out.Complete || out.StoppedAt != JobBaselineLoad {
		t.Fatalf("%+v %v", out, err)
	}
	if n := countOf(h.calls, JobBaselineLoad); n != 4 {
		t.Fatalf("attempts %d", n)
	}
	if countOf(h.calls, JobBaselineValidate) != 0 {
		t.Fatal("validate must not start")
	}
	if h.st.jobs[JobBaselineLoad].State != JobFailed || h.st.states[len(h.st.states)-1] != StateLoadingBase {
		t.Fatal(h.st.jobs, h.st.states)
	}
}

func TestRestartSkipsSucceeded(t *testing.T) {
	st := newStore()
	st.jobs[JobMigrate] = JobRecord{State: JobSucceeded, Attempts: 1}
	st.jobs[JobBaselineLoad] = JobRecord{State: JobRunning, Attempts: 1}
	h := newHarness(st, nil, false)
	if out, _ := h.q.Run(context.Background()); !out.Complete {
		t.Fatal("not complete")
	}
	if !reflect.DeepEqual(h.calls, []string{JobBaselineLoad, JobBaselineValidate}) {
		t.Fatal(h.calls)
	}
}

func TestValidationFailure(t *testing.T) {
	failed := fmt.Errorf("report: %w", ErrValidationFailed)
	h := newHarness(newStore(), map[string][]error{JobBaselineValidate: {failed}}, false)
	out, _ := h.q.Run(context.Background())
	if out.Complete || out.StoppedAt != JobBaselineValidate || len(h.sleeps) != 0 {
		t.Fatalf("%+v %v", out, h.sleeps)
	}
	if countOf(h.calls, JobBaselineValidate) != 1 {
		t.Fatal("validation must not be retried")
	}

	h = newHarness(newStore(), map[string][]error{JobBaselineValidate: {failed}}, true)
	if out, _ := h.q.Run(context.Background()); !out.Complete {
		t.Fatalf("continue flag should complete: %+v", out)
	}
	if h.st.jobs[JobBaselineValidate].State != JobValidationFailed {
		t.Fatal(h.st.jobs)
	}
}

func TestDelay(t *testing.T) {
	if _, ok := Delay(0); ok {
		t.Fatal()
	}
	if _, ok := Delay(4); ok {
		t.Fatal()
	}
	if d, _ := Delay(3); d != 40*time.Second {
		t.Fatal(d)
	}
}

func countOf(s []string, v string) int {
	n := 0
	for _, x := range s {
		if x == v {
			n++
		}
	}
	return n
}

// Feature: bellu-security-knowledge-graph, Property 46: Build queue semantics
// **Validates: Requirements 26.1, 26.3, 26.4, 26.5, 26.6**
func TestPropertyQueueSemantics(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		names := []string{JobMigrate, JobBaselineLoad, JobBaselineValidate}
		cont := rapid.Bool().Draw(t, "cont")
		st := newStore()
		var started []string
		// outcome per job: 0 ok, 1 fails n times (0..5), 2 validation failure (validate only)
		failN := map[string]int{}
		valFail := rapid.Bool().Draw(t, "valFail")
		for _, n := range names {
			failN[n] = rapid.IntRange(0, 5).Draw(t, "fail"+n)
		}
		attempts := map[string]int{}
		mk := func(name string) Job {
			return Job{Name: name, BuildState: name, Run: func(context.Context) error {
				for _, p := range names {
					if p == name {
						break
					}
					if st.jobs[p].State != JobSucceeded && !(st.jobs[p].State == JobValidationFailed && cont) {
						t.Fatalf("%s started before %s done", name, p)
					}
				}
				started = append(started, name)
				attempts[name]++
				if attempts[name] <= failN[name] {
					return errors.New("x")
				}
				if name == JobBaselineValidate && valFail {
					return ErrValidationFailed
				}
				return nil
			}}
		}
		var sleeps []time.Duration
		q := &Queue{Store: st, ContinueOnValidationFail: cont, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Sleep: func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil }}
		for _, n := range names {
			q.Jobs = append(q.Jobs, mk(n))
		}
		// Pre-succeed a random prefix to model restarts.
		skip := rapid.IntRange(0, 3).Draw(t, "skip")
		for i := 0; i < skip; i++ {
			st.jobs[names[i]] = JobRecord{State: JobSucceeded}
		}
		out, err := q.Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < skip; i++ {
			if attempts[names[i]] != 0 {
				t.Fatal("succeeded job was rerun")
			}
		}
		for _, n := range names {
			if attempts[n] > 4 {
				t.Fatalf("%s ran %d attempts", n, attempts[n])
			}
		}
		for _, d := range sleeps {
			if d != 10*time.Second && d != 20*time.Second && d != 40*time.Second {
				t.Fatal(d)
			}
		}
		// Expected stop point.
		stop := ""
		for i := skip; i < 3; i++ {
			n := names[i]
			if failN[n] >= 4 {
				stop = n
				break
			}
			if n == JobBaselineValidate && valFail && !cont {
				stop = n
			}
		}
		if (stop == "") != out.Complete || out.StoppedAt != stop {
			t.Fatalf("stop=%q out=%+v", stop, out)
		}
	})
}
