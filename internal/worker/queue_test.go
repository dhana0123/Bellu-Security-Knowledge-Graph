package worker

import (
	"context"
	"errors"
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

var queueDef = []struct {
	name, state  string
	modeSpecific bool
}{
	{JobMigrate, StateMigrating, false},
	{JobCWE, StateLoadingCWE, false},
	{JobNVD, StateNVDCatchUp, true},
	{JobExploits, StateLoadingExploit, true},
	{"attack", StateLoadingAttack, false},
	{"atlas", StateLoadingAtlas, false},
	{"capec", StateLoadingCAPEC, false},
	{"kev", StateLoadingKEV, true},
	{"epss", StateLoadingEPSS, true},
	{"osv", StateLoadingOSV, true},
	{"ghsa", StateLoadingGHSA, true},
}

type harness struct {
	st     *fakeStore
	calls  []string
	sleeps []time.Duration
	q      *Queue
}

// newHarness builds the four-job queue; outcomes[name] gives the error for
// each successive attempt (nil = success; missing = success).
func newHarness(st *fakeStore, outcomes map[string][]error, opts RunOptions) *harness {
	h := &harness{st: st}
	count := map[string]int{}
	var jobs []Job
	for _, d := range queueDef {
		name := d.name
		jobs = append(jobs, Job{Name: name, BuildState: d.state, ModeSpecific: d.modeSpecific,
			Run: func(context.Context, RunOptions) error {
				h.calls = append(h.calls, name)
				i := count[name]
				count[name]++
				if o := outcomes[name]; i < len(o) {
					return o[i]
				}
				return nil
			}})
	}
	h.q = &Queue{
		Jobs: jobs, Store: st, Opts: opts,
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sleep: func(_ context.Context, d time.Duration) error { h.sleeps = append(h.sleeps, d); return nil },
	}
	return h
}

var full = RunOptions{Mode: "full"}
var sample = RunOptions{Mode: "sample", Limit: 1000}

func TestHappyPath(t *testing.T) {
	h := newHarness(newStore(), nil, full)
	out, err := h.q.Run(context.Background())
	if err != nil || !out.Complete {
		t.Fatalf("%+v %v", out, err)
	}
	if !reflect.DeepEqual(h.calls, jobNames(false)) {
		t.Fatal(h.calls)
	}
	var want []string
	for _, d := range queueDef {
		want = append(want, d.state)
	}
	want = append(want, StateReady)
	if !reflect.DeepEqual(h.st.states, want) || !h.st.complete {
		t.Fatal(h.st.states)
	}
}

func TestNoValidationJob(t *testing.T) {
	for _, d := range queueDef {
		if d.name == "baseline-validate" || d.name == "validate" {
			t.Fatal("the queue must not contain a validation job")
		}
	}
}

func TestRetrySchedule(t *testing.T) {
	boom := errors.New("boom")
	h := newHarness(newStore(), map[string][]error{JobCWE: {boom, boom, boom}}, full)
	out, _ := h.q.Run(context.Background())
	if !out.Complete {
		t.Fatalf("%+v", out)
	}
	if !reflect.DeepEqual(h.sleeps, []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second}) {
		t.Fatal(h.sleeps)
	}
	if h.st.jobs[JobCWE].Attempts != 4 {
		t.Fatal(h.st.jobs[JobCWE])
	}
}

func TestExhaustedStopsQueue(t *testing.T) {
	boom := errors.New("boom")
	h := newHarness(newStore(), map[string][]error{JobCWE: {boom, boom, boom, boom, boom}}, full)
	out, err := h.q.Run(context.Background())
	if err != nil || out.Complete || out.StoppedAt != JobCWE {
		t.Fatalf("%+v %v", out, err)
	}
	if n := countOf(h.calls, JobCWE); n != 4 {
		t.Fatalf("attempts %d", n)
	}
	if countOf(h.calls, JobNVD) != 0 {
		t.Fatal("nvd must not start")
	}
	if h.st.jobs[JobCWE].State != JobFailed || h.st.states[len(h.st.states)-1] != StateLoadingCWE {
		t.Fatal(h.st.jobs, h.st.states)
	}
}

func TestNotImplementedIsNotRetried(t *testing.T) {
	h := newHarness(newStore(), map[string][]error{JobCWE: {ErrNotImplemented}}, full)
	out, _ := h.q.Run(context.Background())
	if out.StoppedAt != JobCWE || len(h.sleeps) != 0 || countOf(h.calls, JobCWE) != 1 {
		t.Fatalf("%+v sleeps=%v calls=%v", out, h.sleeps, h.calls)
	}
}

func TestRestartSkipsSucceeded(t *testing.T) {
	st := newStore()
	st.jobs[JobMigrate] = JobRecord{State: JobSucceeded, Attempts: 1}
	st.jobs[JobCWE] = JobRecord{State: JobRunning, Attempts: 1}
	h := newHarness(st, nil, full)
	if out, _ := h.q.Run(context.Background()); !out.Complete {
		t.Fatal("not complete")
	}
	if !reflect.DeepEqual(h.calls, jobNames(false)[1:]) {
		t.Fatal(h.calls)
	}
}

// Continuing a sample graph as a full build keeps migrate and CWE and re-runs
// NVD and Exploit-DB (Requirement 12.10).
func TestSampleToFullContinuation(t *testing.T) {
	st := newStore()
	h := newHarness(st, nil, sample)
	if out, _ := h.q.Run(context.Background()); !out.Complete {
		t.Fatal("sample run incomplete")
	}
	h = newHarness(st, nil, full)
	if out, _ := h.q.Run(context.Background()); !out.Complete {
		t.Fatal("full run incomplete")
	}
	if !reflect.DeepEqual(h.calls, jobNames(true)) {
		t.Fatalf("calls %v", h.calls)
	}
	// A third run with the same mode does nothing and writes no job state.
	h = newHarness(st, nil, full)
	if out, _ := h.q.Run(context.Background()); !out.Complete || len(h.calls) != 0 {
		t.Fatalf("expected no jobs, got %v", h.calls)
	}
}

func TestChangedSampleLimitReRunsModeJobs(t *testing.T) {
	st := newStore()
	newHarness(st, nil, sample).q.Run(context.Background())
	h := newHarness(st, nil, RunOptions{Mode: "sample", Limit: 50})
	h.q.Run(context.Background())
	if !reflect.DeepEqual(h.calls, jobNames(true)) {
		t.Fatalf("calls %v", h.calls)
	}
}

func TestChangedSampleOrderReRunsModeJobs(t *testing.T) {
	st := newStore()
	newHarness(st, nil, sample).q.Run(context.Background()) // stored as order "first"
	latest := RunOptions{Mode: "sample", Limit: 1000, Order: "latest"}
	h := newHarness(st, nil, latest)
	h.q.Run(context.Background())
	if !reflect.DeepEqual(h.calls, jobNames(true)) {
		t.Fatalf("calls %v", h.calls)
	}
	if st.jobs[JobNVD].Order != "latest" {
		t.Fatalf("order not stored: %+v", st.jobs[JobNVD])
	}
	// An empty order is "first", so a record without queueOrder stays done.
	h = newHarness(st, nil, RunOptions{Mode: "sample", Limit: 1000, Order: "latest"})
	h.q.Run(context.Background())
	if len(h.calls) != 0 {
		t.Fatalf("calls %v", h.calls)
	}
	old := newStore()
	old.jobs[JobNVD] = JobRecord{State: JobSucceeded, Mode: "sample", Limit: 1000}
	if !Done(Job{ModeSpecific: true}, old.jobs[JobNVD], RunOptions{Mode: "sample", Limit: 1000, Order: "first"}) {
		t.Fatal("a record without an order must count as first")
	}
}
func TestDelay(t *testing.T) {
	if _, ok := Delay(0); ok {
		t.Fatal()
	}
	if _, ok := Delay(4); ok {
		t.Fatal()
	}
	if d, _ := Delay(3); d != 20*time.Second {
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
// **Validates: Requirements 11.1, 11.3, 11.4, 11.5, 11.6, 11.9, 11.10, 12.9**
func TestPropertyQueueSemantics(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		st := newStore()
		opts := full
		if rapid.Bool().Draw(t, "sampleMode") {
			opts = RunOptions{Mode: "sample", Limit: rapid.IntRange(1, 3).Draw(t, "limit")}
		}
		failN := map[string]int{}
		for _, d := range queueDef {
			failN[d.name] = rapid.IntRange(0, 5).Draw(t, "fail"+d.name)
		}
		// Pre-existing records model restarts: a succeeded prefix, with a random
		// mode and limit on the mode-specific jobs.
		skip := rapid.IntRange(0, len(queueDef)).Draw(t, "skip")
		prior := RunOptions{Mode: "sample", Limit: rapid.IntRange(1, 3).Draw(t, "priorLimit")}
		if rapid.Bool().Draw(t, "priorFull") {
			prior = full
		}
		for i := 0; i < skip; i++ {
			st.jobs[queueDef[i].name] = JobRecord{State: JobSucceeded, Mode: prior.Mode, Limit: prior.Limit}
		}
		attempts := map[string]int{}
		var jobs []Job
		for i, d := range queueDef {
			i, d := i, d
			jobs = append(jobs, Job{Name: d.name, BuildState: d.state, ModeSpecific: d.modeSpecific,
				Run: func(context.Context, RunOptions) error {
					for p := 0; p < i; p++ {
						if st.jobs[queueDef[p].name].State != JobSucceeded {
							t.Fatalf("%s started before %s succeeded", d.name, queueDef[p].name)
						}
					}
					if last := st.states[len(st.states)-1]; last != d.state {
						t.Fatalf("buildState %q while %s runs", last, d.name)
					}
					attempts[d.name]++
					if attempts[d.name] <= failN[d.name] {
						return errors.New("x")
					}
					return nil
				}})
		}
		var sleeps []time.Duration
		q := &Queue{Jobs: jobs, Store: st, Opts: opts, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Sleep: func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil }}
		out, err := q.Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		// Expected: which jobs are done before the run, which fails.
		stop, wantRuns := "", map[string]bool{}
		for i, d := range queueDef {
			done := i < skip && (!d.modeSpecific || prior == opts)
			if done {
				continue
			}
			wantRuns[d.name] = true
			if failN[d.name] >= 4 {
				stop = d.name
				break
			}
		}
		for _, d := range queueDef {
			got := attempts[d.name]
			if got > 4 {
				t.Fatalf("%s ran %d attempts", d.name, got)
			}
			if !wantRuns[d.name] && got != 0 {
				t.Fatalf("%s was not due but ran", d.name)
			}
		}
		for _, d := range sleeps {
			if d != 5*time.Second && d != 10*time.Second && d != 20*time.Second {
				t.Fatal(d)
			}
		}
		if (stop == "") != out.Complete || out.StoppedAt != stop {
			t.Fatalf("stop=%q out=%+v", stop, out)
		}
		if out.Complete {
			if last := st.states; len(wantRuns) > 0 && last[len(last)-1] != StateReady {
				t.Fatalf("complete queue must end in ready: %v", last)
			}
		} else if st.states[len(st.states)-1] == StateReady {
			t.Fatal("ready reported for a stopped queue")
		}
	})
}

// jobNames returns the queue job names in order; modeOnly keeps the
// mode-specific jobs.
func jobNames(modeOnly bool) []string {
	var out []string
	for _, d := range queueDef {
		if !modeOnly || d.modeSpecific {
			out = append(out, d.name)
		}
	}
	return out
}
