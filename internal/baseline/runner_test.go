package baseline

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bskg/internal/graph"
)

type fakeJobs struct {
	st      RunState
	ok      bool
	started int
	done    []string
}

func (f *fakeJobs) Read(context.Context) (RunState, bool, error) { return f.st, f.ok, nil }
func (f *fakeJobs) Start(_ context.Context, st RunState) error {
	f.st, f.ok = st, true
	f.started++
	return nil
}
func (f *fakeJobs) Complete(_ context.Context, s string) error {
	f.st.LastCompleted = s
	f.done = append(f.done, s)
	return nil
}

var errTransient = &graph.Error{Class: graph.ClassTransient, Err: errors.New("unavailable")}

type harness struct {
	store  *fakeJobs
	ran    []string
	fail   map[string][]error // step -> errors for successive attempts
	sleeps []time.Duration
}

func (h *harness) runner() Runner {
	return Runner{
		Store: h.store, Commit: "c1",
		Build: func(RunState) []Step {
			var out []Step
			for _, n := range []string{"a", "b", StepFinalize} {
				out = append(out, Step{Name: n, Run: func(context.Context) error {
					h.ran = append(h.ran, n)
					if q := h.fail[n]; len(q) > 0 {
						h.fail[n] = q[1:]
						return q[0]
					}
					return nil
				}})
			}
			return out
		},
		NewRunID: func(time.Time) (string, error) { return "RUN", nil },
		Sleep:    func(_ context.Context, d time.Duration) error { h.sleeps = append(h.sleeps, d); return nil },
	}
}

func TestRunnerFreshRunsAllInOrder(t *testing.T) {
	h := &harness{store: &fakeJobs{}}
	st, err := h.runner().Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(h.ran, []string{"a", "b", StepFinalize}) || st.RunID != "RUN" || h.store.started != 1 {
		t.Fatalf("ran=%v st=%+v started=%d", h.ran, st, h.store.started)
	}
}

func TestRunnerSkipsCompletedAndKeepsRunID(t *testing.T) {
	at := time.Now()
	h := &harness{store: &fakeJobs{ok: true, st: RunState{RunID: "OLD", Commit: "c1", StartedAt: at, LastCompleted: "a"}}}
	st, err := h.runner().Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(h.ran, []string{"b", StepFinalize}) || st.RunID != "OLD" || h.store.started != 0 {
		t.Fatalf("ran=%v st=%+v started=%d", h.ran, st, h.store.started)
	}
}

func TestRunnerStartsNewLoadAfterCompleteOrCommitChange(t *testing.T) {
	for _, old := range []RunState{
		{RunID: "OLD", Commit: "c1", StartedAt: time.Now(), LastCompleted: StepFinalize},
		{RunID: "OLD", Commit: "other", StartedAt: time.Now(), LastCompleted: "a"},
	} {
		h := &harness{store: &fakeJobs{ok: true, st: old}}
		st, err := h.runner().Run(context.Background())
		if err != nil || st.RunID != "RUN" || len(h.ran) != 3 || h.store.started != 1 {
			t.Fatalf("old=%+v ran=%v st=%+v err=%v", old, h.ran, st, err)
		}
	}
}

func TestRunnerResumeWithNoCompletedStepResetsCounters(t *testing.T) {
	h := &harness{store: &fakeJobs{ok: true, st: RunState{RunID: "OLD", Commit: "c1", StartedAt: time.Now()}}}
	st, err := h.runner().Run(context.Background())
	if err != nil || st.RunID != "OLD" || h.store.started != 1 || len(h.ran) != 3 {
		t.Fatalf("st=%+v started=%d ran=%v err=%v", st, h.store.started, h.ran, err)
	}
}

func TestRunnerRetriesTransientThenSucceeds(t *testing.T) {
	h := &harness{store: &fakeJobs{}, fail: map[string][]error{"a": {errTransient, errTransient}}}
	if _, err := h.runner().Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(h.ran, []string{"a", "a", "a", "b", StepFinalize}) {
		t.Fatalf("ran=%v", h.ran)
	}
	if !reflect.DeepEqual(h.sleeps, []time.Duration{5 * time.Second, 5 * time.Second}) {
		t.Fatalf("sleeps=%v", h.sleeps)
	}
}

func TestRunnerGivesUpAfterThreeRetriesNamingStep(t *testing.T) {
	h := &harness{store: &fakeJobs{}, fail: map[string][]error{"b": {errTransient, errTransient, errTransient, errTransient, errTransient}}}
	_, err := h.runner().Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "step b") {
		t.Fatalf("err=%v", err)
	}
	if n := countOf(h.ran, "b"); n != 4 {
		t.Fatalf("b attempts=%d, want 4", n)
	}
	if !reflect.DeepEqual(h.store.done, []string{"a"}) {
		t.Fatalf("done=%v", h.store.done)
	}
}

func TestRunnerDoesNotRetryNonTransient(t *testing.T) {
	h := &harness{store: &fakeJobs{}, fail: map[string][]error{"a": {errors.New("bad row")}}}
	_, err := h.runner().Run(context.Background())
	if err == nil || countOf(h.ran, "a") != 1 || len(h.sleeps) != 0 {
		t.Fatalf("err=%v ran=%v sleeps=%v", err, h.ran, h.sleeps)
	}
}

func TestStepListOrder(t *testing.T) {
	var names []string
	for _, s := range (Loader{}).StepList() {
		names = append(names, s.Name)
	}
	want := []string{StepVulnNodes, StepExploitNodes, StepAuthorNodes, StepWrites, StepExploitsRel,
		StepWeaknessNodes, StepExampleOf, StepVulnAddProps, StepDomainRefers, StepProductAffects,
		StepVendorBelongs, StepAffectedVer, StepRejectDelete, StepExploitability, StepFinalize}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("%v", names)
	}
}

func countOf(l []string, s string) int {
	n := 0
	for _, x := range l {
		if x == s {
			n++
		}
	}
	return n
}
