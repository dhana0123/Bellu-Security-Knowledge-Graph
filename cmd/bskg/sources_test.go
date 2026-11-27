package main

import (
	"bytes"
	"context"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/config"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/pipeline"
)

func TestSourceJobsFollowEnabledAndRegistered(t *testing.T) {
	reg := pipeline.NewRegistry()
	for _, n := range []string{"cwe", "nvd", "exploitdb", "kev", "osv", "capec"} {
		reg.Register(nopAdapter{n})
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	// ghsa is enabled without an adapter; epss is registered-less and disabled; osv is registered but disabled.
	enabled := strings.Split(config.DefaultEnabledSources, ",")
	enabled = removeName(enabled, "osv")
	jobs := sourceJobs(reg, &lockedStore{}, enabled, 500, log)
	var names, states []string
	for _, j := range jobs {
		names = append(names, j.Name)
		states = append(states, j.BuildState)
	}
	wantNames := []string{"cwe", "nvd-catch-up", "exploitdb", "capec", "kev"}
	wantStates := []string{"loading_cwe", "nvd_catch_up", "loading_exploits", "loading_capec", "loading_kev"}
	if !reflect.DeepEqual(names, wantNames) || !reflect.DeepEqual(states, wantStates) {
		t.Fatalf("jobs %v states %v", names, states)
	}
	for _, j := range jobs {
		want := j.Name == "nvd-catch-up" || j.Name == "exploitdb" || j.Name == "kev"
		if j.ModeSpecific != want {
			t.Errorf("%s ModeSpecific = %v", j.Name, j.ModeSpecific)
		}
	}
	if !strings.Contains(logs.String(), "source=ghsa") || strings.Contains(logs.String(), "source=osv") {
		t.Fatalf("warnings: %s", logs.String())
	}
}

func TestCoreJobsAreListedWithoutAdapters(t *testing.T) {
	jobs := sourceJobs(pipeline.NewRegistry(), &lockedStore{}, nil, 500, quiet)
	if len(jobs) != 3 || jobs[0].Name != "cwe" || jobs[2].Name != "exploitdb" {
		t.Fatalf("%d jobs", len(jobs))
	}
}

func TestDailySyncRunsInQueueOrder(t *testing.T) {
	reg := pipeline.NewRegistry()
	var order []string
	for _, n := range []string{"ghsa", "kev", "nvd", "cwe"} {
		reg.Register(nopAdapter{n})
	}
	st := &recordingStore{}
	_ = dailySync(context.Background(), reg, st, []string{"ghsa", "osv", "kev", "nvd", "cwe"}, 500, quiet)
	order = st.sources
	if !reflect.DeepEqual(order, []string{"cwe", "nvd", "kev", "ghsa"}) {
		t.Fatalf("order %v", order)
	}
}

type recordingStore struct {
	lockedStore
	sources []string
}

func (s *recordingStore) Acquire(ctx context.Context, source, owner string) (pipeline.Lease, error) {
	s.sources = append(s.sources, source)
	return s.lockedStore.Acquire(ctx, source, owner)
}

func removeName(l []string, n string) []string {
	var out []string
	for _, v := range l {
		if v != n {
			out = append(out, v)
		}
	}
	return out
}
