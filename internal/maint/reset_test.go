package maint

import (
	"context"
	"errors"
	"testing"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/model"
)

type fakeStore struct {
	active  bool
	rels    int64
	nodes   map[string]int64
	failOn  string // label whose delete fails
	calls   []string
	maxSeen int
}

func (f *fakeStore) Active(context.Context) (bool, error) { return f.active, nil }

func (f *fakeStore) DeleteRels(_ context.Context, limit int) (int64, error) {
	f.calls = append(f.calls, "rels")
	f.maxSeen = max(f.maxSeen, limit)
	n := min(f.rels, int64(limit))
	f.rels -= n
	return n, nil
}

func (f *fakeStore) DeleteNodes(_ context.Context, label string, limit int) (int64, error) {
	f.calls = append(f.calls, label)
	if label == f.failOn {
		return 0, errors.New("boom")
	}
	n := min(f.nodes[label], int64(limit))
	f.nodes[label] -= n
	return n, nil
}

func TestResetRequiresConfirm(t *testing.T) {
	f := &fakeStore{rels: 5}
	if _, err := Reset(context.Background(), f, false); !errors.Is(err, ErrNotConfirmed) || len(f.calls) != 0 {
		t.Fatal(err, f.calls)
	}
}

func TestResetRefusesWhenActive(t *testing.T) {
	f := &fakeStore{active: true, rels: 5}
	if _, err := Reset(context.Background(), f, true); !errors.Is(err, ErrActive) || len(f.calls) != 0 {
		t.Fatal(err, f.calls)
	}
}

func TestResetDeletesInBatchesRelsFirstAndKeepsMigrationAndApiKey(t *testing.T) {
	f := &fakeStore{rels: 25000, nodes: map[string]int64{"Vulnerability": 10001, "SyncRun": 3, "Migration": 2, "ApiKey": 1}}
	res, err := Reset(context.Background(), f, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Relationships != 25000 || res.Nodes != 10004 || f.maxSeen != BatchLimit {
		t.Fatalf("%+v max=%d", res, f.maxSeen)
	}
	if f.nodes["Migration"] != 2 || f.nodes["ApiKey"] != 1 {
		t.Fatalf("kept labels were touched: %v", f.nodes)
	}
	if f.calls[0] != "rels" {
		t.Fatalf("relationships must go first: %v", f.calls[:2])
	}
	for _, c := range f.calls {
		if c == "Migration" || c == "ApiKey" {
			t.Fatalf("deleted %s", c)
		}
	}
	for _, l := range model.ResetLabels() {
		found := false
		for _, c := range f.calls {
			found = found || c == l
		}
		if !found {
			t.Fatalf("label %s not processed", l)
		}
	}
}

func TestResetEmptyGraph(t *testing.T) {
	res, err := Reset(context.Background(), &fakeStore{nodes: map[string]int64{}}, true)
	if err != nil || res != (Result{}) {
		t.Fatal(res, err)
	}
}

func TestResetFailureReportsPartialCountsAndResumes(t *testing.T) {
	f := &fakeStore{rels: 7, nodes: map[string]int64{"Author": 4, "Vulnerability": 6}, failOn: "Vulnerability"}
	res, err := Reset(context.Background(), f, true)
	if err == nil || res.Relationships != 7 || res.Nodes < 4 {
		t.Fatal(res, err)
	}
	f.failOn = ""
	res2, err := Reset(context.Background(), f, true)
	if err != nil || f.nodes["Vulnerability"] != 0 || f.nodes["Author"] != 0 {
		t.Fatal(res2, err, f.nodes)
	}
}
