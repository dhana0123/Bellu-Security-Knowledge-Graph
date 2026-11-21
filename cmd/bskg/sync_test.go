package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bskg/internal/checkpoint"
	"github.com/bellu/bskg/internal/pipeline"
	"github.com/bellu/bskg/internal/source"
	"github.com/bellu/bskg/internal/worker"
)

type nopAdapter struct{ name string }

func (a nopAdapter) Name() string { return a.name }
func (a nopAdapter) Fetch(context.Context, source.Checkpoint, source.RunOptions) (source.Iterator, error) {
	return nil, errors.New("not used")
}
func (a nopAdapter) Normalize(source.Record) (source.Normalized, error) {
	return source.Normalized{}, nil
}

// lockedStore refuses every lock, which proves pipeline.Run was reached.
type lockedStore struct {
	pipeline.Store
	acquires int
}

func (s *lockedStore) Acquire(context.Context, string, string) (pipeline.Lease, error) {
	s.acquires++
	return nil, checkpoint.ErrLocked
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestSyncJobUnregisteredIsNotImplemented(t *testing.T) {
	job := syncJob(pipeline.NewRegistry(), &lockedStore{}, "cwe", 500, quiet)
	err := job(context.Background(), worker.RunOptions{})
	if !errors.Is(err, worker.ErrNotImplemented) {
		t.Fatal(err)
	}
}

func TestSyncJobRegisteredCallsPipeline(t *testing.T) {
	reg := pipeline.NewRegistry()
	if err := reg.Register(nopAdapter{"cwe"}); err != nil {
		t.Fatal(err)
	}
	oldWait, oldPoll := lockWait, lockPoll
	lockWait, lockPoll = 30*time.Millisecond, 10*time.Millisecond
	defer func() { lockWait, lockPoll = oldWait, oldPoll }()
	st := &lockedStore{}
	err := syncJob(reg, st, "cwe", 500, quiet)(context.Background(), worker.RunOptions{Mode: "sample", Limit: 5})
	if !errors.Is(err, checkpoint.ErrLocked) || errors.Is(err, worker.ErrNotImplemented) || st.acquires < 2 {
		t.Fatalf("err=%v acquires=%d", err, st.acquires)
	}
}

func TestDailySyncSkipsUnregisteredAndContinuesAfterFailure(t *testing.T) {
	reg := pipeline.NewRegistry()
	reg.Register(nopAdapter{"nvd"})
	reg.Register(nopAdapter{"exploitdb"})
	st := &lockedStore{}
	err := dailySync(context.Background(), reg, st, []string{"cwe", "nvd", "exploitdb"}, 500, quiet)
	if err == nil || st.acquires != 2 {
		t.Fatalf("err=%v acquires=%d", err, st.acquires)
	}
}

func TestStatusTable(t *testing.T) {
	var b bytes.Buffer
	writeStatusTable(&b, []checkpoint.SourceStatus{
		{Source: "cwe"},
		{Source: "nvd", LastStatus: "running", Step: "upsert", Processed: 10, DeadLetters: 2},
	})
	out := b.String()
	for _, want := range []string{"SOURCE", "never run", "upsert 10", "running"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestSyncAndResetArgumentErrors(t *testing.T) {
	cases := []struct {
		args []string
		want int
	}{
		{[]string{"sync", "bogus"}, 2},
		{[]string{"sync", "--since", "yesterday"}, 2},
		{[]string{"sync", "--nope"}, 2},
		{[]string{"sync", "--replay-dead-letter"}, 1}, // config fails first: no password in the test env
		{[]string{"reset"}, 1},
		{[]string{"reset", "--confirm", "x"}, 2},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		if got := run(c.args, &out, &errb); got != c.want {
			t.Errorf("run(%v) = %d, want %d (%s)", c.args, got, c.want, errb.String())
		}
	}
	var out, errb bytes.Buffer
	run([]string{"reset"}, &out, &errb)
	if !strings.Contains(errb.String(), "--confirm") {
		t.Errorf("reset without --confirm must name the flag: %q", errb.String())
	}
}
