package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/change"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/checkpoint"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/graph"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/upsert"
)

// fakeStore is an in-memory Store. Events records the call order.
type fakeStore struct {
	mu     sync.Mutex
	events []string

	lockErr  error
	cp       checkpoint.Checkpoint
	dead     map[string]checkpoint.DeadLetter
	versions []string
	runs     map[string]string // id -> status
	runErr   string
	counters checkpoint.Counters
	cursor   *struct {
		resume string
		w      time.Time
	}
	applied [][]string // CVE keys per Apply

	// failApply returns an error for the Nth (1-based) Apply attempt, if set.
	failApply func(n int, w upsert.Writes) error
	applyN    int
	cursors   int

	upstream    map[string]int64
	upstreamAt  time.Time
	upstreamErr error
}

func newFake() *fakeStore {
	return &fakeStore{dead: map[string]checkpoint.DeadLetter{}, runs: map[string]string{}}
}

func (f *fakeStore) ev(s string) { f.mu.Lock(); f.events = append(f.events, s); f.mu.Unlock() }

type fakeLease struct{ f *fakeStore }

func (l fakeLease) Hold(ctx context.Context) (context.Context, func()) {
	return ctx, func() {}
}
func (l fakeLease) Release(context.Context) error { l.f.ev("release"); return nil }

func (f *fakeStore) Acquire(_ context.Context, s, _ string) (Lease, error) {
	f.ev("acquire")
	if f.lockErr != nil {
		return nil, f.lockErr
	}
	return fakeLease{f}, nil
}
func (f *fakeStore) ReadCheckpoint(context.Context, string) (checkpoint.Checkpoint, error) {
	f.ev("readcheckpoint")
	return f.cp, nil
}
func (f *fakeStore) StartRun(_ context.Context, id, _ string, _ time.Time) error {
	f.ev("startrun")
	f.runs[id] = "running"
	return nil
}
func (f *fakeStore) FinishRun(_ context.Context, id, status, msg string, _ time.Time) error {
	f.ev("finish:" + status)
	f.runs[id] = status
	f.runErr = msg
	return nil
}
func (f *fakeStore) WriteVersion(_ context.Context, _, v string) error {
	f.ev("version")
	f.versions = append(f.versions, v)
	return nil
}
func (f *fakeStore) WriteUpstream(_ context.Context, _ string, totals map[string]int64, at time.Time) error {
	f.ev("upstream")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.upstreamErr != nil {
		return f.upstreamErr
	}
	f.upstream, f.upstreamAt = totals, at
	return nil
}

func (f *fakeStore) ListDeadLetters(context.Context, string, string) ([]checkpoint.DeadLetter, error) {
	var out []checkpoint.DeadLetter
	for _, d := range f.dead {
		out = append(out, d)
	}
	return out, nil
}

// InTx buffers effects and applies them only when fn returns nil, so a
// failing transaction leaves nothing behind.
func (f *fakeStore) InTx(ctx context.Context, fn func(context.Context, Tx) error) error {
	f.ev("begin")
	tx := &fakeTx{f: f, dead: map[string]checkpoint.DeadLetter{}}
	if err := fn(ctx, tx); err != nil {
		f.ev("rollback")
		return err
	}
	f.ev("commit")
	f.applied = append(f.applied, tx.applied...)
	if tx.counters != nil {
		f.counters = *tx.counters
	}
	for id, d := range tx.dead {
		f.dead[id] = d
	}
	for _, id := range tx.del {
		delete(f.dead, id)
	}
	if tx.cursor != nil {
		f.cursor = tx.cursor
		f.cursors++
	}
	return nil
}

type fakeTx struct {
	f        *fakeStore
	applied  [][]string
	counters *checkpoint.Counters
	dead     map[string]checkpoint.DeadLetter
	del      []string
	cursor   *struct {
		resume string
		w      time.Time
	}
}

func (t *fakeTx) Load(_ context.Context, b upsert.Batch) (upsert.State, error) {
	t.f.ev("load")
	return upsert.State{}, nil
}
func (t *fakeTx) Apply(_ context.Context, w upsert.Writes, _ []change.Record) error {
	t.f.ev("apply")
	t.f.applyN++
	if t.f.failApply != nil {
		if err := t.f.failApply(t.f.applyN, w); err != nil {
			return err
		}
	}
	var keys []string
	for _, n := range w.Nodes {
		keys = append(keys, n.Key.Value)
	}
	t.applied = append(t.applied, keys)
	return nil
}
func (t *fakeTx) UpdateRun(_ context.Context, _ string, c checkpoint.Counters, _ checkpoint.Progress) error {
	t.f.ev("updaterun")
	t.counters = &c
	return nil
}
func (t *fakeTx) WriteCursor(_ context.Context, _ string, resume string, w time.Time) error {
	t.f.ev("cursor:" + resume)
	t.cursor = &struct {
		resume string
		w      time.Time
	}{resume, w}
	return nil
}
func (t *fakeTx) PutDeadLetter(_ context.Context, d checkpoint.DeadLetter) error {
	t.f.ev("deadletter:" + d.RecordID)
	t.dead[checkpoint.DeadLetterID(d.Source, d.RecordID, d.Kind)] = d
	return nil
}
func (t *fakeTx) DeleteDeadLetter(_ context.Context, s, id, k string) error {
	t.f.ev("deletedead:" + id)
	t.del = append(t.del, checkpoint.DeadLetterID(s, id, k))
	return nil
}

// stubAdapter yields recs; a record with payload "bad" fails Normalize.
type stubAdapter struct {
	f    *fakeStore
	recs []source.Record
	got  source.Checkpoint
	opts source.RunOptions
}

func (a *stubAdapter) Name() string { return "stub" }
func (a *stubAdapter) Fetch(_ context.Context, cp source.Checkpoint, o source.RunOptions) (source.Iterator, error) {
	a.f.ev("fetch")
	a.got, a.opts = cp, o
	return &sliceIter{a: a}, nil
}
func (a *stubAdapter) Normalize(rec source.Record) (source.Normalized, error) {
	a.f.ev("normalize:" + rec.ID)
	if string(rec.Payload) == "bad" {
		return source.Normalized{}, errors.New("cannot parse")
	}
	return source.Normalized{Entities: []source.Entity{{
		Ref:   source.Ref{Kind: source.RefCVE, Raw: rec.ID},
		Props: map[string]any{"description": string(rec.Payload)},
	}}}, nil
}

type sliceIter struct {
	a *stubAdapter
	i int
}

func (s *sliceIter) Next(context.Context) (source.Record, error) {
	if s.i >= len(s.a.recs) {
		return source.Record{}, io.EOF
	}
	s.i++
	s.a.f.ev("next")
	return s.a.recs[s.i-1], nil
}

func rec(n int, payload string) source.Record {
	return source.Record{
		ID: fmt.Sprintf("CVE-2024-%04d", n), Payload: []byte(payload),
		Cursor: source.Cursor{Resume: fmt.Sprint(n), Watermark: time.Unix(int64(n)*1000, 0).UTC(), Version: "v1"},
	}
}

func noSleep(context.Context, time.Duration) error { return nil }

func TestStageOrder(t *testing.T) {
	f := newFake()
	a := &stubAdapter{f: f, recs: []source.Record{rec(1, "a"), rec(2, "b")}}
	res, err := Run(context.Background(), f, a, Options{BatchSize: 10, Sleep: noSleep})
	if err != nil {
		t.Fatal(err)
	}
	want := "acquire,startrun,readcheckpoint,fetch,next,normalize:CVE-2024-0001,next,normalize:CVE-2024-0002," +
		"begin,load,apply,updaterun,cursor:2,commit,finish:succeeded,version,release"
	if got := strings.Join(f.events, ","); got != want {
		t.Fatalf("stage order\n got %s\nwant %s", got, want)
	}
	if res.Status != checkpoint.StatusSucceeded || res.Counters.Fetched != 2 || res.Counters.Created != 2 {
		t.Fatalf("%+v", res)
	}
	if len(f.versions) != 1 || f.versions[0] != "v1" || f.cursor.resume != "2" || f.counters.Fetched != 2 {
		t.Fatalf("%+v %v %+v", f.versions, f.cursor, f.counters)
	}
}

func TestBatching(t *testing.T) {
	f := newFake()
	a := &stubAdapter{f: f}
	for i := 1; i <= 5; i++ {
		a.recs = append(a.recs, rec(i, "x"))
	}
	if _, err := Run(context.Background(), f, a, Options{BatchSize: 2, Sleep: noSleep}); err != nil {
		t.Fatal(err)
	}
	if len(f.applied) != 3 || len(f.applied[0]) != 2 || len(f.applied[2]) != 1 || f.cursors != 3 {
		t.Fatalf("applied=%v cursors=%d", f.applied, f.cursors)
	}
}

func TestInvalidBatchSizeStartsNothing(t *testing.T) {
	for _, n := range []int{-1, 10001} {
		f := newFake()
		if _, err := Run(context.Background(), f, &stubAdapter{f: f}, Options{BatchSize: n}); err == nil {
			t.Fatalf("batch size %d accepted", n)
		}
		if len(f.events) != 0 {
			t.Fatalf("events: %v", f.events)
		}
	}
}

func TestLockedRefuses(t *testing.T) {
	f := newFake()
	f.lockErr = checkpoint.ErrLocked
	_, err := Run(context.Background(), f, &stubAdapter{f: f}, Options{})
	if !errors.Is(err, checkpoint.ErrLocked) || strings.Join(f.events, ",") != "acquire" {
		t.Fatalf("%v %v", err, f.events)
	}
}

func TestSampleWritesNoCheckpointOrVersion(t *testing.T) {
	f := newFake()
	a := &stubAdapter{f: f, recs: []source.Record{rec(1, "a"), rec(2, "b")}}
	res, err := Run(context.Background(), f, a, Options{SampleLimit: 2, BatchSize: 1, Sleep: noSleep})
	if err != nil {
		t.Fatal(err)
	}
	if f.cursors != 0 || len(f.versions) != 0 || res.Counters.Created != 2 || a.opts.SampleLimit != 2 {
		t.Fatalf("cursors=%d versions=%v %+v", f.cursors, f.versions, res)
	}
	for _, e := range f.events {
		if strings.HasPrefix(e, "cursor:") || e == "version" {
			t.Fatalf("unexpected %s", e)
		}
	}
}

func TestNormalizeFailureDeadLettered(t *testing.T) {
	f := newFake()
	a := &stubAdapter{f: f, recs: []source.Record{rec(1, "a"), rec(2, "bad"), rec(3, "c")}}
	res, err := Run(context.Background(), f, a, Options{Sleep: noSleep})
	if err != nil {
		t.Fatal(err)
	}
	id := checkpoint.DeadLetterID("stub", "CVE-2024-0002", checkpoint.KindFailed)
	if _, ok := f.dead[id]; !ok || res.Status != checkpoint.StatusSucceededWithErrors ||
		res.Counters.Failed != 1 || res.Counters.Created != 2 || res.Counters.Fetched != 3 {
		t.Fatalf("%+v dead=%v", res, f.dead)
	}
	if len(f.versions) != 1 {
		t.Fatal("version must be stored for succeeded_with_errors")
	}
}

func TestTransientRetryThenSuccess(t *testing.T) {
	f := newFake()
	f.failApply = func(n int, _ upsert.Writes) error {
		if n <= 2 {
			return &graph.Error{Class: graph.ClassTransient, Err: errors.New("down")}
		}
		return nil
	}
	var delays []time.Duration
	sleep := func(_ context.Context, d time.Duration) error { delays = append(delays, d); return nil }
	a := &stubAdapter{f: f, recs: []source.Record{rec(1, "a")}}
	res, err := Run(context.Background(), f, a, Options{Sleep: sleep})
	if err != nil || res.Counters.Created != 1 {
		t.Fatal(err, res)
	}
	if len(delays) != 2 || delays[0] != time.Second || delays[1] != 2*time.Second {
		t.Fatalf("delays %v", delays)
	}
}

func TestTransientExhaustedFailsRunAndKeepsCheckpoint(t *testing.T) {
	f := newFake()
	f.failApply = func(int, upsert.Writes) error {
		return &graph.Error{Class: graph.ClassTransient, Err: errors.New("down")}
	}
	var delays []time.Duration
	sleep := func(_ context.Context, d time.Duration) error { delays = append(delays, d); return nil }
	a := &stubAdapter{f: f, recs: []source.Record{rec(1, "a")}}
	res, err := Run(context.Background(), f, a, Options{Sleep: sleep})
	if err == nil || res.Status != checkpoint.StatusFailed {
		t.Fatal(err, res)
	}
	want := []time.Duration{1, 2, 4, 8, 16}
	if len(delays) != 5 {
		t.Fatalf("delays %v", delays)
	}
	for i, d := range want {
		if delays[i] != d*time.Second {
			t.Fatalf("delays %v", delays)
		}
	}
	if f.cursor != nil || len(f.versions) != 0 || f.runs[res.RunID] != "failed" {
		t.Fatalf("cursor=%v versions=%v", f.cursor, f.versions)
	}
}

func TestClientErrorReplaysPerRecordAndDeadLetters(t *testing.T) {
	f := newFake()
	f.failApply = func(_ int, w upsert.Writes) error {
		for _, n := range w.Nodes {
			if n.Key.Value == "CVE-2024-0002" {
				return &graph.Error{Class: graph.ClassClient, Err: errors.New("constraint")}
			}
		}
		return nil
	}
	a := &stubAdapter{f: f, recs: []source.Record{rec(1, "a"), rec(2, "b"), rec(3, "c")}}
	res, err := Run(context.Background(), f, a, Options{BatchSize: 10, Sleep: noSleep})
	if err != nil {
		t.Fatal(err)
	}
	id := checkpoint.DeadLetterID("stub", "CVE-2024-0002", checkpoint.KindFailed)
	if _, ok := f.dead[id]; !ok || res.Status != checkpoint.StatusSucceededWithErrors ||
		res.Counters.Created != 2 || res.Counters.Failed != 1 || res.Counters.Fetched != 3 {
		t.Fatalf("%+v dead=%v", res, f.dead)
	}
	if f.cursor.resume != "3" {
		t.Fatalf("cursor %+v", f.cursor)
	}
}

func TestFatalErrorFailsRun(t *testing.T) {
	f := newFake()
	f.failApply = func(int, upsert.Writes) error { return errors.New("boom") }
	a := &stubAdapter{f: f, recs: []source.Record{rec(1, "a")}}
	res, err := Run(context.Background(), f, a, Options{Sleep: noSleep})
	if err == nil || res.Status != checkpoint.StatusFailed {
		t.Fatal(err, res)
	}
	if got := f.events[len(f.events)-1]; got != "release" {
		t.Fatalf("lock not released: %v", f.events)
	}
}

func TestSinceOverridesCheckpoint(t *testing.T) {
	f := newFake()
	f.cp = checkpoint.Checkpoint{Found: true, Watermark: time.Unix(5000, 0), Resume: "9", Version: "old"}
	since := time.Unix(100, 0).UTC()
	a := &stubAdapter{f: f}
	if _, err := Run(context.Background(), f, a, Options{Since: since}); err != nil {
		t.Fatal(err)
	}
	if !a.got.Watermark.Equal(since) || a.got.Resume != "" || a.got.Version != "" {
		t.Fatalf("%+v", a.got)
	}
}

func TestStoredCheckpointPassedToFetch(t *testing.T) {
	f := newFake()
	f.cp = checkpoint.Checkpoint{Found: true, Watermark: time.Unix(5000, 0), Resume: "9", Version: "old"}
	a := &stubAdapter{f: f}
	if _, err := Run(context.Background(), f, a, Options{}); err != nil {
		t.Fatal(err)
	}
	if a.got.Resume != "9" || a.got.Version != "old" || !a.got.Watermark.Equal(time.Unix(5000, 0)) {
		t.Fatalf("%+v", a.got)
	}
}

func TestReplayDeadLetters(t *testing.T) {
	f := newFake()
	ok := checkpoint.DeadLetter{Source: "stub", RecordID: "CVE-2024-0001", Kind: checkpoint.KindFailed, Payload: []byte("a")}
	bad := checkpoint.DeadLetter{Source: "stub", RecordID: "CVE-2024-0002", Kind: checkpoint.KindFailed, Payload: []byte("bad"), Error: "old"}
	f.dead[checkpoint.DeadLetterID("stub", ok.RecordID, ok.Kind)] = ok
	f.dead[checkpoint.DeadLetterID("stub", bad.RecordID, bad.Kind)] = bad
	a := &stubAdapter{f: f}
	res, err := Run(context.Background(), f, a, Options{ReplayDeadLetters: true, Sleep: noSleep})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.dead) != 1 || f.dead[checkpoint.DeadLetterID("stub", bad.RecordID, bad.Kind)].Error != "cannot parse" {
		t.Fatalf("dead=%v", f.dead)
	}
	if res.Counters.Created != 1 || res.Counters.Failed != 1 || f.cursors != 0 || len(f.versions) != 0 {
		t.Fatalf("%+v cursors=%d", res, f.cursors)
	}
	for _, e := range f.events {
		if e == "fetch" {
			t.Fatal("replay must not fetch")
		}
	}
}

func TestCursorMarkerRecord(t *testing.T) {
	f := newFake()
	a := &stubAdapter{f: f, recs: []source.Record{
		rec(1, "a"),
		{Cursor: source.Cursor{Resume: "", Watermark: time.Unix(9000, 0).UTC()}},
	}}
	res, err := Run(context.Background(), f, a, Options{})
	if err != nil || res.Counters.Fetched != 1 {
		t.Fatal(err, res)
	}
	if !f.cursor.w.Equal(time.Unix(9000, 0)) || f.cursor.resume != "" {
		t.Fatalf("%+v", f.cursor)
	}
}

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	f := newFake()
	if err := r.Register(&stubAdapter{f: f}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(&stubAdapter{f: f}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, ok := r.Get("stub"); !ok || len(r.Names()) != 1 {
		t.Fatal("lookup")
	}
}

// totalerAdapter adds source.Totaler to stubAdapter.
type totalerAdapter struct {
	*stubAdapter
	totals map[string]int64
	err    error
	calls  int
}

func (a *totalerAdapter) Totals(context.Context) (map[string]int64, error) {
	a.calls++
	return a.totals, a.err
}

func TestUpstreamTotalsStoredAfterSuccess(t *testing.T) {
	now := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, sample := range []int{0, 2} {
		f := newFake()
		a := &totalerAdapter{stubAdapter: &stubAdapter{f: f, recs: []source.Record{rec(1, "a"), rec(2, "b")}}, totals: map[string]int64{"cves": 7}}
		_, err := Run(context.Background(), f, a, Options{SampleLimit: sample, BatchSize: 10, Sleep: noSleep, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		if a.calls != 1 || f.upstream["cves"] != 7 || !f.upstreamAt.Equal(now) {
			t.Fatalf("sample=%d calls=%d %v %v", sample, a.calls, f.upstream, f.upstreamAt)
		}
	}
}

func TestUpstreamTotalsStoredWhenNothingFetched(t *testing.T) {
	f := newFake()
	a := &totalerAdapter{stubAdapter: &stubAdapter{f: f}, totals: map[string]int64{"rows": 3}}
	if _, err := Run(context.Background(), f, a, Options{Sleep: noSleep}); err != nil {
		t.Fatal(err)
	}
	if f.upstream["rows"] != 3 {
		t.Fatalf("%v", f.upstream)
	}
}

func TestUpstreamTotalsFailureIsOnlyAWarning(t *testing.T) {
	f := newFake()
	a := &totalerAdapter{stubAdapter: &stubAdapter{f: f, recs: []source.Record{rec(1, "a")}}, err: errors.New("boom")}
	res, err := Run(context.Background(), f, a, Options{Sleep: noSleep})
	if err != nil || res.Status != checkpoint.StatusSucceeded || f.upstream != nil {
		t.Fatalf("%v %+v %v", err, res, f.upstream)
	}
	f2 := newFake()
	f2.upstreamErr = errors.New("write failed")
	a2 := &totalerAdapter{stubAdapter: &stubAdapter{f: f2, recs: []source.Record{rec(1, "a")}}, totals: map[string]int64{"x": 1}}
	if res, err := Run(context.Background(), f2, a2, Options{Sleep: noSleep}); err != nil || res.Status != checkpoint.StatusSucceeded {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestUpstreamTotalsNotCalledOnFailedRun(t *testing.T) {
	f := newFake()
	f.failApply = func(int, upsert.Writes) error { return errors.New("fatal") }
	a := &totalerAdapter{stubAdapter: &stubAdapter{f: f, recs: []source.Record{rec(1, "a")}}, totals: map[string]int64{"x": 1}}
	if _, err := Run(context.Background(), f, a, Options{Sleep: noSleep}); err == nil {
		t.Fatal("want error")
	}
	if a.calls != 0 || f.upstream != nil {
		t.Fatalf("calls=%d %v", a.calls, f.upstream)
	}
}
