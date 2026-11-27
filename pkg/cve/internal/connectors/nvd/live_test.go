package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/fetch"
)

// fakeClock is a manually advanced clock; sleeping advances it instead of blocking.
type fakeClock struct {
	mu     sync.Mutex
	t      time.Time
	sleeps []time.Duration
}

func (f *fakeClock) Now() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.t }
func (f *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sleeps = append(f.sleeps, d)
	f.t = f.t.Add(d)
	return nil
}

type req struct {
	from, to time.Time
	start    int
	per      string
	key      string
	at       time.Time
}

// fakeNVD serves perWindow synthetic CVEs for every queried window, pageSize at a time.
type fakeNVD struct {
	mu        sync.Mutex
	clock     *fakeClock
	perWindow int
	pageSize  int
	reqs      []req
	// script returns a status (and optional Retry-After) to send instead of data; 0 = serve data.
	script func(n int) (int, string)
	// body overrides the vulnerabilities served for a page (window start, index) when set.
	entry func(w time.Time, i int) string
	onReq func(n int)
}

func (f *fakeNVD) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, err1 := time.Parse(dateLayout, q.Get("lastModStartDate"))
	to, err2 := time.Parse(dateLayout, q.Get("lastModEndDate"))
	if err1 != nil || err2 != nil {
		http.Error(w, "both lastModStartDate and lastModEndDate required", http.StatusBadRequest)
		return
	}
	if to.Sub(from) > MaxWindow {
		http.Error(w, "range over 120 days", http.StatusBadRequest)
		return
	}
	si, _ := strconv.Atoi(q.Get("startIndex"))
	f.mu.Lock()
	rq := req{from: from, to: to, start: si, per: q.Get("resultsPerPage"), key: r.Header.Get("apiKey")}
	if f.clock != nil {
		rq.at = f.clock.Now()
	}
	f.reqs = append(f.reqs, rq)
	n := len(f.reqs)
	f.mu.Unlock()
	if f.onReq != nil {
		f.onReq(n)
	}
	if f.script != nil {
		if code, ra := f.script(n); code != 0 {
			if ra != "" {
				w.Header().Set("Retry-After", ra)
			}
			w.WriteHeader(code)
			return
		}
	}
	resp := map[string]any{"startIndex": si, "totalResults": f.perWindow}
	var vs []json.RawMessage
	for i := si; i < si+f.pageSize && i < f.perWindow; i++ {
		var e string
		if f.entry != nil {
			e = f.entry(from, i)
		} else {
			e = fmt.Sprintf(`{"cve":{"id":%q}}`, idFor(from, i))
		}
		vs = append(vs, json.RawMessage(e))
	}
	resp["resultsPerPage"] = len(vs)
	resp["vulnerabilities"] = vs
	json.NewEncoder(w).Encode(resp)
}

func idFor(w time.Time, i int) string {
	return fmt.Sprintf("CVE-2024-%d%d", int(w.Sub(FullStart).Hours()/24), i)
}

func (f *fakeNVD) requests() []req {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]req(nil), f.reqs...)
}

func liveClient(url, key string, fc *fakeClock, now time.Time) *Client {
	c := NewClient(url, key)
	c.HTTP.SetClock(fc)
	c.HTTP.SetSleeper(fc.sleep)
	c.Now = func() time.Time { return now }
	return c
}

func collect(t *testing.T, c *Client, ctx context.Context, mode connectors.Mode, since time.Time) (ids []string, errs []error) {
	t.Helper()
	for it, err := range c.Fetch(ctx, mode, since) {
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ids = append(ids, it.ID)
	}
	return
}

var t0 = time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

func TestLivePagingAndMaxPageSize(t *testing.T) {
	f := &fakeNVD{perWindow: 5, pageSize: 2}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := liveClient(srv.URL, "", &fakeClock{t: t0}, t0)
	ids, errs := collect(t, c, context.Background(), connectors.Incremental, t0.Add(-48*time.Hour))
	if len(errs) != 0 || len(ids) != 5 {
		t.Fatalf("ids=%v errs=%v", ids, errs)
	}
	rs := f.requests()
	if len(rs) != 3 || rs[0].start != 0 || rs[1].start != 2 || rs[2].start != 4 {
		t.Fatalf("paging: %+v", rs)
	}
	if rs[0].per != "2000" || ResultsPerPage != 2000 {
		t.Fatalf("resultsPerPage = %s", rs[0].per)
	}
	if st := c.Stats(); st.Pages != 3 || st.Records != 5 || st.Failed != 0 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestLiveRetriesRespectRetryAfter(t *testing.T) {
	f := &fakeNVD{perWindow: 1, pageSize: 2}
	f.script = func(n int) (int, string) {
		switch n {
		case 1:
			return http.StatusTooManyRequests, "45"
		case 2:
			return http.StatusServiceUnavailable, ""
		}
		return 0, ""
	}
	srv := httptest.NewServer(f)
	defer srv.Close()
	fc := &fakeClock{t: t0}
	c := liveClient(srv.URL, "", fc, t0)
	ids, errs := collect(t, c, context.Background(), connectors.Incremental, t0.Add(-time.Hour))
	if len(errs) != 0 || len(ids) != 1 {
		t.Fatalf("ids=%v errs=%v", ids, errs)
	}
	if len(f.requests()) != 3 {
		t.Fatalf("want 3 attempts, got %d", len(f.requests()))
	}
	var saw45 bool
	for _, d := range fc.sleeps {
		if d >= 45*time.Second {
			saw45 = true
		}
	}
	if !saw45 {
		t.Fatalf("Retry-After 45s not honoured; sleeps = %v", fc.sleeps)
	}
}

func TestLiveRetriesExhaustedSurfaceError(t *testing.T) {
	f := &fakeNVD{perWindow: 1, pageSize: 1, script: func(int) (int, string) { return http.StatusServiceUnavailable, "" }}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := liveClient(srv.URL, "", &fakeClock{t: t0}, t0)
	_, errs := collect(t, c, context.Background(), connectors.Incremental, t0.Add(-time.Hour))
	var fr *fetch.FailedRequestError
	if len(errs) != 1 || !errors.As(errs[0], &fr) || fr.Attempts != 5 {
		t.Fatalf("errs = %v", errs)
	}
}

func TestLiveRateSpacingAndAPIKey(t *testing.T) {
	for _, tc := range []struct {
		name, key string
		min       time.Duration
	}{
		{"no key", "", 5 * time.Second},               // 5 requests per 30 s
		{"with key", "k-123", 600 * time.Millisecond}, // 50 requests per 30 s
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := &fakeClock{t: t0}
			f := &fakeNVD{clock: fc, perWindow: 6, pageSize: 2}
			srv := httptest.NewServer(f)
			defer srv.Close()
			c := liveClient(srv.URL, tc.key, fc, t0)
			ids, errs := collect(t, c, context.Background(), connectors.Incremental, t0.Add(-24*time.Hour))
			if len(errs) != 0 || len(ids) != 6 {
				t.Fatalf("ids=%v errs=%v", ids, errs)
			}
			rs := f.requests()
			if len(rs) != 3 {
				t.Fatalf("reqs = %d", len(rs))
			}
			for i, r := range rs {
				if r.key != tc.key {
					t.Fatalf("req %d apiKey = %q, want %q", i, r.key, tc.key)
				}
				if i > 0 && r.at.Sub(rs[i-1].at) < tc.min {
					t.Fatalf("req %d spacing %s < %s", i, r.at.Sub(rs[i-1].at), tc.min)
				}
			}
			// The effective rate must stay within the NVD limit over any 30 s span.
			limit := 5
			if tc.key != "" {
				limit = 50
			}
			for i := range rs {
				n := 0
				for _, r := range rs[i:] {
					if r.at.Sub(rs[i].at) < 30*time.Second {
						n++
					}
				}
				if n > limit {
					t.Fatalf("%d requests inside 30 s exceeds limit %d", n, limit)
				}
			}
		})
	}
}

func TestLiveWindowSplitting(t *testing.T) {
	f := &fakeNVD{perWindow: 1, pageSize: 1}
	srv := httptest.NewServer(f)
	defer srv.Close()
	now := time.Date(2024, 3, 7, 5, 0, 0, 0, time.UTC)
	c := liveClient(srv.URL, "key", &fakeClock{t: now}, now)
	ids, errs := collect(t, c, context.Background(), connectors.Full, time.Time{})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	rs := f.requests()
	if len(rs) != len(Windows(FullStart, now, MaxWindow)) || len(ids) != len(rs) {
		t.Fatalf("reqs=%d ids=%d", len(rs), len(ids))
	}
	if !rs[0].from.Equal(FullStart) || !rs[len(rs)-1].to.Equal(now) {
		t.Fatalf("coverage %v .. %v", rs[0].from, rs[len(rs)-1].to)
	}
	for i, r := range rs {
		if r.to.Sub(r.from) > MaxWindow || !r.to.After(r.from) {
			t.Fatalf("window %d invalid: %v..%v", i, r.from, r.to)
		}
		if i > 0 && !r.from.Equal(rs[i-1].to) {
			t.Fatalf("gap before window %d", i)
		}
	}
}

func TestLiveResumeAfterCancellation(t *testing.T) {
	cpPath := filepath.Join(t.TempDir(), "sub", "nvd-cursor.json")
	since := t0.Add(-200 * 24 * time.Hour) // two windows
	f := &fakeNVD{perWindow: 5, pageSize: 2}
	srv := httptest.NewServer(f)
	defer srv.Close()

	// Run 1: cancel while consuming the second page of the second window.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c1 := liveClient(srv.URL, "", &fakeClock{t: t0}, t0)
	c1.Checkpoint = FileCheckpoint{Path: cpPath}
	var first []string
	for it, err := range c1.Fetch(ctx, connectors.Incremental, since) {
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("unexpected error %v", err)
			}
			break
		}
		first = append(first, it.ID)
		if len(first) == 5+3 { // window 1 (5) + first item of window 2's second page
			cancel()
		}
	}
	cur, err := loadCursor(context.Background(), FileCheckpoint{Path: cpPath})
	if err != nil || cur == nil {
		t.Fatalf("cursor: %v %v", cur, err)
	}
	if cur.Complete || cur.NextIndex != 2 || !cur.WindowStart.Equal(since.Add(MaxWindow)) {
		t.Fatalf("cursor after cancel = %+v", cur)
	}
	before := len(f.requests())

	// Run 2: a fresh client (new process) with a later "now" must resume the saved run.
	c2 := liveClient(srv.URL, "", &fakeClock{t: t0.Add(time.Hour)}, t0.Add(time.Hour))
	c2.Checkpoint = FileCheckpoint{Path: cpPath}
	second, errs := collect(t, c2, context.Background(), connectors.Incremental, since)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	rs := f.requests()[before:]
	if len(rs) != 2 || rs[0].start != 2 || !rs[0].from.Equal(since.Add(MaxWindow)) || !rs[0].to.Equal(t0) {
		t.Fatalf("resume requests = %+v", rs)
	}
	got := map[string]bool{}
	for _, id := range append(append([]string{}, first...), second...) {
		got[id] = true
	}
	if len(got) != 10 {
		t.Fatalf("union of both runs has %d distinct ids, want 10: %v", len(got), got)
	}
	// Only the page that was interrupted may be seen twice.
	if len(first)+len(second) > 10+2 {
		t.Fatalf("too much re-delivery: %d+%d", len(first), len(second))
	}
	if cur, _ = loadCursor(context.Background(), FileCheckpoint{Path: cpPath}); !cur.Complete || !cur.RunEnd.Equal(t0) {
		t.Fatalf("final cursor = %+v", cur)
	}
}

func TestLiveIdempotentRerun(t *testing.T) {
	cp := &MemoryCheckpoint{}
	f := &fakeNVD{perWindow: 3, pageSize: 2}
	srv := httptest.NewServer(f)
	defer srv.Close()
	run := func(now time.Time, mode connectors.Mode) ([]string, []error) {
		c := liveClient(srv.URL, "", &fakeClock{t: now}, now)
		c.Checkpoint = cp
		return collect(t, c, context.Background(), mode, time.Time{})
	}
	now := time.Date(2000, 2, 1, 0, 0, 0, 0, time.UTC)
	a, errs := run(now, connectors.Full)
	if len(errs) != 0 || len(a) == 0 {
		t.Fatalf("a=%v errs=%v", a, errs)
	}
	n := len(f.requests())

	// Incremental at the same instant: nothing new, no requests.
	b, errs := run(now, connectors.Incremental)
	if len(errs) != 0 || len(b) != 0 || len(f.requests()) != n {
		t.Fatalf("no-op rerun fetched %d ids, %d requests", len(b), len(f.requests())-n)
	}
	// Incremental a day later: exactly one window starting at the high-water mark.
	c, errs := run(now.Add(24*time.Hour), connectors.Incremental)
	rs := f.requests()[n:]
	if len(errs) != 0 || len(c) != 3 || len(rs) != 2 || !rs[0].from.Equal(now) {
		t.Fatalf("c=%v reqs=%+v", c, rs)
	}
	// A rerun of the same full range yields the same ids in the same order.
	cp2 := &MemoryCheckpoint{}
	cl := liveClient(srv.URL, "", &fakeClock{t: now}, now)
	cl.Checkpoint = cp2
	a2, _ := collect(t, cl, context.Background(), connectors.Full, time.Time{})
	if fmt.Sprint(a) != fmt.Sprint(a2) {
		t.Fatalf("full reruns differ:\n%v\n%v", a, a2)
	}
}

func TestLiveNoCheckpointFullRunsRestart(t *testing.T) {
	f := &fakeNVD{perWindow: 1, pageSize: 1}
	srv := httptest.NewServer(f)
	defer srv.Close()
	now := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 2; i++ {
		c := liveClient(srv.URL, "", &fakeClock{t: now}, now)
		if ids, errs := collect(t, c, context.Background(), connectors.Full, time.Time{}); len(ids) != len(Windows(FullStart, now, MaxWindow)) || len(errs) != 0 {
			t.Fatalf("run %d: %v %v", i, ids, errs)
		}
	}
}

func TestLiveUnreadableRecordsAreReported(t *testing.T) {
	f := &fakeNVD{perWindow: 4, pageSize: 4}
	f.entry = func(w time.Time, i int) string {
		switch i {
		case 1:
			return `{"cve":{"id":"CVE-2024-1111","descriptions":"x"},"extra":[1,2}`[:0] + `{"cve":{"id":"CVE-2024-1111"},"cve":[` + `]}`
		case 2:
			return `{"cve":{"id":12345}}`
		case 3:
			return `{"cve":{}}`
		}
		return fmt.Sprintf(`{"cve":{"id":%q}}`, idFor(w, i))
	}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := liveClient(srv.URL, "", &fakeClock{t: t0}, t0)
	var good []string
	var bad []*RecordError
	for it, err := range c.Fetch(context.Background(), connectors.Incremental, t0.Add(-time.Hour)) {
		var re *RecordError
		switch {
		case errors.As(err, &re):
			bad = append(bad, re)
		case err != nil:
			t.Fatal(err)
		default:
			good = append(good, it.ID)
		}
	}
	if len(good) != 1 || len(bad) != 3 {
		t.Fatalf("good=%v bad=%v", good, bad)
	}
	for _, re := range bad {
		if re.Reason == "" || re.Error() == "" {
			t.Fatalf("failure without reason: %+v", re)
		}
	}
	if bad[0].ID != "CVE-2024-1111" || bad[0].Index != 1 {
		t.Fatalf("id/index not reported: %+v", bad[0])
	}
	if st := c.Stats(); st.Records != 1 || st.Failed != 3 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestLiveZeroEntriesBeforeTotalIsAnError(t *testing.T) {
	f := &fakeNVD{perWindow: 3, pageSize: 0}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := liveClient(srv.URL, "", &fakeClock{t: t0}, t0)
	c.Checkpoint = &MemoryCheckpoint{}
	_, errs := collect(t, c, context.Background(), connectors.Incremental, t0.Add(-time.Hour))
	if len(errs) != 1 {
		t.Fatalf("errs = %v", errs)
	}
	if cur, _ := loadCursor(context.Background(), c.Checkpoint); cur != nil && cur.Complete {
		t.Fatal("run must not be marked complete")
	}
}

func TestCheckpointStores(t *testing.T) {
	ctx := context.Background()
	for name, cp := range map[string]Checkpointer{
		"memory": &MemoryCheckpoint{},
		"file":   FileCheckpoint{Path: filepath.Join(t.TempDir(), "d", "c.json")},
	} {
		if raw, err := cp.Load(ctx); err != nil || len(raw) != 0 {
			t.Fatalf("%s: empty load = %q %v", name, raw, err)
		}
		if err := cp.Save(ctx, json.RawMessage(`{"a":1}`)); err != nil {
			t.Fatal(err)
		}
		if err := cp.Save(ctx, json.RawMessage(`{"a":2}`)); err != nil {
			t.Fatal(err)
		}
		if raw, err := cp.Load(ctx); err != nil || string(raw) != `{"a":2}` {
			t.Fatalf("%s: load = %q %v", name, raw, err)
		}
	}
	bad := &MemoryCheckpoint{}
	bad.Save(ctx, json.RawMessage(`not json`))
	f := &fakeNVD{perWindow: 1, pageSize: 1}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := liveClient(srv.URL, "", &fakeClock{t: t0}, t0)
	c.Checkpoint = bad
	if _, errs := collect(t, c, ctx, connectors.Incremental, t0.Add(-time.Hour)); len(errs) != 1 || len(f.requests()) != 0 {
		t.Fatalf("corrupt checkpoint must stop the run: %v", errs)
	}
}
