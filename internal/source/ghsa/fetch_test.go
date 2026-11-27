package ghsa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/httpx"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
)

// fakeClock advances only when Sleep is called, so tests never wait.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	return nil
}
func (c *fakeClock) slept() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.sleeps...)
}

var t0 = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

// fakeGitHub serves generated advisories with the GitHub paging rules: the
// `after` cursor is the decimal index of the first record of the page.
type fakeGitHub struct {
	n     int
	mu    sync.Mutex
	reqs  []*http.Request
	count int
	// hook may answer a request itself; it returns true when it did.
	hook func(n int, w http.ResponseWriter, r *http.Request) bool
	srv  *httptest.Server
}

func recTime(i int) time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Minute)
}
func recID(i int) string { return fmt.Sprintf("GHSA-tst%d-aaaa-bbbb", i) }

func newFake(t *testing.T, n int) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{n: n}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	n := f.count
	f.count++
	f.reqs = append(f.reqs, r)
	f.mu.Unlock()
	if f.hook != nil && f.hook(n, w, r) {
		return
	}
	q := r.URL.Query()
	per, _ := strconv.Atoi(q.Get("per_page"))
	start, _ := strconv.Atoi(q.Get("after"))
	lo := 0
	if u := q.Get("updated"); u != "" {
		ts, err := time.Parse(time.RFC3339, strings.TrimPrefix(u, ">="))
		if err != nil {
			http.Error(w, "bad updated", 422)
			return
		}
		for lo < f.n && recTime(lo).Before(ts) {
			lo++
		}
	}
	i := lo + start
	end := min(i+per, f.n)
	out := []map[string]any{}
	for ; i < end; i++ {
		out = append(out, map[string]any{"ghsa_id": recID(i), "updated_at": recTime(i).Format(time.RFC3339), "summary": "s"})
	}
	if end < f.n {
		nu := url.Values{"after": {strconv.Itoa(end - lo)}, "per_page": {q.Get("per_page")}}
		w.Header().Set("Link", fmt.Sprintf(`<%s/advisories?%s>; rel="next"`, f.srv.URL, nu.Encode()))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (f *fakeGitHub) requests() []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*http.Request(nil), f.reqs...)
}

type env struct {
	f     *fakeGitHub
	a     *Adapter
	clock *fakeClock
	logs  *bytes.Buffer
}

func newEnv(t *testing.T, n int, o Options) *env {
	t.Helper()
	f := newFake(t, n)
	c := &fakeClock{now: t0}
	buf := &bytes.Buffer{}
	o.BaseURL = f.srv.URL + "/advisories"
	o.Clock = c
	if o.Client == nil {
		o.Client = &http.Client{}
	}
	o.Log = slog.New(slog.NewTextHandler(buf, nil))
	if o.Version == "" {
		o.Version = "1.2.3"
	}
	return &env{f: f, a: New(o), clock: c, logs: buf}
}

// drain reads an iterator until EOF or an error.
func drain(ctx context.Context, it source.Iterator) ([]source.Record, error) {
	var out []source.Record
	for {
		r, err := it.Next(ctx)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, r)
	}
}

func (e *env) run(t *testing.T, cp source.Checkpoint, opts source.RunOptions) ([]source.Record, error) {
	t.Helper()
	it, err := e.a.Fetch(context.Background(), cp, opts)
	if err != nil {
		t.Fatal(err)
	}
	return drain(context.Background(), it)
}

func payloads(recs []source.Record) []source.Record {
	var out []source.Record
	for _, r := range recs {
		if len(r.Payload) > 0 {
			out = append(out, r)
		}
	}
	return out
}

func TestRequestShapeAndPaging(t *testing.T) {
	e := newEnv(t, 250, Options{})
	recs, err := e.run(t, source.Checkpoint{}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := payloads(recs)
	if len(p) != 250 || len(recs) != 251 {
		t.Fatalf("records %d payloads %d, want 251 and 250", len(recs), len(p))
	}
	for i, r := range p {
		if r.ID != recID(i) {
			t.Fatalf("record %d id %s", i, r.ID)
		}
	}
	reqs := e.f.requests()
	if len(reqs) != 3 {
		t.Fatalf("%d requests, want 3", len(reqs))
	}
	q := reqs[0].URL.Query()
	for k, want := range map[string]string{"type": "reviewed", "per_page": "100", "sort": "updated", "direction": "asc"} {
		if q.Get(k) != want {
			t.Errorf("param %s = %q, want %q", k, q.Get(k), want)
		}
	}
	if q.Has("updated") || q.Has("after") {
		t.Errorf("first full request has updated or after: %v", q)
	}
	if got := reqs[1].URL.Query().Get("after"); got != "100" {
		t.Errorf("second page after = %q", got)
	}
	h := reqs[0].Header
	if h.Get("Accept") != "application/vnd.github+json" || h.Get("X-GitHub-Api-Version") != APIVersion || h.Get("User-Agent") != "bskg/1.2.3" {
		t.Errorf("headers: %v", h)
	}
	if h.Get("Authorization") != "" {
		t.Error("Authorization sent without a token")
	}
	if n := strings.Count(e.logs.String(), "60 requests per hour"); n != 1 {
		t.Errorf("token warning logged %d times, want 1: %s", n, e.logs.String())
	}
	// Cursors: the last record of page 1 points at page 2; the watermark rises.
	if got, want := p[99].Cursor.Resume, EncodeResume(time.Time{}, "100"); got != want {
		t.Errorf("cursor after record 99 = %q, want %q", got, want)
	}
	if got, want := p[0].Cursor.Resume, EncodeResume(time.Time{}, ""); got != want {
		t.Errorf("cursor after record 0 = %q, want %q", got, want)
	}
	if !p[10].Cursor.Watermark.Equal(recTime(10)) {
		t.Errorf("watermark after record 10 = %v", p[10].Cursor.Watermark)
	}
	last := recs[len(recs)-1]
	if len(last.Payload) != 0 || last.Cursor.Resume != "" || !last.Cursor.Watermark.Equal(recTime(249)) {
		t.Errorf("final marker = %+v", last)
	}
}

func TestIncrementalUsesWatermark(t *testing.T) {
	e := newEnv(t, 30, Options{})
	wm := recTime(20)
	recs, err := e.run(t, source.Checkpoint{Watermark: wm}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	q := e.f.requests()[0].URL.Query()
	if got, want := q.Get("updated"), ">="+wm.Format(time.RFC3339); got != want {
		t.Errorf("updated = %q, want %q", got, want)
	}
	if len(payloads(recs)) != 10 { // records 20..29 (the mark itself is read again)
		t.Errorf("%d records, want 10", len(payloads(recs)))
	}
}

func TestTokenHeaderOnlyWhenSetAndNeverLogged(t *testing.T) {
	const tok = "ghp_SECRETtoken0123456789"
	e := newEnv(t, 3, Options{Token: tok})
	recs, err := e.run(t, source.Checkpoint{}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.f.requests()[0].Header.Get("Authorization"); got != "Bearer "+tok {
		t.Errorf("Authorization = %q", got)
	}
	if strings.Contains(e.logs.String(), "60 requests per hour") {
		t.Error("warned about the missing token although it is set")
	}
	for _, r := range recs {
		if strings.Contains(r.Cursor.Resume, tok) {
			t.Error("token in cursor")
		}
	}

	// Failure paths: status errors, network errors and logs never show it.
	for name, hook := range map[string]func(int, http.ResponseWriter, *http.Request) bool{
		"500": func(_ int, w http.ResponseWriter, r *http.Request) bool {
			http.Error(w, "boom "+r.Header.Get("Authorization"), 500)
			return true
		},
		"401": func(_ int, w http.ResponseWriter, r *http.Request) bool {
			http.Error(w, "bad credentials", 401)
			return true
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, 3, Options{Token: tok})
			e.f.hook = hook
			_, err := e.run(t, source.Checkpoint{}, source.RunOptions{})
			if err == nil {
				t.Fatal("expected an error")
			}
			if strings.Contains(err.Error(), tok) || strings.Contains(e.logs.String(), tok) {
				t.Errorf("token leaked: %v / %s", err, e.logs.String())
			}
		})
	}
	// A dead server: the transport error must not show the token either.
	e2 := newEnv(t, 3, Options{Token: tok})
	e2.f.srv.Close()
	_, err = e2.run(t, source.Checkpoint{}, source.RunOptions{})
	if err == nil || strings.Contains(err.Error(), tok) || strings.Contains(e2.logs.String(), tok) {
		t.Errorf("network error %v, logs %s", err, e2.logs.String())
	}
}

func TestRetries(t *testing.T) {
	t.Run("5xx then success", func(t *testing.T) {
		e := newEnv(t, 3, Options{})
		e.f.hook = func(n int, w http.ResponseWriter, r *http.Request) bool {
			if n < 2 {
				w.WriteHeader(502)
				return true
			}
			return false
		}
		recs, err := e.run(t, source.Checkpoint{}, source.RunOptions{})
		if err != nil || len(payloads(recs)) != 3 {
			t.Fatalf("err %v records %d", err, len(payloads(recs)))
		}
		if got := e.clock.slept(); len(got) != 2 || got[0] != time.Second || got[1] != 2*time.Second {
			t.Errorf("sleeps %v, want [1s 2s]", got)
		}
	})
	t.Run("gives up after 3 retries", func(t *testing.T) {
		e := newEnv(t, 3, Options{})
		e.f.hook = func(_ int, w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(503); return true }
		_, err := e.run(t, source.Checkpoint{}, source.RunOptions{})
		var se *StatusError
		if !errors.As(err, &se) || se.Code != 503 {
			t.Fatalf("err = %v", err)
		}
		if got := e.clock.slept(); len(got) != 3 || got[0] != time.Second || got[2] != 4*time.Second {
			t.Errorf("sleeps %v, want [1s 2s 4s]", got)
		}
		if n := len(e.f.requests()); n != 4 {
			t.Errorf("%d requests, want 4", n)
		}
	})
	t.Run("4xx is not retried", func(t *testing.T) {
		e := newEnv(t, 3, Options{})
		e.f.hook = func(_ int, w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(404); return true }
		if _, err := e.run(t, source.Checkpoint{}, source.RunOptions{}); err == nil {
			t.Fatal("expected an error")
		}
		if n := len(e.f.requests()); n != 1 || len(e.clock.slept()) != 0 {
			t.Errorf("%d requests, sleeps %v", n, e.clock.slept())
		}
	})
	t.Run("truncated body is retried", func(t *testing.T) {
		e := newEnv(t, 3, Options{})
		e.f.hook = func(n int, w http.ResponseWriter, r *http.Request) bool {
			if n == 0 {
				_, _ = w.Write([]byte(`[{"ghsa_id":"GHSA-x`))
				return true
			}
			return false
		}
		recs, err := e.run(t, source.Checkpoint{}, source.RunOptions{})
		if err != nil || len(payloads(recs)) != 3 {
			t.Fatalf("err %v records %d", err, len(payloads(recs)))
		}
	})
	t.Run("Retry-After on a secondary limit", func(t *testing.T) {
		e := newEnv(t, 3, Options{})
		e.f.hook = func(n int, w http.ResponseWriter, r *http.Request) bool {
			if n == 0 {
				w.Header().Set("Retry-After", "30")
				w.Header().Set("X-RateLimit-Remaining", "42")
				w.WriteHeader(403)
				return true
			}
			return false
		}
		if _, err := e.run(t, source.Checkpoint{}, source.RunOptions{}); err != nil {
			t.Fatal(err)
		}
		if got := e.clock.slept(); len(got) != 1 || got[0] != 30*time.Second {
			t.Errorf("sleeps %v, want [30s]", got)
		}
	})
}

func TestRateLimitWaitsUntilReset(t *testing.T) {
	t.Run("remaining 0 on a 200", func(t *testing.T) {
		e := newEnv(t, 150, Options{})
		reset := t0.Add(120 * time.Second)
		e.f.hook = func(n int, w http.ResponseWriter, r *http.Request) bool {
			if n == 0 {
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
			}
			return false
		}
		recs, err := e.run(t, source.Checkpoint{}, source.RunOptions{})
		if err != nil || len(payloads(recs)) != 150 {
			t.Fatalf("err %v records %d", err, len(payloads(recs)))
		}
		got := e.clock.slept()
		if len(got) != 1 || got[0] < 120*time.Second || got[0] > 125*time.Second {
			t.Fatalf("sleeps %v, want one wait of about 120 s", got)
		}
		if n := len(e.f.requests()); n != 2 {
			t.Errorf("%d requests", n)
		}
	})
	t.Run("no wait when requests remain", func(t *testing.T) {
		e := newEnv(t, 150, Options{})
		e.f.hook = func(n int, w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("X-RateLimit-Remaining", "4999")
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(t0.Add(time.Hour).Unix(), 10))
			return false
		}
		if _, err := e.run(t, source.Checkpoint{}, source.RunOptions{}); err != nil || len(e.clock.slept()) != 0 {
			t.Fatalf("err %v sleeps %v", err, e.clock.slept())
		}
	})
	t.Run("403 with remaining 0", func(t *testing.T) {
		e := newEnv(t, 3, Options{})
		reset := t0.Add(45 * time.Minute)
		e.f.hook = func(n int, w http.ResponseWriter, r *http.Request) bool {
			if n == 0 {
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
				w.WriteHeader(403)
				return true
			}
			return false
		}
		recs, err := e.run(t, source.Checkpoint{}, source.RunOptions{})
		if err != nil || len(payloads(recs)) != 3 {
			t.Fatalf("err %v records %d", err, len(payloads(recs)))
		}
		got := e.clock.slept()
		if len(got) != 1 || got[0] < 45*time.Minute {
			t.Fatalf("sleeps %v, want one wait of at least 45 min", got)
		}
	})
	t.Run("429 without reset header still waits and gives up", func(t *testing.T) {
		e := newEnv(t, 3, Options{})
		e.f.hook = func(n int, w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(429)
			return true
		}
		_, err := e.run(t, source.Checkpoint{}, source.RunOptions{})
		if err == nil {
			t.Fatal("expected an error")
		}
		if n := len(e.f.requests()); n != maxLimitWaits+1 {
			t.Errorf("%d requests, want %d", n, maxLimitWaits+1)
		}
	})
}

func TestResumeAfterInterruption(t *testing.T) {
	e := newEnv(t, 250, Options{})
	e.f.hook = func(n int, w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Query().Get("after") == "200" {
			w.WriteHeader(500)
			return true
		}
		return false
	}
	recs, err := e.run(t, source.Checkpoint{}, source.RunOptions{})
	if err == nil {
		t.Fatal("expected the run to fail at page 3")
	}
	if len(recs) != 200 {
		t.Fatalf("%d records before the failure", len(recs))
	}
	cur := recs[len(recs)-1].Cursor
	if cur.Resume != EncodeResume(time.Time{}, "200") || !cur.Watermark.Equal(recTime(199)) {
		t.Fatalf("cursor after the last committed record: %+v", cur)
	}

	// Second run: the server works; the run continues at page 3 and the lower
	// bound of the first run (none) is kept although the watermark moved.
	e.f.hook = nil
	e.f.mu.Lock()
	e.f.reqs, e.f.count = nil, 0
	e.f.mu.Unlock()
	recs2, err := e.run(t, source.Checkpoint{Resume: cur.Resume, Watermark: cur.Watermark}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	reqs := e.f.requests()
	if len(reqs) != 1 || reqs[0].URL.Query().Get("after") != "200" || reqs[0].URL.Query().Has("updated") {
		t.Fatalf("resume request: %v", reqs[0].URL.RawQuery)
	}
	if p := payloads(recs2); len(p) != 50 || p[0].ID != recID(200) {
		t.Fatalf("resumed records: %d, first %s", len(p), p[0].ID)
	}
	if last := recs2[len(recs2)-1]; last.Cursor.Resume != "" || !last.Cursor.Watermark.Equal(recTime(249)) {
		t.Errorf("final marker %+v", last)
	}
}

func TestResumeKeepsItsLowerBound(t *testing.T) {
	e := newEnv(t, 50, Options{})
	since := recTime(10)
	resume := EncodeResume(since, "20")
	// The stored watermark is later than the run's lower bound.
	recs, err := e.run(t, source.Checkpoint{Resume: resume, Watermark: recTime(35)}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	q := e.f.requests()[0].URL.Query()
	if q.Get("updated") != ">="+since.Format(time.RFC3339) || q.Get("after") != "20" {
		t.Errorf("query %v", q)
	}
	if p := payloads(recs); len(p) != 20 || p[0].ID != recID(30) {
		t.Errorf("records %d first %v", len(p), p[0].ID)
	}
	// A watermark that is lower than a record's own time never moves back.
	if recs[0].Cursor.Watermark.Before(recTime(35)) {
		t.Errorf("watermark moved back to %v", recs[0].Cursor.Watermark)
	}
}

func TestFailureKeepsTheMark(t *testing.T) {
	e := newEnv(t, 10, Options{})
	e.f.hook = func(_ int, w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(500); return true }
	recs, err := e.run(t, source.Checkpoint{Watermark: recTime(5)}, source.RunOptions{})
	if err == nil || len(recs) != 0 {
		t.Fatalf("err %v records %d", err, len(recs))
	}
}

func TestInvalidResume(t *testing.T) {
	a := New(Options{})
	for _, r := range []string{"garbage", "v1|nope|x", "v1|2026-01-01T00:00:00Z", "v2||x"} {
		if _, err := a.Fetch(context.Background(), source.Checkpoint{Resume: r}, source.RunOptions{}); err == nil {
			t.Errorf("resume %q accepted", r)
		}
	}
}

func TestResumeRoundTrip(t *testing.T) {
	since := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	got, after, err := parseResume(EncodeResume(since, "Y3Vyc29yOnYy=="))
	if err != nil || !got.Equal(since) || after != "Y3Vyc29yOnYy==" {
		t.Fatalf("%v %q %v", got, after, err)
	}
	got, after, err = parseResume(EncodeResume(time.Time{}, ""))
	if err != nil || !got.IsZero() || after != "" {
		t.Fatalf("%v %q %v", got, after, err)
	}
}

func TestNextLinkWithoutCursorFails(t *testing.T) {
	e := newEnv(t, 3, Options{})
	e.f.hook = func(_ int, w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Link", `<https://api.github.com/advisories?per_page=100>; rel="next"`)
		_, _ = w.Write([]byte("[]"))
		return true
	}
	if _, err := e.run(t, source.Checkpoint{}, source.RunOptions{}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestNextLinkHostIsIgnored(t *testing.T) {
	// Only the cursor of the link is used, never its host.
	got, err := nextAfter([]string{`<https://evil.example/x?after=abc>; rel="prev", <https://evil.example/x?after=zzz>; rel="next"`})
	if err != nil || got != "zzz" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestSample(t *testing.T) {
	e := newEnv(t, 500, Options{})
	recs, err := e.run(t, source.Checkpoint{Watermark: recTime(300), Resume: "ignored"}, source.RunOptions{SampleLimit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 5 || recs[0].ID != recID(0) {
		t.Fatalf("%d records, first %s", len(recs), recs[0].ID)
	}
	for _, r := range recs {
		if r.Cursor != (source.Cursor{}) {
			t.Fatalf("a sample moved the cursor: %+v", r.Cursor)
		}
	}
	reqs := e.f.requests()
	if len(reqs) != 1 || reqs[0].URL.Query().Get("per_page") != "5" || reqs[0].URL.Query().Has("updated") {
		t.Fatalf("requests %d %v", len(reqs), reqs[0].URL.RawQuery)
	}
}

func TestSampleSpansPages(t *testing.T) {
	e := newEnv(t, 500, Options{PageSize: 10})
	recs, err := e.run(t, source.Checkpoint{}, source.RunOptions{SampleLimit: 25})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 25 || recs[24].ID != recID(24) {
		t.Fatalf("%d records, last %s", len(recs), recs[len(recs)-1].ID)
	}
	if n := len(e.f.requests()); n != 3 {
		t.Errorf("%d requests, want 3", n)
	}
}

func TestSampleLargerThanSource(t *testing.T) {
	e := newEnv(t, 7, Options{})
	recs, err := e.run(t, source.Checkpoint{}, source.RunOptions{SampleLimit: 50})
	if err != nil || len(recs) != 7 {
		t.Fatalf("err %v records %d", err, len(recs))
	}
}

func TestEmptyResultKeepsTheMark(t *testing.T) {
	e := newEnv(t, 5, Options{})
	recs, err := e.run(t, source.Checkpoint{Watermark: recTime(100)}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// The mark itself is passed in the cursor, so a clear marker never lowers it.
	if len(recs) != 1 || len(recs[0].Payload) != 0 || !recs[0].Cursor.Watermark.Equal(recTime(100)) {
		t.Fatalf("records %+v", recs)
	}
}

func TestSkippedRecordsAreCountedAndDoNotMoveTheMark(t *testing.T) {
	e := newEnv(t, 1, Options{})
	e.f.hook = func(_ int, w http.ResponseWriter, r *http.Request) bool {
		_, _ = w.Write([]byte(`[{"ghsa_id":"GHSA-aaaa-bbbb-cccc","updated_at":"2026-02-01T00:00:00Z"},
			{"html_url":"https://github.com/advisories/x","updated_at":"2030-01-01T00:00:00Z"},
			{"ghsa_id":"GHSA-dddd-eeee-ffff"}]`))
		return true
	}
	recs, err := e.run(t, source.Checkpoint{}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads(recs)) != 3 {
		t.Fatalf("records %d", len(payloads(recs)))
	}
	want := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	if got := recs[len(recs)-1].Cursor.Watermark; !got.Equal(want) {
		t.Errorf("final watermark %v, want %v", got, want)
	}
	if !strings.Contains(e.logs.String(), "count=2") {
		t.Errorf("skipped count not logged: %s", e.logs.String())
	}
}

func TestContextCancel(t *testing.T) {
	e := newEnv(t, 10, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	it, err := e.a.Fetch(ctx, source.Checkpoint{}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := it.Next(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestDefaultClientRestrictedToHost(t *testing.T) {
	a := New(Options{BaseURL: "https://example.org/advisories", Clock: &fakeClock{now: t0}, Policy: &httpx.Policy{}})
	it, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = it.Next(context.Background())
	var he *httpx.HostNotAllowedError
	if !errors.As(err, &he) {
		t.Fatalf("err = %v, want HostNotAllowedError", err)
	}
}
