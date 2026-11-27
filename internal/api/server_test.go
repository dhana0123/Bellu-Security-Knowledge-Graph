package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/apikey"
	"pgregory.net/rapid"
)

type fakeAuth struct{ keys map[string]string }

func (f fakeAuth) Verify(_ context.Context, key string) (string, error) {
	if n, ok := f.keys[key]; ok {
		return n, nil
	}
	return "", apikey.ErrUnauthorized
}

type fakeMeta struct {
	m     Meta
	err   error
	calls int
}

func (f *fakeMeta) Read(context.Context) (Meta, error) { f.calls++; return f.m, f.err }

type env struct {
	srv  *Server
	meta *fakeMeta
	log  *bytes.Buffer
	now  *time.Time
}

func newEnv(t *testing.T, limit int, ping error) *env {
	t.Helper()
	now := time.Date(2025, 1, 10, 12, 0, 0, 0, time.UTC)
	e := &env{meta: &fakeMeta{m: Meta{BuildState: "ready"}}, log: &bytes.Buffer{}, now: &now}
	nowFn := func() time.Time { return *e.now }
	e.srv = New(Config{
		Version: "test", Auth: fakeAuth{keys: map[string]string{"bskg_good": "alice"}},
		Limiter: NewKeyRateLimiter(limit, nowFn), Meta: e.meta,
		Ping:   func(context.Context) error { return ping },
		Logger: slog.New(slog.NewJSONHandler(e.log, nil)), QueryTimeout: 50 * time.Millisecond,
		StaleAfter: 48 * time.Hour, Now: nowFn,
	})
	e.srv.Handle("GET /thing/{id}", func(w http.ResponseWriter, r *http.Request) {
		e.srv.WriteJSON(w, r, 200, map[string]any{"id": r.PathValue("id")})
	})
	e.srv.Handle("GET /slow", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := e.srv.QueryContext(r)
		defer cancel()
		<-ctx.Done()
		e.srv.WriteGraphError(w, r, ctx.Err())
	})
	return e
}

func (e *env) do(path, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("bad json %q: %v", rec.Body.String(), err)
	}
	return m
}

func TestAuthenticatedRouteHasEnvelope(t *testing.T) {
	e := newEnv(t, 10, nil)
	rec := e.do("/v1/thing/abc?secret=zzz", "Bearer bskg_good")
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	m := decode(t, rec)
	g := m["graph"].(map[string]any)
	if m["id"] != "abc" || g["version"] != "test" || g["buildState"] != "ready" || g["stale"] != true {
		t.Fatalf("unexpected body %v", m)
	}
	src := g["sources"].(map[string]any)
	for _, s := range []string{"cwe", "nvd", "exploitdb"} {
		v, ok := src[s].(map[string]any)
		if !ok || v["lastSuccess"] != nil {
			t.Fatalf("source %s: %v", s, src)
		}
	}
}

func TestUnauthorizedBodiesIdentical(t *testing.T) {
	e := newEnv(t, 10, nil)
	var bodies []string
	for _, h := range []string{"", "Bearer ", "Bearer nope", "Basic bskg_good", "bskg_good"} {
		rec := e.do("/v1/thing/x", h)
		if rec.Code != 401 {
			t.Fatalf("%q: code %d", h, rec.Code)
		}
		bodies = append(bodies, rec.Body.String())
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("bodies differ: %q vs %q", b, bodies[0])
		}
	}
	if strings.Contains(bodies[0], `"id"`) {
		t.Fatal("no data expected")
	}
	if decode(t, e.do("/v1/nothing", ""))["error"] == nil {
		t.Fatal("unknown /v1 route without key must be 401 error body")
	}
}

func TestUnknownRouteIs404WhenAuthenticated(t *testing.T) {
	e := newEnv(t, 10, nil)
	rec := e.do("/v1/nothing", "Bearer bskg_good")
	if rec.Code != 404 || decode(t, rec)["graph"] == nil {
		t.Fatalf("code %d body %s", rec.Code, rec.Body)
	}
}

func TestRateLimit429(t *testing.T) {
	e := newEnv(t, 2, nil)
	for i := 0; i < 2; i++ {
		if c := e.do("/v1/thing/a", "Bearer bskg_good").Code; c != 200 {
			t.Fatalf("req %d: %d", i, c)
		}
	}
	rec := e.do("/v1/thing/a", "Bearer bskg_good")
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" || rec.Header().Get("Retry-After") == "0" {
		t.Fatalf("code %d retry %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if decode(t, rec)["graph"] == nil {
		t.Fatal("429 lacks graph")
	}
}

func TestQueryTimeout504(t *testing.T) {
	e := newEnv(t, 10, nil)
	rec := e.do("/v1/slow", "Bearer bskg_good")
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("code %d", rec.Code)
	}
	if decode(t, rec)["error"].(map[string]any)["code"] != "timeout" {
		t.Fatal("wrong code")
	}
}

func TestRequestLogHasNameAndPathOnly(t *testing.T) {
	e := newEnv(t, 10, nil)
	e.do("/v1/thing/abc?q=SECRETQ", "Bearer bskg_good")
	e.do("/v1/thing/abc", "Bearer bskg_bad")
	out := e.log.String()
	for _, bad := range []string{"bskg_good", "bskg_bad", "SECRETQ"} {
		if strings.Contains(out, bad) {
			t.Fatalf("log leaks %q: %s", bad, out)
		}
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var a, b map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &a)
	_ = json.Unmarshal([]byte(lines[1]), &b)
	if a["keyName"] != "alice" || a["path"] != "/v1/thing/abc" || b["keyName"] != "none" || b["status"] != float64(401) {
		t.Fatalf("log lines %v %v", a, b)
	}
}

func TestHealthz(t *testing.T) {
	if c := newEnv(t, 1, nil).do("/healthz", "").Code; c != 200 {
		t.Fatalf("ok: %d", c)
	}
	if c := newEnv(t, 1, errors.New("down")).do("/healthz", "").Code; c != 503 {
		t.Fatalf("down: %d", c)
	}
}

func TestMetaCacheAndFallback(t *testing.T) {
	e := newEnv(t, 100, nil)
	e.do("/v1/thing/a", "Bearer bskg_good")
	e.do("/v1/thing/a", "Bearer bskg_good")
	if e.meta.calls != 1 {
		t.Fatalf("expected cached, calls=%d", e.meta.calls)
	}
	*e.now = e.now.Add(3 * time.Second)
	e.meta.err = errors.New("neo4j down")
	rec := e.do("/v1/thing/a", "Bearer bskg_good")
	if decode(t, rec)["graph"].(map[string]any)["buildState"] != "ready" {
		t.Fatal("expected last good value on failure")
	}
}

func TestMetaDefaultsWhenNeverRead(t *testing.T) {
	e := newEnv(t, 100, nil)
	e.meta.err = errors.New("down")
	g := decode(t, e.do("/v1/thing/a", "Bearer bskg_good"))["graph"].(map[string]any)
	if g["buildState"] != DefaultBuildState || g["stale"] != true {
		t.Fatalf("%v", g)
	}
}

func TestStaleFreshAndLastSuccess(t *testing.T) {
	e := newEnv(t, 100, nil)
	ts := e.now.Add(-time.Hour)
	e.meta.m.LastSuccess = map[string]*time.Time{"nvd": &ts}
	g := decode(t, e.do("/v1/thing/a", "Bearer bskg_good"))["graph"].(map[string]any)
	if g["stale"] != false || g["sources"].(map[string]any)["nvd"].(map[string]any)["lastSuccess"] == nil {
		t.Fatalf("%v", g)
	}
}

// Feature: bellu-security-knowledge-graph, Property 40: Stale flag
// **Validates: Requirements 25.5**
func TestPropertyStale(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		hours := rapid.IntRange(1, 720).Draw(t, "threshold")
		now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
		if rapid.Bool().Draw(t, "none") {
			if !Stale(nil, now, time.Duration(hours)*time.Hour) {
				t.Fatal("nil must be stale")
			}
			return
		}
		age := time.Duration(rapid.Int64Range(0, 2000*3600).Draw(t, "ageSec")) * time.Second
		last := now.Add(-age)
		want := age > time.Duration(hours)*time.Hour
		if got := Stale(&last, now, time.Duration(hours)*time.Hour); got != want {
			t.Fatalf("age %v threshold %dh: got %v want %v", age, hours, got, want)
		}
	})
}
