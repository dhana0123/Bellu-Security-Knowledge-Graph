package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/checkpoint"
)

func opsEnv(t *testing.T, q queryFunc, src SourceStatusFunc, batch BatchFunc) *env {
	t.Helper()
	e := newEnv(t, 1000, nil)
	if src == nil {
		src = func(context.Context, []string) ([]checkpoint.SourceStatus, error) { return nil, nil }
	}
	if batch == nil {
		batch = func(ctx context.Context, fn func(queryFunc) error) error { return fn(q) }
	}
	OpsRoutes(e.srv, OpsConfig{Q: q, Batch: batch, SourceStatus: src})
	return e
}

func TestKeyInURLRejected(t *testing.T) {
	e := newEnv(t, 1000, nil)
	for _, qs := range []string{
		"apikey=x", "API_KEY=x", "api-key=x", "Key=x", "token=x", "access_token=x", "Authorization=x",
		"foo=bskg_0123456789abcdef_secret", "foo=%20bskg_0123456789abcdef_s",
	} {
		rec := e.do("/v1/thing/a?"+qs, "Bearer bskg_good")
		er, _ := decode(t, rec)["error"].(map[string]any)
		if rec.Code != 400 || er["code"] != "key_in_url" {
			t.Errorf("%s: %d %s", qs, rec.Code, rec.Body.String())
		}
	}
	if rec := e.do("/v1/thing/a?q=bskg_short", "Bearer bskg_good"); rec.Code != 200 {
		t.Errorf("harmless query rejected: %d", rec.Code)
	}
	if h := e.do("/v1/thing/a", "Bearer bskg_good").Header(); h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("headers: %v", h)
	}
}

func TestMigratingGate(t *testing.T) {
	e := newEnv(t, 1000, nil)
	e.srv.cfg.Pending = func(context.Context) (bool, error) { return true, nil }
	rec := e.do("/v1/thing/a", "Bearer bskg_good")
	body := decode(t, rec)
	er, _ := body["error"].(map[string]any)
	g, _ := body["graph"].(map[string]any)
	if rec.Code != 503 || er["code"] != "migrating" || g["buildState"] != "migrating" {
		t.Fatalf("%d %v", rec.Code, body)
	}
	if c := e.do("/healthz", "").Code; c != 503 {
		t.Fatalf("healthz %d", c)
	}
	*e.now = e.now.Add(time.Minute) // past the 2 s cache
	e.srv.cfg.Pending = func(context.Context) (bool, error) { return false, nil }
	if c := e.do("/v1/thing/a", "Bearer bskg_good").Code; c != 200 {
		t.Fatalf("after migration: %d", c)
	}
	if c := e.do("/healthz", "").Code; c != 200 {
		t.Fatalf("healthz after: %d", c)
	}
}

func TestMigrationPending(t *testing.T) {
	for _, c := range []struct {
		rows []Row
		want bool
	}{
		{[]Row{{"version": int64(2)}}, false},
		{[]Row{{"version": int64(1)}}, true},
		{[]Row{{"version": nil}}, true},
		{nil, true},
	} {
		got, err := MigrationPending(func(context.Context, string, map[string]any) ([]Row, error) { return c.rows, nil }, 2)(context.Background())
		if err != nil || got != c.want {
			t.Errorf("%v: %v %v", c.rows, got, err)
		}
	}
}

func TestBuildModeInEnvelope(t *testing.T) {
	e := newEnv(t, 1000, nil)
	e.meta.m = Meta{BuildState: "ready", BuildMode: "sample"}
	g, _ := decode(t, e.do("/v1/thing/a", "Bearer bskg_good"))["graph"].(map[string]any)
	if g["buildMode"] != "sample" || g["stale"] != false {
		t.Fatalf("%v", g)
	}
	if _, ok := g["sources"]; !ok {
		t.Fatal("sources missing")
	}
	e2 := newEnv(t, 1000, nil)
	g, _ = decode(t, e2.do("/v1/thing/a", "Bearer bskg_good"))["graph"].(map[string]any)
	if v, ok := g["buildMode"]; !ok || v != nil || g["stale"] != true {
		t.Fatalf("unset mode: %v", g)
	}
}

func TestNoCORSHeaders(t *testing.T) {
	e := newEnv(t, 1000, nil)
	e.srv.mountUI(fstest.MapFS{"index.html": {Data: []byte("<html>")}})
	for _, p := range []string{"/v1/thing/a", "/v1/nope", "/healthz", "/ui/", "/ui/x", "/nope"} {
		for _, m := range []string{"GET", "OPTIONS", "POST", "HEAD"} {
			req := httptest.NewRequest(m, p, nil)
			req.Header.Set("Origin", "https://evil.example")
			req.Header.Set("Access-Control-Request-Method", "GET")
			req.Header.Set("Authorization", "Bearer bskg_good")
			rec := httptest.NewRecorder()
			e.srv.Handler().ServeHTTP(rec, req)
			for k := range rec.Header() {
				if strings.HasPrefix(strings.ToLower(k), "access-control-") {
					t.Errorf("%s %s sets %s", m, p, k)
				}
			}
		}
	}
}

func TestUIHandler(t *testing.T) {
	e := newEnv(t, 1000, nil)
	e.srv.mountUI(fstest.MapFS{
		"index.html":               {Data: []byte("<html>app</html>")},
		"assets/index-DiwrgTda.js": {Data: []byte("console.log(1)")},
		"favicon.svg":              {Data: []byte("<svg/>")},
	})
	get := func(p string) *httptest.ResponseRecorder { return e.do(p, "") }
	for _, p := range []string{"/ui/", "/ui/index.html", "/ui/search", "/ui/cve/CVE-2021-1", "/ui/assets-not"} {
		rec := get(p)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "app") || rec.Header().Get("Cache-Control") != "no-cache" {
			t.Errorf("%s: %d %v", p, rec.Code, rec.Header())
		}
	}
	rec := get("/ui/assets/index-DiwrgTda.js")
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" || rec.Header().Get("ETag") == "" {
		t.Errorf("hashed asset: %d %v", rec.Code, rec.Header())
	}
	if rec := get("/ui/assets/missing-AAAAAAAA.js"); rec.Code != 404 {
		t.Errorf("missing asset: %d", rec.Code)
	}
	if rec := get("/ui/favicon.svg"); rec.Header().Get("Cache-Control") != "no-cache" {
		t.Errorf("favicon cache: %v", rec.Header())
	}
	if rec := get("/ui"); rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/ui/" {
		t.Errorf("redirect: %d %v", rec.Code, rec.Header())
	}
	for _, p := range []string{"/ui/", "/ui/assets/index-DiwrgTda.js", "/ui/zzz", "/ui/assets/missing.js"} {
		h := get(p).Header()
		csp := h.Get("Content-Security-Policy")
		for _, d := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self' data:", "font-src 'self'", "connect-src 'self'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'"} {
			if !strings.Contains(csp, d) {
				t.Errorf("%s: CSP lacks %q", p, d)
			}
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: headers %v", p, h)
		}
	}
	// 304 with the ETag.
	first := get("/ui/")
	req := httptest.NewRequest("GET", "/ui/", nil)
	req.Header.Set("If-None-Match", first.Header().Get("ETag"))
	rr := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotModified {
		t.Errorf("etag: %d", rr.Code)
	}
}

func TestUINotBuilt(t *testing.T) {
	e := newEnv(t, 1000, nil)
	e.srv.mountUI(fstest.MapFS{})
	if rec := e.do("/ui/", ""); rec.Code != 404 || !strings.Contains(rec.Body.String(), "UI not built") {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}

// --- statistics ---

func TestStatsCacheSingleFlightTTLAndStale(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	var calls atomic.Int32
	release := make(chan struct{})
	var fail atomic.Bool
	c := &statsCache{ttl: 5 * time.Minute, timeout: time.Second, now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }}
	c.compute = func(ctx context.Context) (*StatsResult, error) {
		calls.Add(1)
		<-release
		if fail.Load() {
			return nil, context.DeadlineExceeded
		}
		return &StatsResult{GeneratedAt: now}, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, stale, err := c.get(context.Background()); err != nil || stale {
				t.Errorf("get: %v %v", stale, err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	release <- struct{}{}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("computations: %d", calls.Load())
	}
	if _, _, _ = c.get(context.Background()); calls.Load() != 1 {
		t.Fatal("fresh value recomputed")
	}
	mu.Lock()
	now = now.Add(6 * time.Minute)
	mu.Unlock()
	fail.Store(true)
	go func() { release <- struct{}{} }()
	res, stale, err := c.get(context.Background())
	if err != nil || !stale || res == nil || calls.Load() != 2 {
		t.Fatalf("stale: %v %v %v calls=%d", res, stale, err, calls.Load())
	}
	// No cached value and a failure: the error is returned.
	c2 := &statsCache{ttl: time.Minute, timeout: time.Second, now: time.Now,
		compute: func(context.Context) (*StatsResult, error) { return nil, errors.New("boom") }}
	if _, _, err := c2.get(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestStatsCacheTimeoutIsApplied(t *testing.T) {
	c := &statsCache{ttl: time.Minute, timeout: 20 * time.Millisecond, now: time.Now,
		compute: func(ctx context.Context) (*StatsResult, error) { <-ctx.Done(); return nil, ctx.Err() }}
	if _, _, err := c.get(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

func statsFake(calls *atomic.Int32) queryFunc {
	return func(_ context.Context, q string, _ map[string]any) ([]Row, error) {
		calls.Add(1)
		switch q {
		case cypherStatsScan:
			return []Row{
				{"year": int64(2020), "severity": "HIGH", "exploitability": int64(1), "n": int64(2)},
				{"year": int64(2020), "severity": "LOW", "exploitability": int64(0), "n": int64(1)},
				{"year": int64(2021), "severity": "UNSCORED", "exploitability": nil, "n": int64(1)},
				{"year": nil, "severity": "CRITICAL", "exploitability": int64(0), "n": int64(2)},
			}, nil
		case cypherStatsTopWeaknesses:
			return []Row{{"key": "CWE-79", "n": int64(3)}}, nil
		case cypherStatsTopVendors, cypherStatsTopProducts:
			return nil, nil
		case cypherStatusBuild:
			return []Row{{"found": true, "buildState": "ready", "buildMode": "sample", "sampleLimit": int64(1000)}}, nil
		}
		return []Row{{"n": int64(7)}}, nil
	}
}

func TestStatsEndpoint(t *testing.T) {
	var calls atomic.Int32
	e := opsEnv(t, statsFake(&calls), nil, nil)
	code, body := getJSON(t, e, "/v1/stats")
	if code != 200 {
		t.Fatalf("%d %v", code, body)
	}
	if body["statsStale"] != false || body["generatedAt"] == nil || body["buildState"] != "ready" || body["buildMode"] != "sample" {
		t.Fatalf("%v", body)
	}
	share, _ := body["exploitedShare"].(map[string]any)
	if share["exploited"] != float64(2) || share["total"] != float64(6) || share["ratio"] != 0.3333 {
		t.Fatalf("share %v", share)
	}
	years, _ := body["cvesByYear"].([]any)
	if len(years) != 2 || years[0].(map[string]any)["year"] != float64(2020) || years[0].(map[string]any)["count"] != float64(3) {
		t.Fatalf("years %v", years)
	}
	sev, _ := body["cvssDistribution"].([]any)
	if len(sev) != 6 || sev[5].(map[string]any)["severity"] != "CRITICAL" || sev[5].(map[string]any)["count"] != float64(2) {
		t.Fatalf("sev %v", sev)
	}
	if l, _ := body["labels"].([]any); len(l) != 9 || l[0].(map[string]any)["label"] != "Vulnerability" || l[0].(map[string]any)["count"] != float64(7) {
		t.Fatalf("labels %v", body["labels"])
	}
	if r, _ := body["relationships"].([]any); len(r) != 10 {
		t.Fatalf("rels %v", r)
	}
	// A second request is served from the cache: no stats queries run again.
	before := calls.Load()
	getJSON(t, e, "/v1/stats")
	// Only the two per-request status queries (build, jobs) may run.
	if d := calls.Load() - before; d != 2 {
		t.Fatalf("extra queries on cached request: %d", d)
	}
}

func TestStatsFailureWithoutCache(t *testing.T) {
	e := opsEnv(t, func(context.Context, string, map[string]any) ([]Row, error) { return nil, context.DeadlineExceeded }, nil, nil)
	if code, _ := getJSON(t, e, "/v1/stats"); code != 504 {
		t.Fatalf("timeout: %d", code)
	}
	e = opsEnv(t, func(context.Context, string, map[string]any) ([]Row, error) { return nil, errors.New("x") }, nil, nil)
	if code, _ := getJSON(t, e, "/v1/stats"); code != 500 {
		t.Fatalf("failure: %d", code)
	}
}

// --- status ---

func TestStatusEndpoint(t *testing.T) {
	ts := time.Date(2025, 1, 9, 3, 0, 0, 0, time.UTC)
	q := func(_ context.Context, query string, _ map[string]any) ([]Row, error) {
		switch query {
		case cypherStatusBuild:
			return []Row{{"found": true, "buildState": "nvd_catch_up", "buildMode": "sample", "sampleLimit": int64(1000),
				"queueComplete": false, "validationStatus": "passed", "validationMode": "sample", "validationEndedAt": ts}}, nil
		case cypherStatusJobs:
			return []Row{
				{"name": "cwe", "state": "succeeded", "attempts": int64(1), "mode": "sample", "limit": int64(1000), "startedAt": ts, "endedAt": ts},
				{"name": "migrate", "state": "succeeded", "attempts": int64(1), "startedAt": ts, "endedAt": ts},
				{"name": "nvd-catch-up", "state": "running", "attempts": int64(2), "startedAt": ts},
			}, nil
		}
		return nil, nil
	}
	src := func(_ context.Context, s []string) ([]checkpoint.SourceStatus, error) {
		return []checkpoint.SourceStatus{
			{Source: "cwe", Checkpoint: checkpoint.Checkpoint{Found: true, Watermark: ts, Version: "4.14"}, LastStatus: "succeeded", LastStarted: ts, LastSuccess: ts, DeadLetters: 1},
			{Source: "nvd"}, {Source: "exploitdb"},
		}, nil
	}
	e := opsEnv(t, q, src, nil)
	code, body := getJSON(t, e, "/v1/status")
	if code != 200 {
		t.Fatalf("%d %v", code, body)
	}
	if body["buildState"] != "nvd_catch_up" || body["buildMode"] != "sample" || body["sampleLimit"] != float64(1000) {
		t.Fatalf("%v", body)
	}
	srcs, _ := body["sources"].([]any)
	cwe := srcs[0].(map[string]any)
	nvd := srcs[1].(map[string]any)
	if cwe["neverRun"] != false || cwe["deadLetters"] != float64(1) || cwe["lastRun"].(map[string]any)["status"] != "succeeded" ||
		nvd["neverRun"] != true || nvd["lastRun"] != nil || nvd["lastSuccess"] != nil {
		t.Fatalf("sources %v", srcs)
	}
	jobs := body["queue"].(map[string]any)["jobs"].([]any)
	if len(jobs) != 3 || jobs[0].(map[string]any)["name"] != "migrate" || jobs[2].(map[string]any)["state"] != "running" {
		t.Fatalf("jobs %v", jobs)
	}
	if v := body["validation"].(map[string]any); v["status"] != "passed" || v["buildMode"] != "sample" {
		t.Fatalf("validation %v", v)
	}
}

// --- neighborhood ---

func TestNeighborhoodValidation(t *testing.T) {
	var ran bool
	e := opsEnv(t, func(context.Context, string, map[string]any) ([]Row, error) { ran = true; return nil, nil }, nil, nil)
	bad := map[string]string{
		"id=CVE-2021-1":       "type",
		"type=Vulnerability":  "id",
		"type=Nope&id=x":      "type",
		"type=Migration&id=1": "type",
		"type=Package&id=x":   "type",
		"type=Vulnerability&id=" + strings.Repeat("a", 257): "id",
		"type=Vendor&id=x&depth=3":                          "depth",
		"type=Vendor&id=x&depth=0":                          "depth",
		"type=Vendor&id=x&limit=0":                          "limit",
		"type=Vendor&id=x&limit=301":                        "limit",
		"type=Vendor&id=x&limit=a":                          "limit",
		"type=Vendor&id=x&nodeTypes=Product,Bogus":          "nodeTypes",
		"type=Vendor&id=x&relTypes=AFFECTS,Bogus":           "relTypes",
		"type=Vendor&id=x&relTypes=AFFECTS_PACKAGE":         "relTypes",
	}
	many := make([]string, 51)
	for i := range many {
		many[i] = "AFFECTS"
	}
	bad["type=Vendor&id=x&relTypes="+strings.Join(many, ",")] = "relTypes"
	for qs, param := range bad {
		code, body := getJSON(t, e, "/v1/graph/neighborhood?"+qs)
		er, _ := body["error"].(map[string]any)
		if code != 400 || er["parameter"] != param {
			t.Errorf("%s: %d %v", qs, code, body)
		}
	}
	if ran {
		t.Fatal("a query ran for an invalid request")
	}
}

func nbRow() Row {
	return Row{
		"truncated": true,
		"nodes": []any{
			map[string]any{"id": "Vulnerability:CVE-2021-1", "labels": []any{"Vulnerability"}, "props": map[string]any{
				"cveID": "CVE-2021-1", "v3baseScore": 9.8, "description": strings.Repeat("é", 600),
				"sources": []any{"nvd"}, "p_nvd_run": "r1", "bskgInternal": 1, "publishedDate": neo4j.DateOf(time.Date(2021, 1, 2, 0, 0, 0, 0, time.UTC)),
			}},
			map[string]any{"id": "Product:" + strings.Repeat("p", 150), "labels": []any{"Product"}, "props": map[string]any{}},
			map[string]any{"id": "Exploit:42", "labels": []any{"Exploit"}, "props": map[string]any{"eid": int64(42)}},
		},
		"edges": []any{
			map[string]any{"source": "Exploit:42", "target": "Vulnerability:CVE-2021-1", "type": "EXPLOITS", "viewID": nil},
			map[string]any{"source": "Exploit:42", "target": "Vulnerability:CVE-2021-1", "type": "EXPLOITS", "viewID": nil},
			map[string]any{"source": "Weakness:CWE-1", "target": "Weakness:CWE-2", "type": "CHILD_OF", "viewID": "1000"},
		},
	}
}

func TestNeighborhoodResponseAndParams(t *testing.T) {
	var gotQ string
	var gotP map[string]any
	e := opsEnv(t, func(_ context.Context, q string, p map[string]any) ([]Row, error) {
		gotQ, gotP = q, p
		return []Row{nbRow()}, nil
	}, nil, nil)
	code, body := getJSON(t, e, "/v1/graph/neighborhood?type=Vulnerability&id=cve-2021-1&depth=2&limit=50&relTypes=EXPLOITS,AFFECTS&nodeTypes=Exploit")
	if code != 200 {
		t.Fatalf("%d %v", code, body)
	}
	if gotQ != neighborhoodQueries["Vulnerability"][1] {
		t.Fatal("wrong query for depth 2")
	}
	if gotP["id"] != "CVE-2021-1" || gotP["cap"] != int64(50) || gotP["keep"] != int64(49) || gotP["allRels"] != false || gotP["allNodes"] != false {
		t.Fatalf("params %v", gotP)
	}
	nodes := body["nodes"].([]any)
	if len(nodes) != 3 || body["truncated"] != true {
		t.Fatalf("%v", body)
	}
	n0 := nodes[0].(map[string]any) // sorted: Exploit:42 first
	if n0["id"] != "Exploit:42" || n0["type"] != "Exploit" || n0["key"] != "42" {
		t.Fatalf("n0 %v", n0)
	}
	var vul map[string]any
	for _, n := range nodes {
		m := n.(map[string]any)
		if m["type"] == "Vulnerability" {
			vul = m
		}
		if m["type"] == "Product" && len([]rune(m["label"].(string))) != 100 {
			t.Errorf("label not cut: %v", m["label"])
		}
	}
	props := vul["properties"].(map[string]any)
	if _, ok := props["sources"]; ok {
		t.Error("list property kept")
	}
	if _, ok := props["p_nvd_run"]; ok {
		t.Error("provenance kept")
	}
	if _, ok := props["bskgInternal"]; ok {
		t.Error("internal property kept")
	}
	if len([]rune(props["description"].(string))) != 500 || props["publishedDate"] != "2021-01-02" || props["v3baseScore"] != 9.8 {
		t.Fatalf("props %v", props)
	}
	edges := body["edges"].([]any)
	if len(edges) != 2 {
		t.Fatalf("edges %v", edges)
	}
	if edges[0].(map[string]any)["id"] != "Exploit:42|EXPLOITS|Vulnerability:CVE-2021-1" || edges[1].(map[string]any)["id"] != "Weakness:CWE-1|CHILD_OF|Weakness:CWE-2|1000" ||
		edges[1].(map[string]any)["viewID"] != "1000" {
		t.Fatalf("edges %v", edges)
	}
	// Defaults: depth 1, limit 100, no restrictions.
	getJSON(t, e, "/v1/graph/neighborhood?type=Vendor&id=Acme")
	if gotQ != neighborhoodQueries["Vendor"][0] || gotP["cap"] != int64(100) || gotP["allRels"] != true || gotP["allNodes"] != true {
		t.Fatalf("defaults %v", gotP)
	}
}

func TestNeighborhoodErrors(t *testing.T) {
	e := opsEnv(t, func(context.Context, string, map[string]any) ([]Row, error) { return nil, nil }, nil, nil)
	if code, body := getJSON(t, e, "/v1/graph/neighborhood?type=Vendor&id=Nope"); code != 404 || body["nodes"] != nil {
		t.Fatalf("404: %d %v", code, body)
	}
	e = opsEnv(t, func(context.Context, string, map[string]any) ([]Row, error) { return nil, context.DeadlineExceeded }, nil, nil)
	if code, body := getJSON(t, e, "/v1/graph/neighborhood?type=Vendor&id=Nope"); code != 503 || body["nodes"] != nil {
		t.Fatalf("503: %d %v", code, body)
	}
}

func TestNeighborhoodQueriesCoverEveryDomainLabel(t *testing.T) {
	for _, l := range []string{"Vulnerability", "Exploit", "Author", "Weakness", "Domain", "Product", "Vendor"} {
		qs, ok := neighborhoodQueries[l]
		if !ok || qs[0] == qs[1] || !strings.Contains(qs[0], "(s:"+l+" {") {
			t.Errorf("%s: %v", l, ok)
		}
	}
}

func TestKeyExprUsesLabelSpecificKey(t *testing.T) {
	// FixCommit has a url property and url is the Repository key, so the node
	// id must pick the key by label instead of coalescing key names.
	q := nidExpr("n")
	if strings.Contains(q, "coalesce") || !strings.Contains(q, "WHEN 'FixCommit' THEN n.fcKey") || !strings.Contains(q, "WHEN 'Repository' THEN n.url") {
		t.Errorf("nidExpr = %s", q)
	}
}

func TestStatsCoverage(t *testing.T) {
	at := time.Date(2025, 2, 3, 4, 5, 6, 0, time.UTC)
	var calls atomic.Int32
	base := statsFake(&calls)
	q := func(ctx context.Context, query string, p map[string]any) ([]Row, error) {
		switch query {
		case cypherCoverageVulns:
			return []Row{{"cves": int64(10), "cvesNotRejected": int64(9)}}, nil
		case cypherCoverageWeaknesses:
			return []Row{{"weaknesses": int64(4)}}, nil
		case cypherCoverageExploits:
			return nil, errors.New("down")
		}
		return base(ctx, query, p)
	}
	src := func(_ context.Context, names []string) ([]checkpoint.SourceStatus, error) {
		by := map[string]checkpoint.SourceStatus{
			"nvd": {Source: "nvd", Upstream: map[string]int64{"cves": 12, "cvesNotRejected": 11}, UpstreamAt: at},
			"cwe": {Source: "cwe"},
		}
		var out []checkpoint.SourceStatus
		for _, n := range names {
			s, ok := by[n]
			if !ok {
				s = checkpoint.SourceStatus{Source: n}
			}
			out = append(out, s)
		}
		return out, nil
	}
	e := opsEnv(t, q, src, nil)
	e.srv.cfg.Sources = []string{"exploitdb", "nvd", "cwe"}
	code, body := getJSON(t, e, "/v1/stats")
	if code != 200 {
		t.Fatalf("%d %v", code, body)
	}
	cov, _ := body["coverage"].([]any)
	if len(cov) != 3 {
		t.Fatalf("coverage %v", body["coverage"])
	}
	m := func(i int) map[string]any { return cov[i].(map[string]any) }
	if m(0)["source"] != "exploitdb" || m(0)["upstream"] != nil || m(0)["inGraph"] != nil {
		t.Fatalf("exploitdb %v", m(0))
	}
	up, _ := m(1)["upstream"].(map[string]any)
	ig, _ := m(1)["inGraph"].(map[string]any)
	if m(1)["source"] != "nvd" || up["cves"] != float64(12) || up["cvesNotRejected"] != float64(11) ||
		m(1)["upstreamAt"] != "2025-02-03T04:05:06Z" || ig["cves"] != float64(10) || ig["cvesNotRejected"] != float64(9) {
		t.Fatalf("nvd %v", m(1))
	}
	ig, _ = m(2)["inGraph"].(map[string]any)
	if m(2)["source"] != "cwe" || m(2)["upstream"] != nil || m(2)["upstreamAt"] != nil || ig["weaknesses"] != float64(4) {
		t.Fatalf("cwe %v", m(2))
	}
}
