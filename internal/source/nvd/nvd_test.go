package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/httpx"
	"github.com/bellu/bskg/internal/source"
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

type fakeNVD struct {
	t     *testing.T
	all   []json.RawMessage
	mu    sync.Mutex
	reqs  []*http.Request
	fail  func(n int) (status int, retryAfter string) // n is the 0-based request number
	count int
}

func newFake(t *testing.T) *fakeNVD {
	t.Helper()
	b, err := os.ReadFile("testdata/nvd/cves.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		V []json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return &fakeNVD{t: t, all: doc.V}
}

func (f *fakeNVD) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	n := f.count
	f.count++
	f.reqs = append(f.reqs, r)
	f.mu.Unlock()
	if f.fail != nil {
		if st, ra := f.fail(n); st != 0 {
			if ra != "" {
				w.Header().Set("Retry-After", ra)
			}
			w.WriteHeader(st)
			return
		}
	}
	q := r.URL.Query()
	start, _ := strconv.Atoi(q.Get("startIndex"))
	per, _ := strconv.Atoi(q.Get("resultsPerPage"))
	end := min(start+per, len(f.all))
	page := []json.RawMessage{}
	if start < len(f.all) {
		page = f.all[start:end]
	}
	out := map[string]any{"resultsPerPage": len(page), "startIndex": start, "totalResults": len(f.all), "vulnerabilities": page}
	_ = json.NewEncoder(w).Encode(out)
}

func (f *fakeNVD) queries() []string {
	var out []string
	for _, r := range f.reqs {
		out = append(out, r.URL.RawQuery)
	}
	return out
}

var t0 = time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)

func setup(t *testing.T, f *fakeNVD, o Options) (*Adapter, *fakeClock) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	clk := &fakeClock{now: t0}
	o.BaseURL = srv.URL
	o.Client = httpx.NewAllowList("127.0.0.1").NewClient(0)
	o.Clock = clk
	o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(o), clk
}

func drain(t *testing.T, it source.Iterator) ([]source.Record, error) {
	t.Helper()
	var out []source.Record
	for {
		r, err := it.Next(context.Background())
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, r)
	}
}

func ids(rs []source.Record) []string {
	var out []string
	for _, r := range rs {
		if len(r.Payload) > 0 {
			out = append(out, r.ID)
		}
	}
	return out
}

func TestSampleRule(t *testing.T) {
	f := newFake(t)
	a, _ := setup(t, f, Options{})
	it, err := a.Fetch(context.Background(), source.Checkpoint{Watermark: t0}, source.RunOptions{SampleLimit: 2})
	if err != nil {
		t.Fatal(err)
	}
	recs, err := drain(t, it)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(recs); !reflect.DeepEqual(got, []string{"CVE-2021-0001", "CVE-2021-0002"}) {
		t.Fatalf("ids = %v", got)
	}
	if want := []string{"resultsPerPage=2&startIndex=0"}; !reflect.DeepEqual(f.queries(), want) {
		t.Fatalf("queries = %v, want %v (no date filters, one page)", f.queries(), want)
	}
	for _, r := range recs {
		if r.Cursor != (source.Cursor{}) {
			t.Fatalf("sample record has a cursor: %+v", r.Cursor)
		}
	}
}

func TestSampleLargerThanTotalStopsAtTotal(t *testing.T) {
	f := newFake(t)
	a, _ := setup(t, f, Options{})
	it, _ := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{SampleLimit: 1000})
	recs, err := drain(t, it)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 5 || len(f.reqs) != 1 {
		t.Fatalf("records=%d requests=%d, want 5 and 1", len(recs), len(f.reqs))
	}
}

func TestSampleSpansPagesAscending(t *testing.T) {
	f := newFake(t)
	a, _ := setup(t, f, Options{})
	// min(2000, 3) = 3 per page; N=3 means exactly one page.
	it, _ := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{SampleLimit: 3})
	recs, _ := drain(t, it)
	if len(ids(recs)) != 3 || len(f.reqs) != 1 {
		t.Fatalf("records=%d requests=%d", len(recs), len(f.reqs))
	}
}

func TestFullCatchUpPagesAndCursors(t *testing.T) {
	f := newFake(t)
	a, _ := setup(t, f, Options{PageSize: 2, APIKey: "k-123", Version: "9.9"})
	it, _ := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	recs, err := drain(t, it)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids(recs)) != 5 {
		t.Fatalf("ids = %v", ids(recs))
	}
	if want := []string{"resultsPerPage=2&startIndex=0", "resultsPerPage=2&startIndex=2", "resultsPerPage=2&startIndex=4"}; !reflect.DeepEqual(f.queries(), want) {
		t.Fatalf("queries = %v", f.queries())
	}
	start := t0.Format(time.RFC3339Nano)
	for i, r := range recs[:5] {
		if want := fmt.Sprintf("full@%s:%d", start, i+1); r.Cursor.Resume != want {
			t.Fatalf("record %d resume = %q, want %q", i, r.Cursor.Resume, want)
		}
		if !r.Cursor.Watermark.IsZero() {
			t.Fatalf("record %d sets a watermark before completion", i)
		}
	}
	last := recs[len(recs)-1]
	if len(recs) != 6 || len(last.Payload) != 0 || !last.Cursor.Watermark.Equal(t0) || last.Cursor.Resume != "" {
		t.Fatalf("final marker = %+v (records %d)", last, len(recs))
	}
	h := f.reqs[0].Header
	if h.Get("apiKey") != "k-123" || h.Get("User-Agent") != "bskg/9.9" {
		t.Fatalf("headers = %v", h)
	}
}

func TestFullCatchUpResumes(t *testing.T) {
	f := newFake(t)
	a, _ := setup(t, f, Options{PageSize: 2})
	cp := source.Checkpoint{Resume: "full@" + t0.Add(-time.Hour).Format(time.RFC3339Nano) + ":3"}
	it, err := a.Fetch(context.Background(), cp, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	recs, err := drain(t, it)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(recs); !reflect.DeepEqual(got, []string{"CVE-2021-0004", "CVE-2021-0005"}) {
		t.Fatalf("ids = %v", got)
	}
	if !recs[len(recs)-1].Cursor.Watermark.Equal(t0.Add(-time.Hour)) {
		t.Fatalf("watermark must be the original start time: %+v", recs[len(recs)-1].Cursor)
	}
	if _, err := a.Fetch(context.Background(), source.Checkpoint{Resume: "full@junk"}, source.RunOptions{}); err == nil {
		t.Fatal("want an error for a bad cursor")
	}
}

func TestFullCatchUpResumeAtEnd(t *testing.T) {
	f := newFake(t)
	a, _ := setup(t, f, Options{})
	it, _ := a.Fetch(context.Background(), source.Checkpoint{Resume: "full@" + t0.Format(time.RFC3339Nano) + ":5"}, source.RunOptions{})
	recs, err := drain(t, it)
	if err != nil || len(recs) != 1 || !recs[0].Cursor.Watermark.Equal(t0) {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
}

func TestIncrementalWindows(t *testing.T) {
	f := newFake(t)
	a, _ := setup(t, f, Options{PageSize: 3})
	wm := t0.Add(-300 * 24 * time.Hour)
	it, _ := a.Fetch(context.Background(), source.Checkpoint{Watermark: wm}, source.RunOptions{})
	recs, err := drain(t, it)
	if err != nil {
		t.Fatal(err)
	}
	// 300 days = windows of 120, 120, and 60 days.
	var markers []time.Time
	for _, r := range recs {
		if len(r.Payload) == 0 {
			markers = append(markers, r.Cursor.Watermark)
			if r.Cursor.Resume != "" {
				t.Fatalf("marker resume = %q", r.Cursor.Resume)
			}
		}
	}
	w1 := wm.Add(120*24*time.Hour - time.Millisecond)
	w2 := wm.Add(240*24*time.Hour - time.Millisecond)
	if len(markers) != 3 || !markers[0].Equal(w1) || !markers[1].Equal(w2) || !markers[2].Equal(t0) {
		t.Fatalf("markers = %v", markers)
	}
	if len(ids(recs)) != 15 {
		t.Fatalf("records = %d, want 5 per window", len(ids(recs)))
	}
	var starts, ends []string
	for _, r := range f.reqs {
		q := r.URL.Query()
		if q.Get("startIndex") == "0" {
			starts = append(starts, q.Get("lastModStartDate"))
			ends = append(ends, q.Get("lastModEndDate"))
		}
	}
	if len(starts) != 3 || !strings.HasSuffix(starts[0], "+00:00") || len(starts[0]) != len("2023-08-05T12:00:00.000+00:00") {
		t.Fatalf("starts = %v", starts)
	}
	if ends[0] != w1.Format(dateLayout)+"+00:00" || starts[1] != w1.Add(time.Millisecond).Format(dateLayout)+"+00:00" || ends[2] != t0.Format(dateLayout)+"+00:00" {
		t.Fatalf("starts=%v ends=%v", starts, ends)
	}
	if got := recs[1].Cursor.Resume; got != "win:"+wm.Format(dateLayout)+"Z:2" {
		t.Fatalf("resume = %q", got)
	}
}

func TestIncrementalResumeInWindow(t *testing.T) {
	f := newFake(t)
	a, _ := setup(t, f, Options{})
	ws := t0.Add(-24 * time.Hour)
	cp := source.Checkpoint{Watermark: ws.Add(-time.Millisecond), Resume: "win:" + ws.Format(dateLayout) + "Z:4"}
	it, _ := a.Fetch(context.Background(), cp, source.RunOptions{})
	recs, err := drain(t, it)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(recs); !reflect.DeepEqual(got, []string{"CVE-2021-0005"}) {
		t.Fatalf("ids = %v", got)
	}
	q := f.reqs[0].URL.Query()
	if q.Get("startIndex") != "4" || q.Get("lastModStartDate") != ws.Format(dateLayout)+"+00:00" {
		t.Fatalf("query = %v", q)
	}
}

func TestRetryAfterAndBackoff(t *testing.T) {
	f := newFake(t)
	f.fail = func(n int) (int, string) {
		switch n {
		case 0:
			return 429, "7"
		case 1:
			return 503, ""
		}
		return 0, ""
	}
	a, clk := setup(t, f, Options{})
	it, _ := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{SampleLimit: 1})
	recs, err := drain(t, it)
	if err != nil || len(recs) != 1 {
		t.Fatalf("recs=%d err=%v", len(recs), err)
	}
	// Retry-After replaces the first delay; the second is the computed 4 s.
	if want := []time.Duration{7 * time.Second, 4 * time.Second}; !reflect.DeepEqual(clk.sleeps, want) {
		t.Fatalf("sleeps = %v, want %v", clk.sleeps, want)
	}
}

func TestRetryExhaustionNamesWindowAndStatus(t *testing.T) {
	f := newFake(t)
	f.fail = func(int) (int, string) { return 503, "" }
	a, clk := setup(t, f, Options{})
	it, _ := a.Fetch(context.Background(), source.Checkpoint{Watermark: t0.Add(-time.Hour)}, source.RunOptions{})
	_, err := it.Next(context.Background())
	if err == nil {
		t.Fatal("want error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "window 2024-06-01T11:00:00.000Z") || !strings.Contains(msg, "startIndex 0") || !strings.Contains(msg, "503") {
		t.Fatalf("error = %q", msg)
	}
	if len(f.reqs) != 6 {
		t.Fatalf("requests = %d, want 1 + 5 retries", len(f.reqs))
	}
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second}
	if !reflect.DeepEqual(clk.sleeps, want) {
		t.Fatalf("sleeps = %v", clk.sleeps)
	}
}

func TestClientErrorIsNotRetried(t *testing.T) {
	f := newFake(t)
	f.fail = func(int) (int, string) { return 404, "" }
	a, _ := setup(t, f, Options{})
	it, _ := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if _, err := it.Next(context.Background()); err == nil || len(f.reqs) != 1 {
		t.Fatalf("err=%v requests=%d", err, len(f.reqs))
	}
}

func TestRateLimitKeyless(t *testing.T) {
	f := newFake(t)
	a, clk := setup(t, f, Options{PageSize: 1})
	it, _ := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if _, err := drain(t, it); err != nil {
		t.Fatal(err)
	}
	// Five single-record pages fit in the first window of 5; none waits.
	if len(f.reqs) != 5 || len(clk.sleeps) != 0 {
		t.Fatalf("requests=%d sleeps=%v", len(f.reqs), clk.sleeps)
	}
	it, _ = a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if _, err := drain(t, it); err != nil {
		t.Fatal(err)
	}
	if len(clk.sleeps) == 0 {
		t.Fatal("the sixth request within 30 s must wait")
	}
}

func TestHostAllowList(t *testing.T) {
	a := New(Options{BaseURL: "http://example.invalid/x", Clock: &fakeClock{now: t0}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	it, _ := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	_, err := it.Next(context.Background())
	var he *httpx.HostNotAllowedError
	if !errors.As(err, &he) || he.Host != "example.invalid" {
		t.Fatalf("err = %v", err)
	}
}

func normalizeFixture(t *testing.T, i int) source.Normalized {
	t.Helper()
	f := newFake(t)
	var e struct {
		CVE json.RawMessage `json:"cve"`
	}
	if err := json.Unmarshal(f.all[i], &e); err != nil {
		t.Fatal(err)
	}
	n, err := New(Options{}).Normalize(source.Record{ID: "x", Payload: e.CVE})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func entityProps(n source.Normalized, kind source.RefKind) map[string]any {
	for _, e := range n.Entities {
		if e.Ref.Kind == kind {
			return e.Props
		}
	}
	return nil
}

func rels(n source.Normalized, typ string) []source.Rel {
	var out []source.Rel
	for _, r := range n.Rels {
		if r.Type == typ {
			out = append(out, r)
		}
	}
	return out
}

func TestNormalizeFullRecord(t *testing.T) {
	n := normalizeFixture(t, 0)
	p := entityProps(n, source.RefCVE)
	want := map[string]any{
		"publishedDate":    neo4j.DateOf(time.Date(2021, 3, 4, 0, 0, 0, 0, time.UTC)),
		"lastModifiedDate": neo4j.DateOf(time.Date(2021, 4, 5, 0, 0, 0, 0, time.UTC)),
		"description":      "Cross-site scripting in Widget.",
		"numOfReference":   int64(3),
		"v2version":        int64(2), "v2baseScore": 4.3, "v2impactScore": 2.9, "v2exploitabilityScore": 8.6,
		"v2accessVector": "NETWORK", "v2severity": "MEDIUM", "v2userInteractionRequired": true, "v2acInsufInfo": false,
		"v3version": 3.1, "v3baseScore": 6.1, "v3scope": "CHANGED", "v3baseSeverity": "MEDIUM", "v3impactScore": 2.7,
		"v3userInteraction": "REQUIRED",
	}
	for k, v := range want {
		if !reflect.DeepEqual(p[k], v) {
			t.Errorf("%s = %#v, want %#v", k, p[k], v)
		}
	}
	if _, ok := p["rejected"]; ok {
		t.Error("rejected set on a non-rejected record")
	}
	for _, banned := range []string{"gainedAccess", "vulnerabilityType", "productType"} {
		for _, e := range n.Entities {
			if _, ok := e.Props[banned]; ok {
				t.Errorf("%s must not be set (%v)", banned, e.Ref)
			}
		}
	}
	if !reflect.DeepEqual(n.Entities[0].Clear, []string{"rejected"}) {
		t.Errorf("clear = %v", n.Entities[0].Clear)
	}
	if n.Missing {
		t.Error("a complete record is not Missing")
	}
	if n.Anchor == nil || n.Anchor.Raw != "CVE-2021-0001" || len(n.Owned) != 3 {
		t.Errorf("anchor/owned = %v %v", n.Anchor, n.Owned)
	}
}

func TestNormalizeRelationships(t *testing.T) {
	n := normalizeFixture(t, 0)
	cwe := rels(n, "EXAMPLE_OF")
	if len(cwe) != 2 || cwe[0].To.Raw != "CWE-79" || cwe[1].To.Raw != "NVD-CWE-Other" || !cwe[0].To.MustExist || !cwe[1].To.MustExist {
		t.Errorf("EXAMPLE_OF = %+v", cwe)
	}
	for _, e := range n.Entities {
		if e.Ref.Kind == source.RefCWE {
			t.Error("a Weakness entity must never be emitted")
		}
	}
	dom := rels(n, "REFERS_TO")
	if len(dom) != 2 || dom[0].To.Raw != "example.com" || dom[1].To.Raw != "vendor.example.org" {
		t.Errorf("REFERS_TO = %+v", dom)
	}
	aff := rels(n, "AFFECTS")
	if len(aff) != 2 {
		t.Fatalf("AFFECTS = %+v", aff)
	}
	if v := aff[0].Props["affectedVersion"]; !reflect.DeepEqual(v, []string{"1.0", "[2.0,2.5)", "*"}) {
		t.Errorf("widget versions = %v", v)
	}
	if aff[0].Props["numOfVersion"] != int64(3) || aff[1].Props["numOfVersion"] != int64(1) {
		t.Errorf("numOfVersion = %v %v", aff[0].Props["numOfVersion"], aff[1].Props["numOfVersion"])
	}
	if v := aff[1].Props["affectedVersion"]; !reflect.DeepEqual(v, []string{"-"}) {
		t.Errorf("gadget versions = %v", v)
	}
	bel := rels(n, "BELONGS_TO")
	if len(bel) != 2 || bel[0].From.Kind != source.RefCPE || bel[0].To.Kind != source.RefCPEVend {
		t.Errorf("BELONGS_TO = %+v", bel)
	}
	// widgetos is not vulnerable, so it creates nothing.
	for _, e := range n.Entities {
		if strings.Contains(e.Ref.Raw, "widgetos") {
			t.Errorf("non-vulnerable CPE produced %v", e.Ref)
		}
	}
}

func TestNormalizeRejectedAndMissing(t *testing.T) {
	n := normalizeFixture(t, 1)
	p := entityProps(n, source.RefCVE)
	if p["rejected"] != true || n.Missing {
		t.Errorf("rejected=%v missing=%v", p["rejected"], n.Missing)
	}
	if len(n.Entities[0].Clear) != 0 {
		t.Errorf("clear = %v", n.Entities[0].Clear)
	}
	n = normalizeFixture(t, 2) // no metrics, no weaknesses
	if !n.Missing {
		t.Error("a record without scores must set Missing")
	}
	if _, ok := entityProps(n, source.RefCVE)["v3baseScore"]; ok {
		t.Error("absent score must stay unset")
	}
	if n = normalizeFixture(t, 3); n.Missing || entityProps(n, source.RefCVE)["v3version"] != 3.0 {
		t.Errorf("v3.0 fallback: missing=%v props=%v", n.Missing, entityProps(n, source.RefCVE))
	}
}

func TestNormalizeErrorsAndMarker(t *testing.T) {
	a := New(Options{})
	if _, err := a.Normalize(source.Record{ID: "x", Payload: []byte(`{"id":"OSVDB-1"}`)}); err == nil {
		t.Error("a non-CVE id must fail")
	}
	if _, err := a.Normalize(source.Record{ID: "x", Payload: []byte(`{`)}); err == nil {
		t.Error("invalid JSON must fail")
	}
	if n, err := a.Normalize(source.Record{}); err != nil || len(n.Entities) != 0 {
		t.Errorf("marker: %+v %v", n, err)
	}
}

func TestName(t *testing.T) {
	if !source.ValidName(New(Options{}).Name()) {
		t.Fatal("invalid adapter name")
	}
}
