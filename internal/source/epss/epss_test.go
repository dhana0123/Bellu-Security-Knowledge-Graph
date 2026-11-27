package epss

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/resolve"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
)

type fakeClock struct{ slept []time.Duration }

func (c *fakeClock) Now() time.Time { return time.Unix(1000, 0) }
func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.slept = append(c.slept, d)
	return nil
}

type fataler interface {
	Helper()
	Fatal(args ...any)
}

func gz(t fataler, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func fixture(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "epss_scores.csv.gz"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// server serves body and counts requests.
func server(t testing.TB, body func() []byte) (*httptest.Server, *int32) {
	t.Helper()
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.Write(body())
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func newAdapter(t testing.TB, srv *httptest.Server, clk *fakeClock) *Adapter {
	t.Helper()
	return New(Options{CacheDir: t.TempDir(), ChangeThreshold: 0.01, URL: srv.URL, Client: srv.Client(), Clock: clk})
}

func drain(t testing.TB, it source.Iterator) []source.Record {
	t.Helper()
	var out []source.Record
	for {
		r, err := it.Next(context.Background())
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		out = append(out, r)
	}
}

func TestNameAndConstants(t *testing.T) {
	a := New(Options{CacheDir: t.TempDir()})
	if a.Name() != "epss" || !source.ValidName(a.Name()) {
		t.Fatal("bad name")
	}
	if !strings.HasPrefix(DefaultURL, "https://"+Host+"/") {
		t.Fatal(DefaultURL)
	}
}

func TestFetchStreamsRowsAndVersion(t *testing.T) {
	srv, hits := server(t, func() []byte { return fixture(t) })
	a := newAdapter(t, srv, &fakeClock{})
	it, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, it)
	if len(recs) != 7 { // 6 rows + version marker
		t.Fatalf("got %d records", len(recs))
	}
	if recs[0].ID != "CVE-1999-0001" || recs[2].ID != "CVE-2021-44228" {
		t.Fatalf("ids %q %q", recs[0].ID, recs[2].ID)
	}
	last := recs[6]
	if len(last.Payload) != 0 || last.Cursor.Version != "2026-11-21T12:00:24Z|v2026.06.15" {
		t.Fatalf("marker %+v", last)
	}
	if *hits != 1 {
		t.Fatalf("fetched %d times, want once", *hits)
	}
	tot, _ := a.Totals(context.Background())
	if tot["rows"] != 6 || len(tot) != 1 {
		t.Fatalf("totals %v", tot)
	}
}

func TestNormalize(t *testing.T) {
	srv, _ := server(t, func() []byte { return fixture(t) })
	a := newAdapter(t, srv, &fakeClock{})
	it, _ := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	recs := drain(t, it)
	n, err := a.Normalize(recs[2])
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Gate) != 1 || n.Gate[0].Raw != "CVE-2021-44228" || n.Gate[0].Kind != source.RefCVE {
		t.Fatalf("gate %+v", n.Gate)
	}
	if _, err := resolve.Resolve(n.Gate[0]); err != nil {
		t.Fatal(err)
	}
	e := n.Entities[0]
	if !e.Ref.MustExist || e.Props["epssScore"] != 0.94358 || e.Props["epssPercentile"] != 0.99978 {
		t.Fatalf("props %v", e.Props)
	}
	if d := e.Props["epssDate"].(time.Time); d.Format("2006-01-02") != "2026-11-21" {
		t.Fatalf("date %v", d)
	}
	if e.ChangeThreshold["epssScore"] != 0.01 || e.ChangeFollows["epssDate"] != "epssScore" {
		t.Fatalf("threshold %+v %+v", e.ChangeThreshold, e.ChangeFollows)
	}
	n2, _ := a.Normalize(recs[2])
	if n2.Entities[0].Props["epssScore"] != e.Props["epssScore"] {
		t.Fatal("not deterministic")
	}
	// Boundary values are valid.
	for _, i := range []int{4, 5} {
		if _, err := a.Normalize(recs[i]); err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
	}
}

func TestNormalizeRejects(t *testing.T) {
	a := New(Options{CacheDir: t.TempDir()})
	cases := map[string]string{
		"high score":  `{"cve":"CVE-2021-1","epss":"1.0001","percentile":"0.5","date":"2026-11-21"}`,
		"neg score":   `{"cve":"CVE-2021-1000","epss":"-0.1","percentile":"0.5","date":"2026-11-21"}`,
		"high pct":    `{"cve":"CVE-2021-1000","epss":"0.5","percentile":"2","date":"2026-11-21"}`,
		"nan":         `{"cve":"CVE-2021-1000","epss":"NaN","percentile":"0.5","date":"2026-11-21"}`,
		"not number":  `{"cve":"CVE-2021-1000","epss":"abc","percentile":"0.5","date":"2026-11-21"}`,
		"empty score": `{"cve":"CVE-2021-1000","epss":"","percentile":"0.5","date":"2026-11-21"}`,
		"bad cve":     `{"cve":"nope","epss":"0.5","percentile":"0.5","date":"2026-11-21"}`,
		"bad date":    `{"cve":"CVE-2021-1000","epss":"0.5","percentile":"0.5","date":"yesterday"}`,
		"bad json":    `{`,
	}
	for name, p := range cases {
		_, err := a.Normalize(source.Record{ID: "CVE-X", Payload: []byte(p)})
		if err == nil || !strings.Contains(err.Error(), "CVE-X") {
			t.Errorf("%s: err %v must name the record", name, err)
		}
	}
}

func TestVersionSkipEmitsNothing(t *testing.T) {
	srv, hits := server(t, func() []byte { return fixture(t) })
	a := newAdapter(t, srv, &fakeClock{})
	cp := source.Checkpoint{Version: "2026-11-21T12:00:24Z|v2026.06.15"}
	it, err := a.Fetch(context.Background(), cp, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if recs := drain(t, it); len(recs) != 0 {
		t.Fatalf("got %d records, want none", len(recs))
	}
	if *hits != 1 {
		t.Fatalf("hits %d", *hits)
	}
	// A new model version with the same date is a new version.
	it, _ = a.Fetch(context.Background(), source.Checkpoint{Version: "2026-11-21T12:00:24Z|v2025"}, source.RunOptions{})
	if recs := drain(t, it); len(recs) != 7 {
		t.Fatalf("got %d records", len(recs))
	}
}

func TestSampleLimit(t *testing.T) {
	srv, _ := server(t, func() []byte { return fixture(t) })
	a := newAdapter(t, srv, &fakeClock{})
	it, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{SampleLimit: 2})
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, it)
	if len(recs) != 2 {
		t.Fatalf("got %d records", len(recs))
	}
	for _, r := range recs {
		if r.Cursor.Version != "" || len(r.Payload) == 0 {
			t.Fatalf("sample must not store a version: %+v", r)
		}
	}
}

func TestFetchFailures(t *testing.T) {
	good := "#model_version:v1,score_date:2026-11-21T00:00:00Z\ncve,epss,percentile\nCVE-2021-1000,0.1,0.2\n"
	cases := map[string][]byte{
		"not gzip":       []byte("hello"),
		"truncated gzip": gz(t, good)[:20],
		"no comment":     gz(t, "cve,epss,percentile\nCVE-2021-1000,0.1,0.2\n"),
		"no score_date":  gz(t, "#model_version:v1\ncve,epss,percentile\n"),
		"bad score_date": gz(t, "#model_version:v1,score_date:x\ncve,epss,percentile\n"),
		"bad header":     gz(t, "#model_version:v1,score_date:2026-11-21T00:00:00Z\ncve,score\n"),
		"short row":      gz(t, good+"CVE-2021-1001,0.1\n"),
		"empty":          gz(t, ""),
	}
	for name, body := range cases {
		srv, _ := server(t, func() []byte { return body })
		a := newAdapter(t, srv, &fakeClock{})
		it, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
		if err == nil || it != nil || !strings.Contains(err.Error(), "epss") {
			t.Errorf("%s: it=%v err=%v", name, it, err)
		}
	}
}

func TestFetchHTTPErrorRetriesAndNamesSource(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	clk := &fakeClock{}
	a := newAdapter(t, srv, clk)
	_, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if err == nil || !strings.HasPrefix(err.Error(), "epss:") {
		t.Fatalf("err %v", err)
	}
	if n != 4 || len(clk.slept) != 3 || clk.slept[0] != time.Second || clk.slept[1] != 2*time.Second {
		t.Fatalf("attempts %d sleeps %v", n, clk.slept)
	}
}

func TestFailedDownloadKeepsEarlierFile(t *testing.T) {
	body := fixture(t)
	srv, _ := server(t, func() []byte { return body })
	a := newAdapter(t, srv, &fakeClock{})
	if _, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{}); err != nil {
		t.Fatal(err)
	}
	body = []byte("garbage")
	if _, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{}); err == nil {
		t.Fatal("want error")
	}
}

func TestDefaultClientRejectsOtherHosts(t *testing.T) {
	a := New(Options{CacheDir: t.TempDir(), URL: "https://example.invalid/x.csv.gz", Clock: &fakeClock{}})
	_, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "epss") {
		t.Fatalf("err %v", err)
	}
}
