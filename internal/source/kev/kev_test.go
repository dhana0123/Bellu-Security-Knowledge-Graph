package kev

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bskg/internal/httpx"
	"github.com/bellu/bskg/internal/resolve"
	"github.com/bellu/bskg/internal/source"
)

type fakeClock struct{ slept []time.Duration }

func (c *fakeClock) Now() time.Time { return time.Now() }
func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.slept = append(c.slept, d)
	return nil
}

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "kev.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func serve(t *testing.T, status int, body []byte) (*httptest.Server, *int) {
	t.Helper()
	n := new(int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*n++
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, n
}

func testClient() *http.Client { return httpx.NewAllowList("127.0.0.1").NewClient(10 * time.Second) }

func set(ids ...string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return m
}

func newAdapter(url, dir string, stored map[string]struct{}, clock httpx.Clock) *Adapter {
	return New(Options{URL: url, CacheDir: dir, Clock: clock, Client: testClient(),
		Stored: func(context.Context) (map[string]struct{}, error) { return stored, nil }})
}

func drain(t *testing.T, it source.Iterator) []source.Record {
	t.Helper()
	var out []source.Record
	for {
		r, err := it.Next(context.Background())
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
}

func TestNameValid(t *testing.T) {
	if n := New(Options{}).Name(); n != "kev" || !source.ValidName(n) {
		t.Fatalf("name %q", n)
	}
}

func TestFetchEmitsAllEntriesRemovalsAndVersion(t *testing.T) {
	body := fixture(t)
	srv, hits := serve(t, 200, body)
	dir := t.TempDir()
	a := newAdapter(srv.URL, dir, set("CVE-2020-29583", "CVE-2011-0001", "cve-2010-0002"), &fakeClock{})
	// An unchanged checkpoint must not suppress records (16.3 needs the set).
	it, err := a.Fetch(context.Background(), source.Checkpoint{Version: "x"}, source.RunOptions{SampleLimit: 1})
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, it)
	var ids []string
	for _, r := range recs {
		ids = append(ids, r.ID)
	}
	want := []string{"CVE-2020-29583", "CVE-2019-8394", "CVE-2026-59310", "CVE-2010-0002", "CVE-2011-0001", "catalog"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("records %v, want %v", ids, want)
	}
	sum := sha256.Sum256(body)
	last := recs[len(recs)-1]
	if len(last.Payload) != 0 || last.Cursor.Version != "2026.11.20+"+hex.EncodeToString(sum[:]) {
		t.Fatalf("cursor record %+v", last)
	}
	if *hits != 1 {
		t.Fatalf("%d requests, want 1", *hits)
	}
	tot, _ := a.Totals(context.Background())
	if tot["entries"] != 3 || len(tot) != 1 {
		t.Fatalf("totals %v", tot)
	}
	if _, err := os.Stat(filepath.Join(dir, CacheFile)); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeEntry(t *testing.T) {
	a := New(Options{})
	it, err := newAdapter(mustServe(t, fixture(t)), t.TempDir(), nil, &fakeClock{}).Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, it)
	n, err := a.Normalize(recs[2]) // CVE-2026-59310, ransomware Known
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Entities) != 1 || len(n.Rels) != 0 || n.Anchor != nil || n.Missing {
		t.Fatalf("%+v", n)
	}
	e := n.Entities[0]
	if e.Ref.Kind != source.RefCVE || e.Ref.Raw != "CVE-2026-59310" || e.Ref.MustExist {
		t.Fatalf("ref %+v", e.Ref)
	}
	if len(n.Gate) != 1 || n.Gate[0].Raw != "CVE-2026-59310" || !n.Gate[0].MustExist {
		t.Fatalf("gate %+v", n.Gate)
	}
	wantProps := map[string]any{
		"kev":                  true,
		"kevDateAdded":         time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC),
		"kevDueDate":           time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC),
		"kevRansomwareUse":     "Known",
		"kevVulnerabilityName": e.Props["kevVulnerabilityName"],
	}
	if len(e.Props) != 5 || fmt.Sprint(e.Props) != fmt.Sprint(wantProps) || e.Props["kevVulnerabilityName"] == "" {
		t.Fatalf("props %v", e.Props)
	}
	for k := range e.Props {
		if !strings.HasPrefix(k, "kev") {
			t.Fatalf("non-KEV property %s", k)
		}
	}
	if _, err := resolve.Resolve(n.Gate[0]); err != nil {
		t.Fatal(err)
	}
	again, _ := a.Normalize(recs[2])
	if fmt.Sprint(again) != fmt.Sprint(n) {
		t.Fatal("not deterministic")
	}
}

func mustServe(t *testing.T, b []byte) string { s, _ := serve(t, 200, b); return s.URL }

func rec(id, js string) source.Record { return source.Record{ID: id, Payload: []byte(js)} }

func TestNormalizeTable(t *testing.T) {
	a := New(Options{})
	good := `"cveID":"cve-2021-44228","dateAdded":"2021-12-10","dueDate":"2021-12-24","knownRansomwareCampaignUse":"Known","vulnerabilityName":"Log4j"`
	tests := []struct {
		name, js string
		err      string
		missing  bool
		props    int
	}{
		{"ok lowercase id", `{` + good + `}`, "", false, 5},
		{"bad payload", `{`, "record X: invalid payload", false, 0},
		{"bad cve", `{"cveID":"nope","dateAdded":"2021-12-10"}`, `invalid cveID "nope"`, false, 0},
		{"missing dateAdded", `{"cveID":"CVE-2021-0001","dueDate":"2021-12-24"}`, "dateAdded", false, 0},
		{"bad dateAdded", `{"cveID":"CVE-2021-0001","dateAdded":"10/12/2021"}`, "dateAdded", false, 0},
		{"missing optional fields", `{"cveID":"CVE-2021-0001","dateAdded":"2021-12-10"}`, "", true, 2},
		{"bad dueDate", `{"cveID":"CVE-2021-0001","dateAdded":"2021-12-10","dueDate":"x","knownRansomwareCampaignUse":"Unknown","vulnerabilityName":"n"}`, "", true, 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, err := a.Normalize(rec("X", tc.js))
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) || !strings.Contains(err.Error(), "X") {
					t.Fatalf("err %v, want %q naming the record", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if n.Missing != tc.missing || len(n.Entities[0].Props) != tc.props {
				t.Fatalf("missing=%v props=%v", n.Missing, n.Entities[0].Props)
			}
			if tc.missing && len(n.Notes) == 0 {
				t.Fatal("no warning note")
			}
			if n.Entities[0].Ref.Raw != "CVE-2021-0001" && n.Entities[0].Ref.Raw != "CVE-2021-44228" {
				t.Fatalf("ref %v", n.Entities[0].Ref)
			}
		})
	}
}

func TestNormalizeRemoval(t *testing.T) {
	n, err := New(Options{}).Normalize(rec("CVE-2011-0001", `{"cveID":"CVE-2011-0001","remove":true}`))
	if err != nil {
		t.Fatal(err)
	}
	e := n.Entities[0]
	if len(e.Props) != 1 || e.Props["kev"] != false || len(e.Clear) != 0 || n.Anchor != nil {
		t.Fatalf("%+v", n)
	}
	if len(n.Gate) != 1 || !n.Gate[0].MustExist {
		t.Fatalf("gate %+v", n.Gate)
	}
}

func TestRetryPolicy(t *testing.T) {
	var calls int
	body := fixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls <= 3 {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	clk := &fakeClock{}
	if _, err := newAdapter(srv.URL, t.TempDir(), nil, clk).Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(clk.slept) != fmt.Sprint([]time.Duration{time.Second, 2 * time.Second, 4 * time.Second}) {
		t.Fatalf("waits %v", clk.slept)
	}
}

func TestFailureLeavesNothing(t *testing.T) {
	good := fixture(t)
	cases := map[string]struct {
		status int
		body   []byte
	}{
		"http 500":       {500, []byte("boom")},
		"http 404":       {404, nil},
		"not json":       {200, []byte("<html>")},
		"truncated":      {200, good[:len(good)/2]},
		"not an object":  {200, []byte(`[1,2]`)},
		"no array":       {200, []byte(`{"catalogVersion":"1","count":0}`)},
		"empty catalog":  {200, []byte(`{"catalogVersion":"1","count":0,"vulnerabilities":[]}`)},
		"count mismatch": {200, []byte(strings.Replace(string(good), `"count": 3`, `"count": 4`, 1))},
		"no version":     {200, []byte(strings.Replace(string(good), `"catalogVersion"`, `"catalogVersionX"`, 1))},
		"wrong type":     {200, []byte(`{"catalogVersion":"1","count":1,"vulnerabilities":[{"cveID":5}]}`)},
		"trailing data":  {200, append(append([]byte{}, good...), []byte(`{}`)...)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			srv, _ := serve(t, c.status, c.body)
			dir := t.TempDir()
			prev := filepath.Join(dir, CacheFile)
			_ = os.WriteFile(prev, []byte("previous"), 0o644)
			readCalled := false
			a := New(Options{URL: srv.URL, CacheDir: dir, Clock: &fakeClock{}, Client: testClient(),
				Stored: func(context.Context) (map[string]struct{}, error) {
					readCalled = true
					return set("CVE-2011-0001"), nil
				}})
			it, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
			if err == nil || it != nil {
				t.Fatalf("want error and no iterator, got %v %v", it, err)
			}
			if !strings.HasPrefix(err.Error(), "kev:") {
				t.Fatalf("error does not name the source: %v", err)
			}
			if readCalled {
				t.Fatal("graph read although the parse failed")
			}
			if tot, _ := a.Totals(context.Background()); len(tot) != 0 {
				t.Fatalf("totals set after failure: %v", tot)
			}
		})
	}
}

func TestStoredReadFailureFailsRun(t *testing.T) {
	srv, _ := serve(t, 200, fixture(t))
	a := New(Options{URL: srv.URL, CacheDir: t.TempDir(), Clock: &fakeClock{}, Client: testClient(),
		Stored: func(context.Context) (map[string]struct{}, error) { return nil, errors.New("db down") }})
	it, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if err == nil || it != nil || !strings.Contains(err.Error(), "kev:") {
		t.Fatalf("%v %v", it, err)
	}
}

func TestHostAllowList(t *testing.T) {
	a := New(Options{URL: "http://evil.example/x.json", CacheDir: t.TempDir(), Clock: &fakeClock{}, Client: httpx.NewAllowList("www.cisa.gov").NewClient(time.Second)})
	if _, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{}); err == nil {
		t.Fatal("host outside the allow-list was fetched")
	}
}

func TestDuplicateEntryKeptOnce(t *testing.T) {
	js := `{"catalogVersion":"1","count":2,"vulnerabilities":[
	{"cveID":"CVE-2021-0001","dateAdded":"2021-01-01"},{"cveID":"cve-2021-0001","dateAdded":"2022-01-01"}]}`
	srv, _ := serve(t, 200, []byte(js))
	it, err := newAdapter(srv.URL, t.TempDir(), nil, &fakeClock{}).Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if recs := drain(t, it); len(recs) != 2 { // one entry + cursor
		t.Fatalf("%d records", len(recs))
	}
}

// Feature: bellu-security-knowledge-graph, Property 66: KEV and EPSS updates (Phase 2)
func TestProperty66KEVUpdates(t *testing.T) {
	a := New(Options{})
	idGen := rapid.Custom(func(t *rapid.T) string {
		return fmt.Sprintf("CVE-%d-%04d", rapid.IntRange(2000, 2026).Draw(t, "y"), rapid.IntRange(1, 30).Draw(t, "n"))
	})
	dateGen := rapid.Custom(func(t *rapid.T) string {
		return fmt.Sprintf("%04d-%02d-%02d", rapid.IntRange(2021, 2026).Draw(t, "yy"),
			rapid.IntRange(1, 12).Draw(t, "m"), rapid.IntRange(1, 28).Draw(t, "d"))
	})
	rapid.Check(t, func(t *rapid.T) {
		cat := rapid.SliceOfNDistinct(idGen, 0, 20, func(s string) string { return s }).Draw(t, "catalog")
		nodes := rapid.SliceOfNDistinct(idGen, 0, 25, func(s string) string { return s }).Draw(t, "nodes")
		// graph: node -> current kev flag
		graph := map[string]bool{}
		for _, n := range nodes {
			graph[n] = rapid.Bool().Draw(t, "kev")
		}
		before := map[string]bool{}
		stored := map[string]struct{}{}
		for n, f := range graph {
			before[n] = f
			if f {
				stored[n] = struct{}{}
			}
		}
		inCat := map[string]struct{}{}
		var recs []source.Record
		for _, id := range cat {
			inCat[id] = struct{}{}
			d := dateGen.Draw(t, "date")
			recs = append(recs, rec(id, fmt.Sprintf(`{"cveID":%q,"dateAdded":%q,"dueDate":%q,"knownRansomwareCampaignUse":"Unknown","vulnerabilityName":"n"}`, id, d, d)))
		}
		gone := removed(stored, inCat)
		if !sort.StringsAreSorted(gone) {
			t.Fatal("removals not sorted")
		}
		for _, id := range gone {
			recs = append(recs, rec(id, fmt.Sprintf(`{"cveID":%q,"remove":true}`, id)))
		}
		changes := 0
		for _, r := range recs {
			n, err := a.Normalize(r)
			if err != nil {
				t.Fatal(err)
			}
			// The Gate: apply only when the node exists; never create one.
			if _, ok := graph[n.Gate[0].Raw]; !ok {
				continue
			}
			v := n.Entities[0].Props["kev"].(bool)
			if graph[n.Gate[0].Raw] != v {
				changes++
				graph[n.Gate[0].Raw] = v
			}
		}
		if len(graph) != len(nodes) {
			t.Fatal("a node was created")
		}
		flips := 0
		for id, f := range graph {
			_, want := inCat[id]
			if f != want {
				t.Fatalf("%s kev=%v, in catalog=%v", id, f, want)
			}
			if f != before[id] {
				flips++
			}
		}
		if flips != changes {
			t.Fatalf("%d flag changes but %d change records", flips, changes)
		}
	})
}
