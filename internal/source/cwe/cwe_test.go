package cwe

import (
	"archive/zip"
	"bytes"
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

	"github.com/bellu/bskg/internal/source"
)

func fixtureZip(t *testing.T, name string, mutate func(string) string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "cwe", name))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if mutate != nil {
		s = mutate(s)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("cwec_v5.0.xml")
	io.WriteString(w, s)
	zw.Close()
	return buf.Bytes()
}

type noSleep struct{ sleeps []time.Duration }

func (c *noSleep) Now() time.Time { return time.Unix(0, 0) }
func (c *noSleep) Sleep(_ context.Context, d time.Duration) error {
	c.sleeps = append(c.sleeps, d)
	return nil
}

func serve(t *testing.T, data []byte) *Adapter {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(data) }))
	t.Cleanup(srv.Close)
	return New(WithBaseURL(srv.URL), WithClock(&noSleep{}))
}

func collect(t *testing.T, a *Adapter, it source.Iterator) (nodes map[string]source.Normalized, rels map[string]source.Normalized, order []string) {
	nodes, rels = map[string]source.Normalized{}, map[string]source.Normalized{}
	for {
		rec, err := it.Next(context.Background())
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if rec.Cursor.Version != "5.0" {
			t.Fatalf("cursor version %q", rec.Cursor.Version)
		}
		n, err := a.Normalize(rec)
		if err != nil {
			t.Fatal(err)
		}
		order = append(order, rec.ID)
		if n.Anchor != nil {
			rels[n.Anchor.Raw] = n
		} else {
			nodes[n.Entities[0].Ref.Raw] = n
		}
	}
}

func TestFullCatalog(t *testing.T) {
	a := serve(t, fixtureZip(t, "catalog.xml", nil))
	it, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{SampleLimit: 5})
	if err != nil {
		t.Fatal(err)
	}
	nodes, rels, order := collect(t, a, it)
	if len(nodes) != 4 || len(rels) != 4 {
		t.Fatalf("nodes %d rels %d", len(nodes), len(rels))
	}
	// all node records precede all relationship records
	seenRel := false
	for _, id := range order {
		if strings.HasSuffix(id, "#rels") {
			seenRel = true
		} else if seenRel {
			t.Fatalf("node record %s after a relationship record", id)
		}
	}
	xss := nodes["CWE-79"].Entities[0].Props
	if xss["cweName"] != "Cross-site Scripting" || xss["weaknessAbstraction"] != "Base" || xss["status"] != "Stable" {
		t.Fatalf("props %v", xss)
	}
	if got := xss["extendedDescription"]; got != "Cross-site scripting happens when input is echoed.Second line." {
		t.Fatalf("extended %q", got)
	}
	if v := xss["cweView"].([]string); strings.Join(v, ",") != "1000,1003,1000" {
		t.Fatalf("cweView %v", v)
	}
	cat := nodes["CWE-310"].Entities[0].Props
	if cat["weaknessAbstraction"] != "Category" || cat["description"] != "Weaknesses in cryptography." {
		t.Fatalf("category %v", cat)
	}
	if _, ok := cat["extendedDescription"]; ok {
		t.Fatal("extendedDescription must be absent")
	}
	if _, ok := nodes["CWE-89"]; !ok {
		t.Fatal("leading zeros must be stripped")
	}
	r := rels["CWE-79"]
	if len(r.Rels) != 2 || r.Rels[0].Key["viewID"] != "1000" || r.Rels[1].Key["viewID"] != "1003" ||
		r.Rels[0].To.Raw != "CWE-74" || r.Rels[0].Type != "CHILD_OF" {
		t.Fatalf("rels %+v", r.Rels)
	}
	if len(r.Notes) != 1 || r.Notes[0].Kind != "unresolved" || r.Notes[0].ID != "CWE-9999" {
		t.Fatalf("notes %+v", r.Notes)
	}
	if r.Anchor == nil || len(r.Owned) != 1 || r.Owned[0].Type != "CHILD_OF" {
		t.Fatal("anchor and owned rels")
	}
}

func TestUnchangedVersionSkips(t *testing.T) {
	a := serve(t, fixtureZip(t, "catalog.xml", nil))
	it, err := a.Fetch(context.Background(), source.Checkpoint{Version: "5.0"}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := it.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
	it, err = a.Fetch(context.Background(), source.Checkpoint{Version: "4.9"}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := it.Next(context.Background()); err != nil {
		t.Fatalf("changed version must load: %v", err)
	}
}

func TestTruncation(t *testing.T) {
	long := strings.Repeat("é", MaxTextChars+1)
	a := serve(t, fixtureZip(t, "catalog.xml", func(s string) string {
		return strings.Replace(s, "SQL injection description.", long, 1)
	}))
	it, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	nodes, _, _ := collect(t, a, it)
	n := nodes["CWE-89"]
	if got := []rune(n.Entities[0].Props["description"].(string)); len(got) != MaxTextChars {
		t.Fatalf("len %d", len(got))
	}
	if len(n.Notes) != 1 || n.Notes[0].Kind != "warning" || n.Notes[0].ID != "CWE-89" || !strings.Contains(n.Notes[0].Text, "description") {
		t.Fatalf("notes %+v", n.Notes)
	}
}

func TestDoctypeRejected(t *testing.T) {
	a := serve(t, fixtureZip(t, "doctype.xml", nil))
	_, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "DOCTYPE") || !strings.Contains(err.Error(), "cwe") {
		t.Fatalf("err %v", err)
	}
}

func TestSizeLimit(t *testing.T) {
	data := fixtureZip(t, "catalog.xml", func(s string) string {
		return strings.Replace(s, "<Weaknesses>", "<Weaknesses><!--"+strings.Repeat("x", 4096)+"-->", 1)
	})
	if _, err := openCatalog(data, 200); !errors.Is(err, errTooLarge) {
		t.Fatalf("declared size: %v", err)
	}
	// a limit above the declared size is not reachable here, so check the reader itself
	lr := &limitedReader{r: strings.NewReader(strings.Repeat("a", 100)), n: 10}
	if _, err := io.ReadAll(lr); !errors.Is(err, errTooLarge) {
		t.Fatalf("reader: %v", err)
	}
	lr = &limitedReader{r: strings.NewReader(strings.Repeat("a", 10)), n: 10}
	if b, err := io.ReadAll(lr); err != nil || len(b) != 10 {
		t.Fatalf("exact size must pass: %v", err)
	}
}

func TestRetries(t *testing.T) {
	good := fixtureZip(t, "catalog.xml", nil)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			http.Error(w, "boom", http.StatusServiceUnavailable)
			return
		}
		w.Write(good)
	}))
	defer srv.Close()
	clk := &noSleep{}
	a := New(WithBaseURL(srv.URL), WithClock(clk))
	if _, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 || len(clk.sleeps) != 2 || clk.sleeps[0] != 2*time.Second || clk.sleeps[1] != 4*time.Second {
		t.Fatalf("calls %d sleeps %v", calls.Load(), clk.sleeps)
	}

	calls.Store(-100) // always failing
	_, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "cwe") {
		t.Fatalf("err %v", err)
	}
}

func TestNotFoundNotRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.NotFound(w, nil)
	}))
	defer srv.Close()
	a := New(WithBaseURL(srv.URL), WithClock(&noSleep{}))
	if _, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{}); err == nil || calls.Load() != 1 {
		t.Fatalf("err %v calls %d", err, calls.Load())
	}
}

func TestBadArchiveNamesSource(t *testing.T) {
	a := serve(t, []byte("not a zip"))
	if _, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{}); err == nil || !strings.Contains(err.Error(), "source cwe") {
		t.Fatalf("err %v", err)
	}
	bad := fixtureZip(t, "catalog.xml", func(s string) string { return strings.Replace(s, "</Weakness_Catalog>", "", 1) })
	a = serve(t, bad)
	_, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "catalog version 5.0") {
		t.Fatalf("truncated catalog must fail naming the version: %v", err)
	}
}

func TestTotalsFromParsedCatalog(t *testing.T) {
	a := serve(t, fixtureZip(t, "catalog.xml", nil))
	if m, err := a.Totals(context.Background()); err != nil || len(m) != 0 {
		t.Fatalf("before any fetch: %v %v", m, err)
	}
	for _, cp := range []source.Checkpoint{{}, {Version: "5.0"}} { // fresh, then unchanged
		a = serve(t, fixtureZip(t, "catalog.xml", nil))
		if _, err := a.Fetch(context.Background(), cp, source.RunOptions{}); err != nil {
			t.Fatal(err)
		}
		m, err := a.Totals(context.Background())
		if err != nil || len(m) != 2 || m["weaknesses"] != 3 || m["categories"] != 1 {
			t.Fatalf("checkpoint %+v: %v %v", cp, m, err)
		}
	}
}
