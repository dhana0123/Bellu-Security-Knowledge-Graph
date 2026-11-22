package capec

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bellu/bskg/internal/httpx"
	"github.com/bellu/bskg/internal/resolve"
	"github.com/bellu/bskg/internal/source"
)

type fakeClock struct{}

func (fakeClock) Now() time.Time                                   { return time.Now() }
func (fakeClock) Sleep(ctx context.Context, _ time.Duration) error { return ctx.Err() }

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func serve(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != 0 {
			http.Error(w, "x", status)
			return
		}
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newAdapter(t *testing.T, srv *httptest.Server) *Adapter {
	t.Helper()
	return New(Options{CacheDir: t.TempDir(), URL: srv.URL, Client: srv.Client(), Clock: fakeClock{}})
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

func TestName(t *testing.T) {
	if n := New(Options{}).Name(); n != "capec" || !source.ValidName(n) {
		t.Fatalf("name %q", n)
	}
}

func TestFetchAndNormalize(t *testing.T) {
	srv := serve(t, fixture(t, "capec.xml"), 0)
	a := newAdapter(t, srv)
	it, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{SampleLimit: 1})
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, it)
	if len(recs) != 2 || recs[0].ID != "CAPEC-1" || recs[1].ID != "CAPEC-10" {
		t.Fatalf("records %+v", recs)
	}
	for _, r := range recs {
		if r.Cursor.Version != "3.9" {
			t.Errorf("%s cursor version %q", r.ID, r.Cursor.Version)
		}
	}
	tot, _ := a.Totals(context.Background())
	if !reflect.DeepEqual(tot, map[string]int64{"attackPatterns": 2}) {
		t.Fatalf("totals %v", tot)
	}

	n, err := a.Normalize(recs[0])
	if err != nil {
		t.Fatal(err)
	}
	n2, _ := a.Normalize(recs[0])
	if !reflect.DeepEqual(n, n2) {
		t.Fatal("Normalize is not deterministic")
	}
	if len(n.Entities) != 1 {
		t.Fatalf("entities %+v", n.Entities)
	}
	e := n.Entities[0]
	if k, err := resolve.Resolve(e.Ref); err != nil || k.Label != "AttackPattern" || k.Value != "CAPEC-1" {
		t.Fatalf("entity key %+v err %v", k, err)
	}
	wantProps := map[string]any{
		"name":        "Accessing Functionality Not Properly Constrained by ACLs",
		"description": "In applications, access to functionality is mitigated by an authorization framework.",
		"abstraction": "Standard", "status": "Draft", "likelihood": "High", "severity": "Very High",
	}
	if !reflect.DeepEqual(e.Props, wantProps) || len(e.Clear) != 0 {
		t.Errorf("props %v clear %v", e.Props, e.Clear)
	}

	type edge struct{ typ, from, to string }
	var got []edge
	for _, r := range n.Rels {
		fk, err1 := resolve.Resolve(r.From)
		tk, err2 := resolve.Resolve(r.To)
		if err1 != nil || err2 != nil {
			t.Fatalf("rel %+v: %v %v", r, err1, err2)
		}
		got = append(got, edge{r.Type, fk.Label + ":" + fk.Value, tk.Label + ":" + tk.Value})
		switch r.Type {
		case "RELATED_ATTACK_PATTERN":
			if !r.From.MustExist || r.To.MustExist {
				t.Errorf("RELATED_ATTACK_PATTERN must require the Weakness only: %+v", r)
			}
		case "MAPS_TO_TECHNIQUE":
			if !r.To.MustExist || r.From.MustExist {
				t.Errorf("MAPS_TO_TECHNIQUE must require the Technique only: %+v", r)
			}
		}
	}
	want := []edge{
		{"RELATED_ATTACK_PATTERN", "Weakness:CWE-276", "AttackPattern:CAPEC-1"},
		{"RELATED_ATTACK_PATTERN", "Weakness:CWE-285", "AttackPattern:CAPEC-1"}, // CWE-0285 is a duplicate
		{"MAPS_TO_TECHNIQUE", "AttackPattern:CAPEC-1", "Technique:T1574.010"},
		{"MAPS_TO_TECHNIQUE", "AttackPattern:CAPEC-1", "Technique:T1110"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rels\n got %v\nwant %v", got, want)
	}
	// The malformed CWE_ID and the malformed ATTACK Entry_ID are reported; the
	// WASC mapping is ignored silently.
	if len(n.Notes) != 2 {
		t.Fatalf("notes %v", n.Notes)
	}
	for _, note := range n.Notes {
		if note.Kind != "warning" || note.ID != "CAPEC-1" {
			t.Errorf("note %+v", note)
		}
	}
	if !strings.Contains(n.Notes[0].Text, `"bogus"`) || !strings.Contains(n.Notes[1].Text, `"07"`) {
		t.Errorf("notes %v", n.Notes)
	}
	if n.Anchor == nil || *n.Anchor != e.Ref || !reflect.DeepEqual(n.Owned, []source.OwnedRel{{Type: "MAPS_TO_TECHNIQUE"}}) {
		t.Errorf("anchor %+v owned %v", n.Anchor, n.Owned)
	}

	// Second pattern: leading zeros, nested xhtml markup, absent fields.
	n, err = a.Normalize(recs[1])
	if err != nil {
		t.Fatal(err)
	}
	e = n.Entities[0]
	if e.Ref.Raw != "CAPEC-10" || e.Props["description"] != "An adversary overflows, a buffer.\nSecond paragraph." {
		t.Errorf("entity %+v", e)
	}
	if _, ok := e.Props["likelihood"]; ok || !reflect.DeepEqual(e.Clear, []string{"likelihood", "severity"}) {
		t.Errorf("absent fields: props %v clear %v", e.Props, e.Clear)
	}
	if len(n.Rels) != 0 {
		t.Errorf("rels %+v", n.Rels)
	}
}

func TestVersionSkip(t *testing.T) {
	srv := serve(t, fixture(t, "capec.xml"), 0)
	a := newAdapter(t, srv)
	it, err := a.Fetch(context.Background(), source.Checkpoint{Version: "3.9"}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(drain(t, it)); n != 0 {
		t.Fatalf("unchanged release emitted %d records", n)
	}
	if tot, _ := a.Totals(context.Background()); tot["attackPatterns"] != 2 {
		t.Errorf("totals after a skipped run: %v", tot)
	}
	it, err = a.Fetch(context.Background(), source.Checkpoint{Version: "3.8"}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(drain(t, it)); n != 2 {
		t.Fatalf("changed release emitted %d records, want 2", n)
	}
}

func TestDoctypeRejected(t *testing.T) {
	srv := serve(t, fixture(t, "doctype.xml"), 0)
	it, err := newAdapter(t, srv).Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if err == nil || it != nil || !strings.Contains(err.Error(), "DOCTYPE") || !strings.Contains(err.Error(), "source capec") {
		t.Fatalf("it=%v err=%v", it, err)
	}
}

func TestFailuresNameSourceAndRelease(t *testing.T) {
	good := fixture(t, "capec.xml")
	cases := []struct {
		name   string
		body   string
		status int
		want   []string
	}{
		{"truncated", good[:strings.Index(good, "<Attack_Pattern ID=\"0010\"")+60], 0, []string{"source capec", "release 3.9"}},
		{"duplicate id", strings.Replace(good, `ID="0010"`, `ID="1"`, 1), 0, []string{"source capec", "release 3.9", "CAPEC-1 appears twice"}},
		{"invalid id", strings.Replace(good, `ID="0010"`, `ID="x"`, 1), 0, []string{"source capec", "release 3.9", `invalid ID "x"`}},
		{"no version", strings.Replace(good, `Version="3.9"`, ``, 1), 0, []string{"source capec", "Version attribute"}},
		{"wrong root", `<Weakness_Catalog Version="4.0"/>`, 0, []string{"source capec", "unexpected root"}},
		{"not xml", `{"json": true}`, 0, []string{"source capec"}},
		{"HTTP 404", "", 404, []string{"source capec", "release not read", "last loaded 3.8", "404"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := serve(t, c.body, c.status)
			it, err := newAdapter(t, srv).Fetch(context.Background(), source.Checkpoint{Version: "3.8"}, source.RunOptions{})
			if err == nil || it != nil {
				t.Fatalf("want error, got it=%v err=%v", it, err)
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q lacks %q", err, w)
				}
			}
		})
	}
}

func TestHostNotAllowed(t *testing.T) {
	srv := serve(t, fixture(t, "capec.xml"), 0)
	a := New(Options{CacheDir: t.TempDir(), URL: srv.URL, Clock: fakeClock{}})
	_, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	var he *httpx.HostNotAllowedError
	if !errors.As(err, &he) || !strings.Contains(err.Error(), "source capec") {
		t.Fatalf("want HostNotAllowedError naming the source, got %v", err)
	}
}

func TestNormalizeErrorsAndLimits(t *testing.T) {
	a := New(Options{})
	mk := func(p pattern) source.Record {
		b, _ := json.Marshal(p)
		return source.Record{ID: "CAPEC-" + p.ID, Payload: b}
	}
	n, err := a.Normalize(mk(pattern{ID: "5", Name: strings.Repeat("n", 501), Description: strings.Repeat("d", 20001), Abstraction: "Meta", Status: "Stable"}))
	if err != nil {
		t.Fatal(err)
	}
	p := n.Entities[0].Props
	if len([]rune(p["name"].(string))) != MaxNameChars || len([]rune(p["description"].(string))) != MaxTextChars || len(n.Notes) != 2 {
		t.Error("text not cut")
	}
	if n.Missing {
		t.Error("record with abstraction and status is not Missing")
	}
	n, _ = a.Normalize(mk(pattern{ID: "6", Name: "x"}))
	if !n.Missing {
		t.Error("record without abstraction and status must be Missing")
	}
	for _, bad := range []pattern{{ID: "0", Name: "x"}, {ID: "7"}} {
		if _, err := a.Normalize(mk(bad)); err == nil || !strings.Contains(err.Error(), "CAPEC-"+bad.ID) {
			t.Errorf("%+v: error %v", bad, err)
		}
	}
	if _, err := a.Normalize(source.Record{ID: "CAPEC-1", Payload: []byte("{")}); err == nil {
		t.Error("want decode error")
	}
}
