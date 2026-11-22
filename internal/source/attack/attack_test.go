package attack

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/bellu/bskg/internal/httpx"
	"github.com/bellu/bskg/internal/resolve"
	"github.com/bellu/bskg/internal/source"
)

type fakeClock struct{}

func (fakeClock) Now() time.Time                                   { return time.Now() }
func (fakeClock) Sleep(ctx context.Context, _ time.Duration) error { return ctx.Err() }

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// serve serves the three fixture bundles; override maps a domain to a
// replacement body, status 0 meaning the body is served with 200.
func serve(t *testing.T, override map[string]string, status map[string]int) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		for _, d := range Domains {
			if r.URL.Path != "/"+d+"/"+d+".json" {
				continue
			}
			if st := status[d]; st != 0 {
				http.Error(w, "x", st)
				return
			}
			if body, ok := override[d]; ok {
				io.WriteString(w, body)
				return
			}
			w.Write(fixture(t, d+".json"))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func newAdapter(srv *httptest.Server, dir string) *Adapter {
	return New(Options{CacheDir: dir, BaseURL: srv.URL, Client: srv.Client(), Clock: fakeClock{}})
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
	if !source.ValidName(New(Options{}).Name()) || New(Options{}).Name() != "attack" {
		t.Fatal("invalid name")
	}
}

func TestFetchAndNormalize(t *testing.T) {
	srv, _ := serve(t, nil, nil)
	a := newAdapter(srv, t.TempDir())
	it, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{SampleLimit: 1})
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, it)
	var ids []string
	for _, r := range recs {
		ids = append(ids, r.ID)
		if r.Cursor.Version != "17.3" {
			t.Errorf("%s cursor version %q", r.ID, r.Cursor.Version)
		}
	}
	want := []string{"T0803", "T1066", "T1574", "T1574.010", "T1603"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("ids %v, want %v", ids, want)
	}
	tot, _ := a.Totals(context.Background())
	if !reflect.DeepEqual(tot, map[string]int64{"techniques": 5}) {
		t.Fatalf("totals %v", tot)
	}

	byID := map[string]source.Normalized{}
	for _, r := range recs {
		n, err := a.Normalize(r)
		if err != nil {
			t.Fatal(err)
		}
		n2, _ := a.Normalize(r)
		if !reflect.DeepEqual(n, n2) {
			t.Fatalf("%s: Normalize is not deterministic", r.ID)
		}
		if len(n.Entities) != 1 || len(n.Rels) != 0 || n.Anchor != nil {
			t.Fatalf("%s: unexpected shape %+v", r.ID, n)
		}
		e := n.Entities[0]
		if e.Ref.Kind != source.RefTechnique || e.Ref.MustExist {
			t.Fatalf("%s: ref %+v", r.ID, e.Ref)
		}
		k, err := resolve.Resolve(e.Ref)
		if err != nil || k.Label != "Technique" || k.Prop != "attackID" || k.Value != r.ID {
			t.Fatalf("%s: key %+v err %v", r.ID, k, err)
		}
		byID[r.ID] = n
	}

	tech := byID["T1574"].Entities[0].Props
	if tech["name"] != "Hijack Execution Flow" || tech["revoked"] != false || tech["deprecated"] != false {
		t.Errorf("T1574 props %v", tech)
	}
	if !reflect.DeepEqual(tech["tactics"], []string{"persistence", "privilege-escalation", "defense-evasion"}) {
		t.Errorf("tactics %v", tech["tactics"])
	}
	if !reflect.DeepEqual(tech["domains"], []string{"enterprise-attack"}) || tech["url"] != "https://attack.mitre.org/techniques/T1574" {
		t.Errorf("domains/url %v", tech)
	}
	if byID["T1574.010"].Entities[0].Props["name"] != "Services File Permissions Weakness" {
		t.Errorf("sub-technique %v", byID["T1574.010"].Entities[0].Props)
	}
	rev := byID["T1066"].Entities[0]
	if rev.Props["revoked"] != true {
		t.Errorf("revoked flag %v", rev.Props)
	}
	if _, ok := rev.Props["description"]; ok || !reflect.DeepEqual(rev.Clear, []string{"description"}) {
		t.Errorf("revoked without description: props %v clear %v", rev.Props, rev.Clear)
	}
	ics := byID["T0803"].Entities[0].Props // mitre-ics-attack source name, no x_mitre_domains
	if ics["revoked"] != true || ics["deprecated"] != true || !reflect.DeepEqual(ics["domains"], []string{"ics-attack"}) {
		t.Errorf("ICS props %v", ics)
	}
}

func TestVersionSkip(t *testing.T) {
	srv, _ := serve(t, nil, nil)
	a := newAdapter(srv, t.TempDir())
	it, err := a.Fetch(context.Background(), source.Checkpoint{Version: "17.3"}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(drain(t, it)); n != 0 {
		t.Fatalf("unchanged release emitted %d records", n)
	}
	it, err = a.Fetch(context.Background(), source.Checkpoint{Version: "17.2"}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(drain(t, it)); n != 5 {
		t.Fatalf("changed release emitted %d records, want 5", n)
	}
}

func TestMixedVersions(t *testing.T) {
	m := strings.Replace(string(fixture(t, "mobile-attack.json")), `"x_mitre_version": "17.3"`, `"x_mitre_version": "17.2"`, 1)
	srv, _ := serve(t, map[string]string{"mobile-attack": m}, nil)
	it, err := newAdapter(srv, t.TempDir()).Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	recs := drain(t, it)
	want := "enterprise-attack=17.3;mobile-attack=17.2;ics-attack=17.3"
	if recs[0].Cursor.Version != want {
		t.Fatalf("version %q, want %q", recs[0].Cursor.Version, want)
	}
}

func TestFailuresNameSourceAndRelease(t *testing.T) {
	cases := []struct {
		name     string
		override map[string]string
		status   map[string]int
		want     []string
	}{
		{"truncated bundle", map[string]string{"ics-attack": `{"type":"bundle","objects":[{"type":"x-mitre-collection","x_mitre_version":"17.3"},{"type":"attack-pat`}, nil,
			[]string{"source attack", "release 17.3"}},
		{"no collection", map[string]string{"mobile-attack": `{"type":"bundle","objects":[]}`}, nil,
			[]string{"source attack", "release", "x-mitre-collection"}},
		{"technique without id", map[string]string{"mobile-attack": `{"type":"bundle","objects":[{"type":"x-mitre-collection","x_mitre_version":"17.3"},{"type":"attack-pattern","id":"attack-pattern--x","name":"N","external_references":[]}]}`}, nil,
			[]string{"source attack", "release 17.3", "no ATT&CK external_id"}},
		{"invalid id", map[string]string{"mobile-attack": `{"type":"bundle","objects":[{"type":"x-mitre-collection","x_mitre_version":"17.3"},{"type":"attack-pattern","id":"attack-pattern--x","name":"N","external_references":[{"source_name":"mitre-attack","external_id":"1234"}]}]}`}, nil,
			[]string{"source attack", "release 17.3", `"1234"`}},
		{"not a bundle", map[string]string{"enterprise-attack": `{"type":"other","objects":[]}`}, nil,
			[]string{"source attack", "not a STIX bundle"}},
		{"HTTP 404", nil, map[string]int{"mobile-attack": 404}, []string{"source attack", "release", "last loaded 17.2", "mobile-attack"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := serve(t, c.override, c.status)
			it, err := newAdapter(srv, t.TempDir()).Fetch(context.Background(), source.Checkpoint{Version: "17.2"}, source.RunOptions{})
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

func TestServerErrorIsRetried(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			http.Error(w, "busy", 503)
			return
		}
		d := strings.Split(strings.Trim(r.URL.Path, "/"), "/")[0]
		w.Write(fixture(t, d+".json"))
	}))
	defer srv.Close()
	it, err := newAdapter(srv, t.TempDir()).Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(drain(t, it)) != 5 {
		t.Fatal("want 5 records")
	}
}

func TestHostNotAllowed(t *testing.T) {
	srv, _ := serve(t, nil, nil)
	a := New(Options{CacheDir: t.TempDir(), BaseURL: srv.URL, Clock: fakeClock{}}) // default allow-listed client
	_, err := a.Fetch(context.Background(), source.Checkpoint{}, source.RunOptions{})
	var he *httpx.HostNotAllowedError
	if !errors.As(err, &he) {
		t.Fatalf("want HostNotAllowedError, got %v", err)
	}
	if !strings.Contains(err.Error(), "source attack") {
		t.Errorf("error %q does not name the source", err)
	}
}

func TestNormalizeLimitsAndErrors(t *testing.T) {
	a := New(Options{})
	long := technique{ID: "T1000", Name: strings.Repeat("n", 600), Description: strings.Repeat("d", 20001)}
	n, err := a.Normalize(rec(t, long))
	if err != nil {
		t.Fatal(err)
	}
	p := n.Entities[0].Props
	if len([]rune(p["name"].(string))) != MaxNameChars || len([]rune(p["description"].(string))) != MaxTextChars {
		t.Error("text not cut")
	}
	if len(n.Notes) != 2 || n.Notes[0].Kind != "warning" {
		t.Errorf("notes %v", n.Notes)
	}
	for _, bad := range []technique{{ID: "T12", Name: "x"}, {ID: "T1000"}} {
		if _, err := a.Normalize(rec(t, bad)); err == nil || !strings.Contains(err.Error(), bad.ID) {
			t.Errorf("%+v: error %v", bad, err)
		}
	}
	if _, err := a.Normalize(source.Record{ID: "T1", Payload: []byte("{")}); err == nil {
		t.Error("want decode error")
	}
}

func rec(t *testing.T, tc technique) source.Record {
	t.Helper()
	b, err := json.Marshal(tc)
	if err != nil {
		t.Fatal(err)
	}
	return source.Record{ID: tc.ID, Payload: b}
}
