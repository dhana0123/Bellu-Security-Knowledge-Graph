package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/fetch"
)

type fakeRec struct {
	id       string
	modified time.Time
	raw      string // overrides the generated JSON when set
	name     string // overrides the zip entry name when set
}

func (r fakeRec) body() string {
	if r.raw != "" {
		return r.raw
	}
	return fmt.Sprintf(`{"id":%q,"modified":%q,"summary":"synthetic"}`, r.id, r.modified.UTC().Format(time.RFC3339))
}

type fakeBucket struct {
	mu      sync.Mutex
	eco     map[string][]fakeRec
	order   []string
	status  map[string]int // decoded path -> forced status
	hits    []string       // raw request URIs
	paths   []string       // decoded paths
	listing string         // override ecosystems.txt
}

func newBucket() *fakeBucket {
	return &fakeBucket{eco: map[string][]fakeRec{}, status: map[string]int{}}
}

func (b *fakeBucket) add(eco string, recs ...fakeRec) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.eco[eco]; !ok {
		b.order = append(b.order, eco)
	}
	b.eco[eco] = append(b.eco[eco], recs...)
}

func (b *fakeBucket) count(suffix string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, p := range b.paths {
		if strings.HasSuffix(p, suffix) {
			n++
		}
	}
	return n
}

func (b *fakeBucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.hits = append(b.hits, r.RequestURI)
	b.paths = append(b.paths, r.URL.Path)
	p := strings.TrimPrefix(r.URL.Path, "/")
	if st, ok := b.status[r.URL.Path]; ok {
		http.Error(w, "forced", st)
		return
	}
	if p == "ecosystems.txt" {
		if b.listing != "" {
			fmt.Fprint(w, b.listing)
			return
		}
		for _, e := range b.order {
			fmt.Fprintln(w, e)
		}
		return
	}
	eco, file, ok := strings.Cut(p, "/")
	recs, found := b.eco[eco]
	if !ok || !found {
		http.NotFound(w, r)
		return
	}
	switch {
	case file == "all.zip":
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for _, rc := range recs {
			name := rc.name
			if name == "" {
				name = rc.id + ".json"
			}
			f, _ := zw.Create(name)
			f.Write([]byte(rc.body()))
		}
		zw.Close()
		w.Header().Set("X-Goog-Generation", fmt.Sprint(len(recs)))
		w.Write(buf.Bytes())
	case file == "modified_id.csv":
		s := append([]fakeRec(nil), recs...)
		sort.SliceStable(s, func(i, j int) bool { return s[i].modified.After(s[j].modified) })
		for _, rc := range s {
			fmt.Fprintf(w, "%s,%s\n", rc.modified.UTC().Format(time.RFC3339), rc.id)
		}
	case strings.HasSuffix(file, ".json"):
		id := strings.TrimSuffix(file, ".json")
		for _, rc := range recs {
			if rc.id == id {
				fmt.Fprint(w, rc.body())
				return
			}
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

func day(n int) time.Time { return time.Date(2024, 1, n, 0, 0, 0, 0, time.UTC) }

func newTestSource(t *testing.T, b *fakeBucket, ecos ...string) (*LiveSource, *MemoryCheckpoints) {
	t.Helper()
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	s := NewLive(srv.URL + "/")
	s.HTTP.Retry = fetch.RetryPolicy{InitialDelay: time.Millisecond, MaxAttempts: 2}
	s.HTTP.SetSleeper(func(context.Context, time.Duration) error { return nil })
	if err := s.HTTP.SetInterval(time.Millisecond); err != nil {
		t.Fatal(err)
	}
	s.Ecosystems = ecos
	s.TempDir = t.TempDir()
	cp := NewMemoryCheckpoints()
	s.Checkpoints = cp
	s.CheckpointEvery = 1
	return s, cp
}

type outcome struct {
	items map[string][]byte
	ids   []string
	errs  []error
}

// run drains Fetch; stopAfter > 0 stops consuming after that many successful items.
func run(t *testing.T, s *LiveSource, mode connectors.Mode, stopAfter int) outcome {
	t.Helper()
	o := outcome{items: map[string][]byte{}}
	n := 0
	for it, err := range s.Fetch(context.Background(), mode, time.Time{}) {
		if err != nil {
			o.errs = append(o.errs, err)
			continue
		}
		o.items[it.ID] = it.Payload
		o.ids = append(o.ids, it.ID)
		n++
		if stopAfter > 0 && n >= stopAfter {
			break
		}
	}
	return o
}

func cursorOf(t *testing.T, cp Checkpointer, eco string) Cursor {
	t.Helper()
	c, err := loadCursor(context.Background(), cp, eco)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLiveFullRun(t *testing.T) {
	b := newBucket()
	b.add("PyPI", fakeRec{id: "PYSEC-1", modified: day(1)}, fakeRec{id: "PYSEC-2", modified: day(3)}, fakeRec{id: "pysec-3", modified: day(2)})
	b.add("npm", fakeRec{id: "GHSA-AAAA", modified: day(5)}, fakeRec{id: "GHSA-BBBB", modified: day(4)})
	s, cp := newTestSource(t, b)
	o := run(t, s, connectors.Full, 0)
	if len(o.errs) != 0 || len(o.items) != 5 {
		t.Fatalf("items=%d errs=%v", len(o.items), o.errs)
	}
	if _, ok := o.items["PYSEC-3"]; !ok {
		t.Fatal("id not normalized")
	}
	if c := cursorOf(t, cp, "PyPI"); !c.Completed.Equal(day(3)) || c.Partial != nil {
		t.Fatalf("PyPI cursor %+v", c)
	}
	if c := cursorOf(t, cp, "npm"); !c.Completed.Equal(day(5)) {
		t.Fatalf("npm cursor %+v", c)
	}
	sum := s.Summary()
	if len(sum) != 2 || sum[0].Records != 3 || sum[0].Method != "zip" || sum[1].Records != 2 {
		t.Fatalf("summary %+v", sum)
	}
}

func TestLiveInterruptedThenResume(t *testing.T) {
	b := newBucket()
	var recs []fakeRec
	for i := 1; i <= 6; i++ {
		recs = append(recs, fakeRec{id: fmt.Sprintf("OSV-%d", i), modified: day(i)})
	}
	b.add("Go", recs...)
	s, cp := newTestSource(t, b)
	first := run(t, s, connectors.Full, 2)
	if len(first.ids) != 2 {
		t.Fatalf("first run got %v", first.ids)
	}
	c := cursorOf(t, cp, "Go")
	if c.Partial == nil || c.Partial.Done != 1 && c.Partial.Done != 2 {
		t.Fatalf("expected partial progress, got %+v", c)
	}
	second := run(t, s, connectors.Full, 0)
	if !s.Summary()[0].Resumed {
		t.Fatal("second run did not resume")
	}
	if len(second.errs) != 0 {
		t.Fatal(second.errs)
	}
	seen := map[string]bool{}
	for _, id := range append(first.ids, second.ids...) {
		seen[id] = true
	}
	if len(seen) != 6 {
		t.Fatalf("union has %d ids", len(seen))
	}
	if len(second.ids) > 5 {
		t.Fatalf("second run redid too much: %v", second.ids)
	}
	if c := cursorOf(t, cp, "Go"); c.Partial != nil || !c.Completed.Equal(day(6)) {
		t.Fatalf("final cursor %+v", c)
	}
}

func TestLiveResumeRestartsWhenArchiveChanged(t *testing.T) {
	b := newBucket()
	b.add("Go", fakeRec{id: "A-1", modified: day(1)}, fakeRec{id: "A-2", modified: day(2)}, fakeRec{id: "A-3", modified: day(3)})
	s, _ := newTestSource(t, b)
	run(t, s, connectors.Full, 2)
	b.add("Go", fakeRec{id: "A-4", modified: day(4)}) // new generation
	o := run(t, s, connectors.Full, 0)
	if s.Summary()[0].Resumed || len(o.ids) != 4 {
		t.Fatalf("resumed=%v ids=%v", s.Summary()[0].Resumed, o.ids)
	}
}

func TestLiveRerunNoChangesIsIdempotent(t *testing.T) {
	b := newBucket()
	b.add("PyPI", fakeRec{id: "PYSEC-1", modified: day(1)}, fakeRec{id: "PYSEC-2", modified: day(2)})
	s, cp := newTestSource(t, b)
	first := run(t, s, connectors.Incremental, 0) // no checkpoint: falls back to all.zip
	if len(first.items) != 2 || b.count("all.zip") != 1 {
		t.Fatalf("first: %d items, %d zips", len(first.items), b.count("all.zip"))
	}
	before := cursorOf(t, cp, "PyPI")
	second := run(t, s, connectors.Incremental, 0)
	if len(second.items) != 0 || len(second.errs) != 0 {
		t.Fatalf("second run produced %v %v", second.ids, second.errs)
	}
	if b.count("all.zip") != 1 || b.count("PYSEC-1.json") != 0 || b.count("modified_id.csv") != 1 {
		t.Fatalf("unexpected requests: %v", b.paths)
	}
	if after := cursorOf(t, cp, "PyPI"); !after.Completed.Equal(before.Completed) || after.Partial != nil {
		t.Fatalf("cursor changed %+v -> %+v", before, after)
	}
	// A repeated full run yields byte-identical payloads.
	third := run(t, s, connectors.Full, 0)
	for id, p := range first.items {
		if !bytes.Equal(p, third.items[id]) {
			t.Fatalf("payload for %s changed", id)
		}
	}
}

func TestLiveIncrementalUsesModifiedCSV(t *testing.T) {
	b := newBucket()
	b.add("PyPI", fakeRec{id: "PYSEC-1", modified: day(1)}, fakeRec{id: "PYSEC-2", modified: day(2)}, fakeRec{id: "PYSEC-3", modified: day(3)})
	s, cp := newTestSource(t, b)
	run(t, s, connectors.Full, 0)
	b.mu.Lock()
	b.eco["PyPI"][0].modified = day(10) // PYSEC-1 updated
	b.mu.Unlock()
	b.add("PyPI", fakeRec{id: "PYSEC-4", modified: day(8)})
	zips := b.count("all.zip")
	o := run(t, s, connectors.Incremental, 0)
	if len(o.errs) != 0 || strings.Join(o.ids, ",") != "PYSEC-4,PYSEC-1" {
		t.Fatalf("ids=%v errs=%v (want oldest first)", o.ids, o.errs)
	}
	if b.count("all.zip") != zips {
		t.Fatal("incremental run downloaded all.zip")
	}
	if b.count("PYSEC-2.json") != 0 || b.count("PYSEC-4.json") != 1 || b.count("PYSEC-1.json") != 1 {
		t.Fatalf("requests %v", b.paths)
	}
	if c := cursorOf(t, cp, "PyPI"); !c.Completed.Equal(day(10)) {
		t.Fatalf("cursor %+v", c)
	}
	if s.Summary()[0].Method != "modified_id.csv" {
		t.Fatalf("method %q", s.Summary()[0].Method)
	}
}

func TestLiveIncrementalFetchFailureKeepsWatermark(t *testing.T) {
	b := newBucket()
	b.add("PyPI", fakeRec{id: "PYSEC-1", modified: day(1)})
	s, cp := newTestSource(t, b)
	run(t, s, connectors.Full, 0)
	b.add("PyPI", fakeRec{id: "PYSEC-2", modified: day(2)}, fakeRec{id: "PYSEC-3", modified: day(3)}, fakeRec{id: "PYSEC-4", modified: day(4)})
	b.status["/PyPI/PYSEC-3.json"] = 404
	o := run(t, s, connectors.Incremental, 0)
	if len(o.ids) != 2 || len(o.errs) != 1 {
		t.Fatalf("ids=%v errs=%v", o.ids, o.errs)
	}
	var re *RecordError
	if !errors.As(o.errs[0], &re) || re.Name != "PYSEC-3" {
		t.Fatalf("error %v", o.errs[0])
	}
	if c := cursorOf(t, cp, "PyPI"); !c.Completed.Equal(day(2)) {
		t.Fatalf("watermark advanced past failure: %+v", c)
	}
	delete(b.status, "/PyPI/PYSEC-3.json")
	o = run(t, s, connectors.Incremental, 0)
	if strings.Join(o.ids, ",") != "PYSEC-3,PYSEC-4" || len(o.errs) != 0 {
		t.Fatalf("retry ids=%v errs=%v", o.ids, o.errs)
	}
}

func TestLiveMalformedEntriesReported(t *testing.T) {
	b := newBucket()
	b.add("PyPI",
		fakeRec{id: "PYSEC-1", modified: day(1)},
		fakeRec{id: "x", raw: `{not json`, name: "broken.json"},
		fakeRec{id: "y", raw: `{"modified":"2024-01-01T00:00:00Z"}`, name: "noid.json"},
		fakeRec{id: "z", raw: `hello`, name: "readme.txt"},
		fakeRec{id: "PYSEC-2", modified: day(2)},
	)
	s, cp := newTestSource(t, b)
	o := run(t, s, connectors.Full, 0)
	if len(o.ids) != 2 || len(o.errs) != 3 {
		t.Fatalf("ids=%v errs=%v", o.ids, o.errs)
	}
	names := map[string]bool{}
	for _, err := range o.errs {
		var re *RecordError
		if !errors.As(err, &re) || re.Ecosystem != "PyPI" || re.Err == nil {
			t.Fatalf("bad error %v", err)
		}
		names[re.Name] = true
	}
	for _, n := range []string{"broken.json", "noid.json", "readme.txt"} {
		if !names[n] {
			t.Fatalf("missing failure for %s: %v", n, names)
		}
	}
	if r := s.Summary()[0]; r.Records != 2 || r.Failures != 3 {
		t.Fatalf("summary %+v", r)
	}
	if c := cursorOf(t, cp, "PyPI"); !c.Completed.Equal(day(2)) {
		t.Fatalf("cursor %+v", c)
	}
}

func TestLiveFailedEcosystemReportedNotDropped(t *testing.T) {
	b := newBucket()
	b.add("PyPI", fakeRec{id: "PYSEC-1", modified: day(1)})
	b.add("npm", fakeRec{id: "GHSA-1", modified: day(1)})
	b.add("Maven", fakeRec{id: "GHSA-2", modified: day(1)})
	b.status["/npm/all.zip"] = 500
	s, _ := newTestSource(t, b)
	o := run(t, s, connectors.Full, 0)
	if len(o.ids) != 2 {
		t.Fatalf("ids=%v", o.ids)
	}
	failed := map[string]bool{}
	for _, err := range o.errs {
		var ee *EcosystemError
		if errors.As(err, &ee) {
			failed[ee.Ecosystem] = true
		}
	}
	if !failed["npm"] || len(failed) != 1 {
		t.Fatalf("errs=%v", o.errs)
	}
	for _, r := range s.Summary() {
		if (r.Name == "npm") != (r.Err != nil) {
			t.Fatalf("summary %+v", r)
		}
	}
}

func TestLiveAllowListAndNotListed(t *testing.T) {
	b := newBucket()
	b.add("PyPI", fakeRec{id: "PYSEC-1", modified: day(1)})
	b.add("npm", fakeRec{id: "GHSA-1", modified: day(1)})
	s, _ := newTestSource(t, b, "npm", "Nope")
	o := run(t, s, connectors.Full, 0)
	if len(o.ids) != 1 || o.ids[0] != "GHSA-1" || len(o.errs) != 1 {
		t.Fatalf("ids=%v errs=%v", o.ids, o.errs)
	}
	var ee *EcosystemError
	if !errors.As(o.errs[0], &ee) || ee.Ecosystem != "Nope" {
		t.Fatalf("err %v", o.errs[0])
	}
	if b.count("PyPI/all.zip") != 0 {
		t.Fatal("PyPI was fetched despite allow-list")
	}
}

func TestLiveEscapedEcosystemNames(t *testing.T) {
	b := newBucket()
	b.add("Debian:12", fakeRec{id: "DSA-1", modified: day(1)})
	b.add("Rocky Linux:8", fakeRec{id: "RLSA-1", modified: day(1)})
	s, _ := newTestSource(t, b)
	o := run(t, s, connectors.Full, 0)
	if len(o.errs) != 0 || len(o.ids) != 2 {
		t.Fatalf("ids=%v errs=%v", o.ids, o.errs)
	}
	b.add("Rocky Linux:8", fakeRec{id: "RLSA/2:x", modified: day(2)})
	o = run(t, s, connectors.Incremental, 0)
	if len(o.errs) != 0 || len(o.ids) != 1 {
		t.Fatalf("incremental ids=%v errs=%v", o.ids, o.errs)
	}
	var sawSpace, sawID bool
	for _, h := range b.hits {
		if strings.Contains(h, " ") {
			t.Fatalf("unescaped space in %q", h)
		}
		sawSpace = sawSpace || strings.HasPrefix(h, "/Rocky%20Linux") && strings.Contains(h, "modified_id.csv")
		sawID = sawID || strings.Contains(h, "RLSA%2F2")
	}
	if !sawSpace || !sawID {
		t.Fatalf("escaping not observed: %v", b.hits)
	}
}

func TestLiveEcosystemsTxtFailure(t *testing.T) {
	b := newBucket()
	b.status["/ecosystems.txt"] = 404
	s, _ := newTestSource(t, b)
	o := run(t, s, connectors.Full, 0)
	if len(o.errs) != 1 || len(o.ids) != 0 {
		t.Fatalf("errs=%v", o.errs)
	}
}

func TestFileCheckpointsPersistAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	b := newBucket()
	b.add("Debian:12", fakeRec{id: "DSA-1", modified: day(1)}, fakeRec{id: "DSA-2", modified: day(2)})
	s, _ := newTestSource(t, b)
	s.Checkpoints = NewFileCheckpoints(dir)
	run(t, s, connectors.Full, 0)
	s2, _ := newTestSource(t, b)
	s2.Checkpoints = NewFileCheckpoints(dir)
	b.add("Debian:12", fakeRec{id: "DSA-3", modified: day(3)})
	o := run(t, s2, connectors.Incremental, 0)
	if strings.Join(o.ids, ",") != "DSA-3" {
		t.Fatalf("ids=%v errs=%v", o.ids, o.errs)
	}
	raw, err := NewFileCheckpoints(dir).Load(context.Background(), "Debian:12")
	if err != nil || len(raw) == 0 {
		t.Fatalf("load: %v %q", err, raw)
	}
	if raw, err := NewFileCheckpoints(dir).Load(context.Background(), "none"); err != nil || raw != nil {
		t.Fatalf("missing key: %v %q", err, raw)
	}
}
