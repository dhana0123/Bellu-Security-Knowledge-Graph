package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/resolve"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
)

func td(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type fakeClock struct {
	mu    sync.Mutex
	slept []time.Duration
}

func (c *fakeClock) Now() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }
func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	c.slept = append(c.slept, d)
	c.mu.Unlock()
	return nil
}

// bucket is a fake OSV export bucket.
type bucket struct {
	mu     sync.Mutex
	zips   map[string][]byte // ecosystem -> zip
	csv    map[string]string // ecosystem -> modified_id.csv
	fail   map[string]int    // ecosystem -> status for all.zip
	hits   map[string]int    // request path (unescaped) -> count
	hostUA string
}

func newBucket() *bucket {
	return &bucket{zips: map[string][]byte{}, csv: map[string]string{}, fail: map[string]int{}, hits: map[string]int{}}
}

func (b *bucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.hits[r.URL.Path]++
	b.hostUA = r.Header.Get("User-Agent")
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	eco, file := parts[0], parts[1]
	switch file {
	case "all.zip":
		if code := b.fail[eco]; code != 0 {
			http.Error(w, "boom", code)
			return
		}
		z, ok := b.zips[eco]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(z)
	case "modified_id.csv":
		c, ok := b.csv[eco]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, c)
	default:
		http.NotFound(w, r)
	}
}

func (b *bucket) count(path string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.hits[path]
}

func mkZip(t *testing.T, files ...[2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, err := zw.Create(f[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, f[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func rec(id, modified string) string {
	return fmt.Sprintf(`{"id":%q,"modified":%q,"summary":"s"}`, id, modified)
}

func newAdapter(t *testing.T, srv *httptest.Server, ecos ...string) (*Adapter, *fakeClock) {
	t.Helper()
	clk := &fakeClock{}
	return New(Options{
		Ecosystems: ecos, CacheDir: t.TempDir(), Version: "test",
		BaseURL: srv.URL, Client: srv.Client(), Clock: clk,
	}), clk
}

func drain(t *testing.T, a *Adapter, cp source.Checkpoint, opts source.RunOptions) []source.Record {
	t.Helper()
	it, err := a.Fetch(context.Background(), cp, opts)
	if err != nil {
		t.Fatal(err)
	}
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

func payloads(recs []source.Record) []string {
	var ids []string
	for _, r := range recs {
		if len(r.Payload) > 0 {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

func lastResume(recs []source.Record) string {
	if len(recs) == 0 {
		return ""
	}
	return recs[len(recs)-1].Cursor.Resume
}

func marksOf(t *testing.T, resume string) map[string]string {
	t.Helper()
	st, err := decodeState(resume)
	if err != nil {
		t.Fatal(err)
	}
	return st.Marks
}

func TestName(t *testing.T) {
	if !source.ValidName(Name) || New(Options{}).Name() != "osv" {
		t.Fatal("bad name")
	}
}

// resolveAll checks that every ref of n resolves (an advisory-keyed ref is
// resolved as the pipeline would after the alias rewrite).
func resolveAll(t *testing.T, n source.Normalized) {
	t.Helper()
	check := func(r source.Ref) {
		if _, err := resolve.Resolve(r); err != nil {
			t.Errorf("ref %v does not resolve: %v", r, err)
		}
	}
	for _, e := range n.Entities {
		check(e.Ref)
	}
	for _, r := range n.Rels {
		check(r.From)
		check(r.To)
	}
}

func relSet(n source.Normalized) map[string]bool {
	m := map[string]bool{}
	for _, r := range n.Rels {
		m[r.Type+"|"+r.From.Raw+"|"+r.To.Raw] = true
	}
	return m
}

func entity(n source.Normalized, kind source.RefKind, raw string) *source.Entity {
	for i := range n.Entities {
		if n.Entities[i].Ref.Kind == kind && n.Entities[i].Ref.Raw == raw {
			return &n.Entities[i]
		}
	}
	return nil
}

func TestNormalizeGHSAWithCVE(t *testing.T) {
	a := New(Options{})
	n, err := a.Normalize(source.Record{ID: "GHSA-c2f3-4gh5-wxmp", Payload: td(t, "GHSA-c2f3-4gh5-wxmp.json")})
	if err != nil {
		t.Fatal(err)
	}
	resolveAll(t, n)
	if n.Advisory == nil || n.Advisory.ID != "GHSA-c2f3-4gh5-wxmp" ||
		!reflect.DeepEqual(n.Advisory.CVEs, []string{"CVE-2021-1234"}) ||
		!reflect.DeepEqual(n.Advisory.OtherAliases, []string{"GHSA-ffff-gggg-hhhh"}) {
		t.Fatalf("advisory = %+v", n.Advisory)
	}
	v := entity(n, source.RefAdvisory, "GHSA-c2f3-4gh5-wxmp")
	if v == nil {
		t.Fatal("no vulnerability entity")
	}
	if v.Props["osvSeverity"] != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" ||
		v.Props["osvSummary"] != "Prototype pollution in @scope/Pkg" {
		t.Errorf("props = %v", v.Props)
	}
	if got := v.Props["osvModified"].(time.Time); !got.Equal(time.Date(2024, 3, 1, 10, 0, 0, 123456000, time.UTC)) {
		t.Errorf("osvModified = %v", got)
	}
	if _, ok := v.Props["osvPublished"].(time.Time); !ok {
		t.Error("osvPublished missing")
	}
	for k := range v.Props {
		if !strings.HasPrefix(k, "osv") {
			t.Errorf("property %q is not source-prefixed", k)
		}
	}
	if !reflect.DeepEqual(v.Clear, []string{"osvWithdrawn"}) {
		t.Errorf("clear = %v", v.Clear)
	}
	// Both affected entries name one package: one relationship.
	purl := "pkg:npm/%40scope/pkg"
	pkgRels := 0
	for _, r := range n.Rels {
		if r.Type == "AFFECTS_PACKAGE" {
			pkgRels++
			if r.To.Raw != purl || r.From.Kind != source.RefAdvisory {
				t.Errorf("rel = %+v", r)
			}
			want := map[string]any{
				"introduced": "0", "fixed": "1.2.3", "lastAffected": "2.4.0",
				"affectedRanges": []string{"introduced=0,fixed=1.2.3", "introduced=2.0.0,lastAffected=2.4.0"},
			}
			if !reflect.DeepEqual(r.Props, want) {
				t.Errorf("AFFECTS_PACKAGE props = %#v", r.Props)
			}
		}
	}
	if pkgRels != 1 {
		t.Errorf("AFFECTS_PACKAGE count = %d", pkgRels)
	}
	if p := entity(n, source.RefPackage, purl); p == nil || p.Props["ecosystem"] != "npm" || p.Props["name"] != "@scope/Pkg" {
		t.Errorf("package = %+v", p)
	}
	// Git from references: repository, one fix commit, the short sha warns.
	rs := relSet(n)
	repo := "https://github.com/scope/pkg"
	fc := repo + "@0123456789abcdef0123456789abcdef01234567"
	for _, w := range []string{
		"REFERS_TO_REPOSITORY|GHSA-c2f3-4gh5-wxmp|" + repo,
		"HAS_FIX_COMMIT|" + repo + "|" + fc,
		"FIXES|" + fc + "|GHSA-c2f3-4gh5-wxmp",
		"EXAMPLE_OF|GHSA-c2f3-4gh5-wxmp|CWE-79",
		"EXAMPLE_OF|GHSA-c2f3-4gh5-wxmp|CWE-1321",
	} {
		if !rs[w] {
			t.Errorf("missing relationship %s", w)
		}
	}
	for _, r := range n.Rels {
		if r.Type == "EXAMPLE_OF" && !r.To.MustExist {
			t.Errorf("weakness ref must be MustExist: %+v", r)
		}
	}
	warn := 0
	for _, no := range n.Notes {
		if strings.Contains(no.Text, "40-digit") || strings.Contains(no.Text, "NVD-CWE-Other") {
			warn++
		}
	}
	if warn != 2 {
		t.Errorf("notes = %+v", n.Notes)
	}
	if n.Anchor == nil || n.Anchor.Raw != "GHSA-c2f3-4gh5-wxmp" ||
		!reflect.DeepEqual(n.Owned, []source.OwnedRel{{Type: "AFFECTS_PACKAGE"}, {Type: "REFERS_TO_REPOSITORY"}}) {
		t.Errorf("anchor = %+v owned = %+v", n.Anchor, n.Owned)
	}
}

func TestNormalizePySecNoCVE(t *testing.T) {
	a := New(Options{})
	n, err := a.Normalize(source.Record{ID: "PYSEC-2021-1", Payload: td(t, "PYSEC-2021-1.json")})
	if err != nil {
		t.Fatal(err)
	}
	resolveAll(t, n)
	if n.Advisory == nil || len(n.Advisory.CVEs) != 0 || len(n.Advisory.OtherAliases) != 0 || n.Advisory.ID != "PYSEC-2021-1" {
		t.Fatalf("advisory = %+v", n.Advisory)
	}
	if !relSet(n)["AFFECTS_PACKAGE|PYSEC-2021-1|pkg:pypi/django-foo"] {
		t.Errorf("rels = %+v", n.Rels)
	}
	if entity(n, source.RefPackage, "pkg:pypi/django-foo").Props["name"] != "Django_Foo" {
		t.Error("package name not kept as OSV writes it")
	}
	// No severity: cleared, never an empty string.
	v := entity(n, source.RefAdvisory, "PYSEC-2021-1")
	if _, ok := v.Props["osvSeverity"]; ok || !contains(v.Clear, "osvSeverity") {
		t.Errorf("props %v clear %v", v.Props, v.Clear)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestNormalizeGoGitRange(t *testing.T) {
	a := New(Options{})
	n, err := a.Normalize(source.Record{ID: "GO-2021-0113", Payload: td(t, "GO-2021-0113.json")})
	if err != nil {
		t.Fatal(err)
	}
	resolveAll(t, n)
	if !reflect.DeepEqual(n.Advisory.CVEs, []string{"CVE-2021-38561"}) || !reflect.DeepEqual(n.Advisory.OtherAliases, []string{"GHSA-ppp5-5v6c-4jwp"}) {
		t.Errorf("advisory = %+v", n.Advisory)
	}
	repo := "https://github.com/golang/text"
	fc := repo + "@383b2e75a7a4198c42f8f87833eefb772868a56f"
	rs := relSet(n)
	for _, w := range []string{
		"HOSTED_IN|pkg:golang/golang.org/x/text|" + repo,
		"REFERS_TO_REPOSITORY|GO-2021-0113|" + repo,
		"HAS_FIX_COMMIT|" + repo + "|" + fc,
		"FIXES|" + fc + "|GO-2021-0113",
		"AFFECTS_PACKAGE|GO-2021-0113|pkg:golang/golang.org/x/text",
	} {
		if !rs[w] {
			t.Errorf("missing %s; have %v", w, rs)
		}
	}
	// The same commit comes from the GIT range and from a reference: once.
	fcs, repos, fixes := 0, 0, 0
	for _, e := range n.Entities {
		switch e.Ref.Kind {
		case source.RefFixCommit:
			fcs++
		case source.RefRepository:
			repos++
		}
	}
	for _, r := range n.Rels {
		if r.Type == "FIXES" {
			fixes++
		}
	}
	if fcs != 1 || repos != 2 || fixes != 1 {
		t.Errorf("fix commits %d repositories %d FIXES %d", fcs, repos, fixes)
	}
	// The reference link adds the url the GIT range lacks.
	if e := entity(n, source.RefFixCommit, fc); e.Props["url"] == nil || e.Props["sha"] != "383b2e75a7a4198c42f8f87833eefb772868a56f" {
		t.Errorf("fix commit props = %v", e.Props)
	}
	short := false
	for _, no := range n.Notes {
		if no.Kind == "warning" && strings.Contains(no.Text, "deadbeef") {
			short = true
		}
	}
	if !short {
		t.Errorf("no warning for the short sha: %+v", n.Notes)
	}
	v := entity(n, source.RefAdvisory, "GO-2021-0113")
	if _, ok := v.Props["osvWithdrawn"].(time.Time); !ok || contains(v.Clear, "osvWithdrawn") {
		t.Errorf("withdrawn: %v %v", v.Props, v.Clear)
	}
	// GIT ranges do not appear in affectedRanges.
	for _, r := range n.Rels {
		if r.Type == "AFFECTS_PACKAGE" {
			if got := r.Props["affectedRanges"]; !reflect.DeepEqual(got, []string{"introduced=0,fixed=0.3.7"}) {
				t.Errorf("affectedRanges = %v", got)
			}
		}
	}
}

func TestNormalizeMissingModifiedOrID(t *testing.T) {
	a := New(Options{})
	n, err := a.Normalize(source.Record{ID: "GHSA-xxxx-yyyy-zzzz", Payload: td(t, "no-modified.json")})
	if err != nil {
		t.Fatal(err)
	}
	if !n.Missing || len(n.Entities) != 0 || len(n.Rels) != 0 || len(n.Notes) != 1 || n.Notes[0].Kind != "warning" {
		t.Errorf("normalized = %+v", n)
	}
	n, err = a.Normalize(source.Record{ID: "entry", Payload: []byte(`{"modified":"2024-01-01T00:00:00Z"}`)})
	if err != nil || !n.Missing || len(n.Entities) != 0 {
		t.Errorf("no id: %+v %v", n, err)
	}
}

func TestNormalizeBadPackages(t *testing.T) {
	a := New(Options{})
	n, err := a.Normalize(source.Record{ID: "OSV-2024-1", Payload: td(t, "bad-purl.json")})
	if err != nil {
		t.Fatal(err)
	}
	resolveAll(t, n)
	var pk []string
	for _, e := range n.Entities {
		if e.Ref.Kind == source.RefPackage {
			pk = append(pk, e.Ref.Raw)
		}
	}
	if !reflect.DeepEqual(pk, []string{"pkg:cargo/serde"}) {
		t.Errorf("packages = %v", pk)
	}
	bad, repoNote := 0, false
	for _, no := range n.Notes {
		if strings.Contains(no.Text, "package skipped") {
			bad++
		}
		if strings.Contains(no.Text, "not normalized") {
			repoNote = true
		}
	}
	if bad != 2 || !repoNote {
		t.Errorf("notes = %+v", n.Notes)
	}
	for _, e := range n.Entities {
		if e.Ref.Kind == source.RefRepository || e.Ref.Kind == source.RefFixCommit {
			t.Errorf("unexpected %+v", e)
		}
	}
	for _, r := range n.Rels {
		if r.Type != "AFFECTS_PACKAGE" {
			t.Errorf("unexpected relationship %+v", r)
		}
	}
	if len(n.Advisory.CVEs) != 0 {
		t.Error("unexpected CVEs")
	}
}

func TestNormalizeTwoCVEsSummaryCutAndRangeCap(t *testing.T) {
	var evs []string
	for i := 0; i < 130; i++ {
		evs = append(evs, fmt.Sprintf(`{"introduced":"%d.0"},{"fixed":"%d.1"}`, i, i))
	}
	long := strings.Repeat("é", 2500)
	payload := fmt.Sprintf(`{"id":"GHSA-c2f3-4gh5-wxmp","modified":"2024-01-01T00:00:00Z","summary":%q,
	  "aliases":["cve-2020-0001","CVE-2020-0002","CVE-2020-0001"],"upstream":["CVE-2020-0002","RHSA-1"],
	  "affected":[{"package":{"ecosystem":"PyPI","name":"x"},"ranges":[{"type":"ECOSYSTEM","events":[%s]}]}]}`,
		long, strings.Join(evs, ","))
	n, err := New(Options{}).Normalize(source.Record{ID: "GHSA-c2f3-4gh5-wxmp", Payload: []byte(payload)})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(n.Advisory.CVEs, []string{"cve-2020-0001", "CVE-2020-0002"}) ||
		!reflect.DeepEqual(n.Advisory.OtherAliases, []string{"RHSA-1"}) {
		t.Errorf("advisory = %+v", n.Advisory)
	}
	v := entity(n, source.RefAdvisory, "GHSA-c2f3-4gh5-wxmp")
	if got := []rune(v.Props["osvSummary"].(string)); len(got) != 2000 {
		t.Errorf("summary has %d runes", len(got))
	}
	for _, r := range n.Rels {
		if r.Type == "AFFECTS_PACKAGE" {
			if got := len(r.Props["affectedRanges"].([]string)); got != 100 {
				t.Errorf("affectedRanges has %d entries", got)
			}
		}
	}
}

func TestNormalizeCVEIdRecord(t *testing.T) {
	n, err := New(Options{}).Normalize(source.Record{ID: "CVE-2021-0001", Payload: []byte(
		`{"id":"CVE-2021-0001","modified":"2024-01-01T00:00:00Z","summary":"x"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if n.Advisory != nil || n.Entities[0].Ref.Kind != source.RefCVE {
		t.Errorf("normalized = %+v", n)
	}
	if _, err := New(Options{}).Normalize(source.Record{ID: "x", Payload: []byte(`{"id":"nonsense","modified":"2024-01-01T00:00:00Z"}`)}); err == nil || !strings.Contains(err.Error(), "nonsense") {
		t.Errorf("err = %v", err)
	}
	if _, err := New(Options{}).Normalize(source.Record{ID: "bad.json", Payload: []byte(`{`)}); err == nil || !strings.Contains(err.Error(), "bad.json") {
		t.Errorf("err = %v", err)
	}
}

func TestNormalizeDeterministicAndCursorMarker(t *testing.T) {
	a := New(Options{})
	r := source.Record{ID: "GO-2021-0113", Payload: td(t, "GO-2021-0113.json")}
	n1, _ := a.Normalize(r)
	n2, _ := a.Normalize(r)
	if !reflect.DeepEqual(n1, n2) {
		t.Error("Normalize is not deterministic")
	}
	n, err := a.Normalize(source.Record{ID: "osv-cursor:npm"})
	if err != nil || len(n.Entities) != 0 {
		t.Errorf("cursor marker: %+v %v", n, err)
	}
}

// fixtureZip is the npm/PyPI/Go test bucket content.
func fixtureBucket(t *testing.T) *bucket {
	b := newBucket()
	b.zips["npm"] = mkZip(t,
		[2]string{"GHSA-c2f3-4gh5-wxmp.json", string(td(t, "GHSA-c2f3-4gh5-wxmp.json"))},
		[2]string{"no-modified.json", string(td(t, "no-modified.json"))},
		[2]string{"readme.txt", "ignored"},
	)
	b.zips["PyPI"] = mkZip(t, [2]string{"PYSEC-2021-1.json", string(td(t, "PYSEC-2021-1.json"))})
	b.zips["Go"] = mkZip(t,
		[2]string{"GO-2021-0113.json", string(td(t, "GO-2021-0113.json"))},
		[2]string{"OSV-2024-1.json", string(td(t, "bad-purl.json"))},
	)
	b.csv["npm"] = "2024-03-01T10:00:00.123456Z,GHSA-c2f3-4gh5-wxmp\n"
	b.csv["PyPI"] = "2024-02-01T00:00:00Z,PYSEC-2021-1\n"
	b.csv["Go"] = "2024-06-01T00:00:00Z,OSV-2024-1\n2024-04-01T12:00:00Z,GO-2021-0113\n"
	return b
}

func TestFetchFullThenIncremental(t *testing.T) {
	b := fixtureBucket(t)
	srv := httptest.NewServer(b)
	defer srv.Close()
	a, _ := newAdapter(t, srv, "npm", "PyPI", "Go")

	recs := drain(t, a, source.Checkpoint{}, source.RunOptions{})
	if got, want := payloads(recs), []string{"GHSA-c2f3-4gh5-wxmp", "GHSA-xxxx-yyyy-zzzz", "PYSEC-2021-1", "GO-2021-0113", "OSV-2024-1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("records = %v, want %v", got, want)
	}
	if b.hostUA != "bskg/test" {
		t.Errorf("User-Agent = %q", b.hostUA)
	}
	marks := marksOf(t, lastResume(recs))
	want := map[string]string{
		"npm":  "2024-03-01T10:00:00.123456Z",
		"PyPI": "2024-02-01T00:00:00Z",
		"Go":   "2024-06-01T00:00:00Z",
	}
	if !reflect.DeepEqual(marks, want) {
		t.Fatalf("marks = %v", marks)
	}
	st, _ := decodeState(lastResume(recs))
	if !strings.Contains(st.Licenses["npm"], "CC-BY-4.0") || st.Licenses["Go"] == "" {
		t.Errorf("licenses = %v", st.Licenses)
	}
	// The mark of an ecosystem is not in a cursor before the ecosystem ended.
	for _, r := range recs {
		if r.ID == "GHSA-c2f3-4gh5-wxmp" && len(marksOf(t, r.Cursor.Resume)) != 0 {
			t.Errorf("mark advanced before the ecosystem finished: %s", r.Cursor.Resume)
		}
	}
	// Downloaded zips do not stay in the cache.
	left, _ := filepath.Glob(filepath.Join(a.cache, "*"))
	if len(left) != 0 {
		t.Errorf("cache not empty: %v", left)
	}

	// Second run, nothing newer: modified_id.csv says so, no zip request.
	zipHits := b.count("/npm/all.zip")
	recs2 := drain(t, a, source.Checkpoint{Resume: lastResume(recs)}, source.RunOptions{})
	if got := payloads(recs2); len(got) != 0 {
		t.Fatalf("second run emitted %v", got)
	}
	if b.count("/npm/all.zip") != zipHits {
		t.Error("npm zip downloaded although modified_id.csv has nothing new")
	}
	if !reflect.DeepEqual(marksOf(t, lastResume(recs2)), want) {
		t.Errorf("marks changed: %v", lastResume(recs2))
	}

	// A newer Go record: only it is emitted; other ecosystems stay unchanged.
	b.mu.Lock()
	b.zips["Go"] = mkZip(t,
		[2]string{"GO-2021-0113.json", string(td(t, "GO-2021-0113.json"))},
		[2]string{"OSV-2024-1.json", string(td(t, "bad-purl.json"))},
		[2]string{"GO-2025-1.json", rec("GO-2025-1", "2025-01-01T00:00:00Z")},
	)
	b.csv["Go"] = "2025-01-01T00:00:00Z,GO-2025-1\n" + b.csv["Go"]
	b.mu.Unlock()
	recs3 := drain(t, a, source.Checkpoint{Resume: lastResume(recs)}, source.RunOptions{})
	if got := payloads(recs3); !reflect.DeepEqual(got, []string{"GO-2025-1"}) {
		t.Fatalf("third run emitted %v", got)
	}
	m3 := marksOf(t, lastResume(recs3))
	if m3["Go"] != "2025-01-01T00:00:00Z" || m3["npm"] != want["npm"] || m3["PyPI"] != want["PyPI"] {
		t.Errorf("marks = %v", m3)
	}
}

func TestMarkUsesNewestRecordAndSkipsOlder(t *testing.T) {
	b := newBucket()
	b.zips["Go"] = mkZip(t,
		[2]string{"a.json", rec("GO-2024-0001", "2024-01-01T00:00:00Z")},
		[2]string{"b.json", rec("GO-2024-0002", "2024-03-01T00:00:00Z")},
		[2]string{"c.json", rec("GO-2024-0003", "2024-02-01T00:00:00Z")},
	)
	b.csv["Go"] = "2024-03-01T00:00:00Z,GO-2024-0002\n"
	srv := httptest.NewServer(b)
	defer srv.Close()
	a, _ := newAdapter(t, srv, "Go")
	cp := source.Checkpoint{Resume: `{"v":1,"marks":{"Go":"2024-01-15T00:00:00Z"}}`}
	recs := drain(t, a, cp, source.RunOptions{})
	if got := payloads(recs); !reflect.DeepEqual(got, []string{"GO-2024-0002", "GO-2024-0003"}) {
		t.Fatalf("emitted %v", got)
	}
	if m := marksOf(t, lastResume(recs)); m["Go"] != "2024-03-01T00:00:00Z" {
		t.Errorf("marks = %v", m)
	}
	// A record exactly at the mark is not emitted.
	cp = source.Checkpoint{Resume: `{"v":1,"marks":{"Go":"2024-02-01T00:00:00Z"}}`}
	if got := payloads(drain(t, a, cp, source.RunOptions{})); !reflect.DeepEqual(got, []string{"GO-2024-0002"}) {
		t.Errorf("emitted %v", got)
	}
}

func TestModifiedCSVProblemFallsBackToZip(t *testing.T) {
	b := newBucket()
	b.zips["Go"] = mkZip(t, [2]string{"a.json", rec("GO-2024-0002", "2024-03-01T00:00:00Z")})
	// no csv: 404
	srv := httptest.NewServer(b)
	defer srv.Close()
	a, _ := newAdapter(t, srv, "Go")
	cp := source.Checkpoint{Resume: `{"v":1,"marks":{"Go":"2024-01-15T00:00:00Z"}}`}
	if got := payloads(drain(t, a, cp, source.RunOptions{})); !reflect.DeepEqual(got, []string{"GO-2024-0002"}) {
		t.Errorf("emitted %v", got)
	}
}

func TestEcosystemFailureKeepsMarkAndContinues(t *testing.T) {
	b := fixtureBucket(t)
	b.fail["PyPI"] = http.StatusInternalServerError
	srv := httptest.NewServer(b)
	defer srv.Close()
	a, clk := newAdapter(t, srv, "npm", "PyPI", "Go")
	cp := source.Checkpoint{Resume: `{"v":1,"marks":{"PyPI":"2000-01-01T00:00:00Z"}}`}
	b.csv["PyPI"] = "2024-02-01T00:00:00Z,PYSEC-2021-1\n"

	recs := drain(t, a, cp, source.RunOptions{})
	var failure *source.Record
	for i := range recs {
		if recs[i].ID == "osv-ecosystem:PyPI" {
			failure = &recs[i]
		}
	}
	if failure == nil {
		t.Fatalf("no failure record in %v", payloads(recs))
	}
	if _, err := a.Normalize(*failure); err == nil || !strings.Contains(err.Error(), "PyPI") {
		t.Errorf("Normalize of the failure record: %v", err)
	}
	// Retried 3 times from 1 s, doubling (14.7).
	if !reflect.DeepEqual(clk.slept, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}) {
		t.Errorf("sleeps = %v", clk.slept)
	}
	if got := b.count("/PyPI/all.zip"); got != 4 {
		t.Errorf("PyPI attempts = %d", got)
	}
	m := marksOf(t, lastResume(recs))
	if m["PyPI"] != "2000-01-01T00:00:00Z" {
		t.Errorf("PyPI mark changed: %v", m)
	}
	if m["npm"] == "" || m["Go"] == "" {
		t.Errorf("other ecosystems not finished: %v", m)
	}
	if got := payloads(recs); !contains(got, "GHSA-c2f3-4gh5-wxmp") || !contains(got, "GO-2021-0113") {
		t.Errorf("records = %v", got)
	}
}

func TestCorruptZipAndUnsupportedEcosystem(t *testing.T) {
	b := newBucket()
	b.zips["npm"] = []byte("not a zip")
	b.zips["Go"] = mkZip(t, [2]string{"a.json", rec("GO-2024-0002", "2024-03-01T00:00:00Z")})
	srv := httptest.NewServer(b)
	defer srv.Close()
	a, _ := newAdapter(t, srv, "npm", "Debian", "Go")
	recs := drain(t, a, source.Checkpoint{}, source.RunOptions{})
	var ids []string
	for _, r := range recs {
		ids = append(ids, r.ID)
	}
	want := []string{"osv-ecosystem:npm", "osv-ecosystem:Debian", "GO-2024-0002", "osv-cursor:Go"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("ids = %v", ids)
	}
	if m := marksOf(t, lastResume(recs)); len(m) != 1 || m["Go"] == "" {
		t.Errorf("marks = %v", m)
	}
}

func TestEcosystemNameWithSpaceIsEscaped(t *testing.T) {
	var path string
	b := newBucket()
	b.zips["GitHub Actions"] = mkZip(t, [2]string{"GHSA-c2f3-4gh5-wxmp.json", rec("GHSA-c2f3-4gh5-wxmp", "2024-01-01T00:00:00Z")})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.EscapedPath()
		b.ServeHTTP(w, r)
	}))
	defer srv.Close()
	a, _ := newAdapter(t, srv, "GitHub Actions")
	recs := drain(t, a, source.Checkpoint{}, source.RunOptions{})
	if path != "/GitHub%20Actions/all.zip" {
		t.Errorf("path = %q", path)
	}
	if got := payloads(recs); len(got) != 1 {
		t.Errorf("records = %v", got)
	}
}

func TestSampleLimit(t *testing.T) {
	b := fixtureBucket(t)
	srv := httptest.NewServer(b)
	defer srv.Close()
	a, _ := newAdapter(t, srv, "npm", "PyPI", "Go")
	// Marks are ignored in a sample build.
	cp := source.Checkpoint{Resume: `{"v":1,"marks":{"npm":"2099-01-01T00:00:00Z"}}`}
	recs := drain(t, a, cp, source.RunOptions{SampleLimit: 3})
	if got, want := payloads(recs), []string{"GHSA-c2f3-4gh5-wxmp", "GHSA-xxxx-yyyy-zzzz", "PYSEC-2021-1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("records = %v", got)
	}
	if b.count("/Go/all.zip") != 0 {
		t.Error("Go zip downloaded after the limit")
	}
	if b.count("/npm/modified_id.csv") != 0 {
		t.Error("sample build read modified_id.csv")
	}
	left, _ := filepath.Glob(filepath.Join(a.cache, "*"))
	if len(left) != 0 {
		t.Errorf("cache not empty: %v", left)
	}
	if got := payloads(drain(t, a, source.Checkpoint{}, source.RunOptions{SampleLimit: 1})); len(got) != 1 {
		t.Errorf("limit 1: %v", got)
	}
}

var keyRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]*$`)

func TestTotals(t *testing.T) {
	b := fixtureBucket(t)
	b.csv["Go"] = "2024-06-01T00:00:00Z,OSV-2024-1\n2024-04-01T12:00:00Z,GO-2021-0113\n\n"
	b.zips["crates.io"] = mkZip(t, [2]string{"RUSTSEC-2020-0001.json", rec("RUSTSEC-2020-0001", "2024-01-01T00:00:00Z")})
	b.csv["crates.io"] = "1\n2\n3\n"
	srv := httptest.NewServer(b)
	defer srv.Close()
	a, _ := newAdapter(t, srv, "npm", "Go", "crates.io")

	// Before any fetch: counted from modified_id.csv.
	got, err := a.Totals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]int64{"npm": 1, "Go": 2, "cratesio": 3, "total": 6}; !reflect.DeepEqual(got, want) {
		t.Errorf("totals = %v", got)
	}
	// After a full read: counted from the zips (3 entries ending in .json for npm minus none).
	drain(t, a, source.Checkpoint{}, source.RunOptions{})
	got, _ = a.Totals(context.Background())
	if want := map[string]int64{"npm": 2, "Go": 2, "cratesio": 1, "total": 5}; !reflect.DeepEqual(got, want) {
		t.Errorf("totals after fetch = %v", got)
	}
	for k := range got {
		if !keyRe.MatchString(k) {
			t.Errorf("bad key %q", k)
		}
	}
	// An ecosystem that cannot be counted is left out, and so is the total.
	delete(b.csv, "npm")
	a2, _ := newAdapter(t, srv, "npm", "Go")
	got, _ = a2.Totals(context.Background())
	if want := map[string]int64{"Go": 2}; !reflect.DeepEqual(got, want) {
		t.Errorf("totals = %v", got)
	}
}

func TestInvalidCheckpoint(t *testing.T) {
	a := New(Options{Ecosystems: []string{"Go"}})
	for _, r := range []string{`{`, `{"marks":{"Go":"yesterday"}}`} {
		if _, err := a.Fetch(context.Background(), source.Checkpoint{Resume: r}, source.RunOptions{}); err == nil {
			t.Errorf("Fetch accepted checkpoint %q", r)
		}
	}
}

func TestCancelledContext(t *testing.T) {
	b := fixtureBucket(t)
	srv := httptest.NewServer(b)
	defer srv.Close()
	a, _ := newAdapter(t, srv, "npm")
	ctx, cancel := context.WithCancel(context.Background())
	it, _ := a.Fetch(ctx, source.Checkpoint{}, source.RunOptions{})
	cancel()
	if _, err := it.Next(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestStateEncodingIsStable(t *testing.T) {
	st, _ := decodeState("")
	st.Marks["npm"] = "2024-01-01T00:00:00Z"
	st.Marks["Go"] = "2024-01-02T00:00:00Z"
	var m map[string]any
	if err := json.Unmarshal([]byte(st.encode()), &m); err != nil || m["v"].(float64) != 1 {
		t.Fatalf("%v %v", m, err)
	}
	if st.encode() != st.encode() || !strings.HasPrefix(st.encode(), `{"v":1,"marks":{"Go":`) {
		t.Errorf("encoding = %s", st.encode())
	}
}
