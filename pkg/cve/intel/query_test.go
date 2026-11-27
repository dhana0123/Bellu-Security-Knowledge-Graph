package intel

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/osv"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/graph"
)

type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

const pyDoc1 = `{"id":"GHSA-py-0001","aliases":["CVE-2024-5000"],"summary":"py bug","published":"2024-01-01T00:00:00Z","modified":"2024-02-01T00:00:00Z",
 "references":[{"type":"FIX","url":"https://example.test/fix/1"}],
 "affected":[{"package":{"ecosystem":"PyPI","name":"Foo_Bar"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"2.0"}]}]}]}`

const pyDoc2 = `{"id":"GHSA-py-0002","aliases":["CVE-2024-5000"],"summary":"py bug again","published":"2024-01-01T00:00:00Z","modified":"2024-03-01T00:00:00Z",
 "affected":[{"package":{"ecosystem":"PyPI","name":"Foo_Bar"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"2.0"}]}]}]}`

var (
	t1 = time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	t2 = time.Date(2024, 4, 1, 0, 0, 0, 0, time.UTC)
)

// buildPyGraph builds a graph with CVE-2024-5000 (second record recorded at t2).
func buildPyGraph(t *testing.T, history bool) string {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	canon := filepath.Join(dir, "canonical.db")
	st, err := canonical.Open(canon)
	if err != nil {
		t.Fatal(err)
	}
	clk := &fixedClock{t: t1}
	st.SetClock(clk)
	up := func(doc string) {
		rec, err := osv.Parse("osv", []byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.UpsertRecord(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	up(pyDoc1)
	clk.t = t2
	up(pyDoc2)
	if _, err := st.Resolve(ctx, canonical.ResolveOptions{}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	out := filepath.Join(dir, "graph.db")
	p := &graph.Projector{CanonicalPath: canon, History: history,
		Sinks: []graph.NamedSink{{Name: "sqlite", Sink: graph.NewSQLiteSink(out)}},
		Clock: &fixedClock{t: t2}}
	if _, err := p.Run(ctx); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPackageVulnerabilities(t *testing.T) {
	c := openClient(t, buildPyGraph(t, false))
	ctx := context.Background()

	ms, err := c.GetPackageVulnerabilities(ctx, "PyPI", "foo-bar", "1.5")
	if err != nil || len(ms) != 1 {
		t.Fatalf("got %v, %v", ms, err)
	}
	m := ms[0]
	if m.State != MatchAffected || m.Level != LevelAffectedPackage || m.FixedVersion != "2.0" || m.Range == nil || m.Range.Source != "osv" {
		t.Errorf("match = %+v range=%+v", m, m.Range)
	}
	// name canonicalization
	if ms, err := c.GetPackageVulnerabilities(ctx, "pypi", "Foo_Bar", "1.5"); err != nil || len(ms) != 1 {
		t.Errorf("Foo_Bar: %v, %v", ms, err)
	}
	// outside the range
	if ms, err := c.GetPackageVulnerabilities(ctx, "PyPI", "foo-bar", "2.0"); err != nil || ms == nil || len(ms) != 0 {
		t.Errorf("fixed version: %v, %v", ms, err)
	}
	// unknown package
	if ms, err := c.GetPackageVulnerabilities(ctx, "PyPI", "nope", "1.0"); err != nil || ms == nil || len(ms) != 0 {
		t.Errorf("unknown pkg: %v, %v", ms, err)
	}
	// invalid version
	ms, err = c.GetPackageVulnerabilities(ctx, "PyPI", "foo-bar", "not a version!!")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.State != MatchUnknown || m.Range != nil || m.Level != LevelAffectedPackage {
			t.Errorf("expected unknown, got %+v", m)
		}
	}
	// validation
	for _, a := range [][3]string{{"", "n", "1"}, {"PyPI", " ", "1"}, {"PyPI", "n", ""}} {
		if _, err := c.GetPackageVulnerabilities(ctx, a[0], a[1], a[2]); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%v: err = %v", a, err)
		}
	}
}

func TestProductsAndPatches(t *testing.T) {
	c := openClient(t, buildPyGraph(t, false))
	ctx := context.Background()
	ps, err := c.GetAffectedProducts(ctx, "CVE-2024-5000")
	if err != nil || len(ps) != 1 {
		t.Fatalf("%v %v", ps, err)
	}
	if p := ps[0]; p.Kind != "package" || p.Ecosystem != "PyPI" || p.Fixed != "2.0" || p.Introduced != "1.0" || p.ID != "pkg:pypi/foo-bar" {
		t.Errorf("product = %+v", p)
	}
	pt, err := c.GetPatches(ctx, "CVE-2024-5000")
	if err != nil || len(pt) != 1 || pt[0].URL != "https://example.test/fix/1" || pt[0].Source != "osv" {
		t.Errorf("patches = %+v, %v", pt, err)
	}
	if _, err := c.GetAffectedProducts(ctx, "CVE-1999-0000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("products err = %v", err)
	}
	if _, err := c.GetPatches(ctx, "CVE-1999-0000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("patches err = %v", err)
	}
	if _, err := c.GetPatches(ctx, ""); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("empty id err = %v", err)
	}
}

func TestAnalyzeDependencies(t *testing.T) {
	c := openClient(t, buildPyGraph(t, false))
	ctx := context.Background()
	deps := []Dependency{
		{"PyPI", "nope", "1"},
		{"PyPI", "Foo_Bar", "1.5"},
		{"PyPI", "foo-bar", "3.0"},
	}
	res, err := c.AnalyzeDependencies(ctx, deps)
	if err != nil || len(res) != 3 {
		t.Fatalf("%v %v", res, err)
	}
	for i, r := range res {
		if r.Dependency != deps[i] || r.Vulnerabilities == nil {
			t.Errorf("result %d = %+v", i, r)
		}
	}
	if len(res[0].Vulnerabilities) != 0 || len(res[1].Vulnerabilities) != 1 || len(res[2].Vulnerabilities) != 0 {
		t.Errorf("results = %+v", res)
	}

	if _, err := c.AnalyzeDependencies(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("empty: %v", err)
	}
	big := make([]Dependency, MaxDependencies+1)
	for i := range big {
		big[i] = Dependency{"PyPI", "x", "1"}
	}
	if _, err := c.AnalyzeDependencies(ctx, big); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("too many: %v", err)
	}
	if res, err := c.AnalyzeDependencies(ctx, big[:MaxDependencies]); err != nil || len(res) != MaxDependencies {
		t.Errorf("max: %d %v", len(res), err)
	}
	_, err = c.AnalyzeDependencies(ctx, []Dependency{{"PyPI", "a", "1"}, {"PyPI", "", "1"}})
	if !errors.Is(err, ErrInvalidRequest) || !strings.Contains(err.Error(), "deps[1].name") {
		t.Errorf("field error: %v", err)
	}
	_, err = c.AnalyzeDependencies(ctx, []Dependency{{"PyPI", "a", ""}})
	if !strings.Contains(err.Error(), "deps[0].version") {
		t.Errorf("field error: %v", err)
	}
	// DB failure maps to ErrSourceUnavailable
	cc := openClient(t, buildPyGraph(t, false))
	cc.Close()
	if _, err := cc.AnalyzeDependencies(ctx, deps); !errors.Is(err, ErrSourceUnavailable) {
		t.Errorf("closed db: %v", err)
	}
}

func TestAttackPathsStub(t *testing.T) {
	c := openClient(t, buildPyGraph(t, false))
	ps, err := c.GetAttackPaths(context.Background(), "CVE-2024-5000")
	if ps != nil || !errors.Is(err, ErrNotImplemented) {
		t.Errorf("%v %v", ps, err)
	}
}

func TestAsOf(t *testing.T) {
	ctx := context.Background()
	// without history
	c := openClient(t, buildPyGraph(t, false))
	mid := t1.Add(24 * time.Hour)
	if _, err := c.GetVulnerability(ctx, "CVE-2024-5000", WithAsOf(mid)); !errors.Is(err, ErrHistoryUnavailable) {
		t.Errorf("no history: %v", err)
	}
	if _, err := c.GetPackageVulnerabilities(ctx, "PyPI", "foo-bar", "1.5", WithAsOf(mid)); !errors.Is(err, ErrHistoryUnavailable) {
		t.Errorf("pkg no history: %v", err)
	}

	// with history
	c = openClient(t, buildPyGraph(t, true))
	v, err := c.GetVulnerability(ctx, "CVE-2024-5000", WithAsOf(mid))
	if err != nil {
		t.Fatal(err)
	}
	checkNonNil(t, v)
	if len(v.Sources) != 1 || v.Sources[0].ExternalID != "GHSA-PY-0001" || v.Summary != "py bug" {
		t.Errorf("mid view = %+v", v)
	}
	v, err = c.GetVulnerability(ctx, "CVE-2024-5000", WithAsOf(t2.Add(time.Hour)))
	if err != nil || len(v.Sources) != 2 {
		t.Fatalf("late view = %+v, %v", v, err)
	}
	if _, err := c.GetVulnerability(ctx, "CVE-2024-5000", WithAsOf(t1.Add(-time.Hour))); !errors.Is(err, ErrNotFound) {
		t.Errorf("before any record: %v", err)
	}
	if _, err := c.GetVulnerability(ctx, "CVE-2024-5000", WithAsOf(time.Time{})); !errors.Is(err, ErrInvalidAsOf) {
		t.Errorf("zero: %v", err)
	}
	if _, err := c.GetVulnerability(ctx, "CVE-2024-5000", WithAsOf(time.Now().Add(time.Hour))); !errors.Is(err, ErrInvalidAsOf) {
		t.Errorf("future: %v", err)
	}
	if _, err := c.GetPatches(ctx, "CVE-2024-5000", WithAsOf(mid)); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("patches as-of: %v", err)
	}
}

func TestOpenInstalled(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenInstalled(dir); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("empty dir: %v", err)
	}
	if _, err := OpenInstalled(""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty path: %v", err)
	}
	src := buildPyGraph(t, false)
	snap := filepath.Join(dir, "snapshots", "s1")
	if err := os.MkdirAll(snap, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snap, "graph.db"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("snapshots", "s1"), filepath.Join(dir, "current")); err != nil {
		t.Fatal(err)
	}
	c, err := OpenInstalled(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.GetVulnerability(context.Background(), "CVE-2024-5000"); err != nil {
		t.Error(err)
	}
}
