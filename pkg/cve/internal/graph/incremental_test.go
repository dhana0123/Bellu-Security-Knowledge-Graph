package graph

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

type incrFixture struct {
	t     *testing.T
	canon string
	store *canonical.Store
	dir   string // incremental output
}

func newIncrFixture(t *testing.T) *incrFixture {
	t.Helper()
	canon := filepath.Join(t.TempDir(), "canonical.db")
	st := buildFixtureStoreAt(t, canon)
	return &incrFixture{t: t, canon: canon, store: st, dir: t.TempDir()}
}

func (f *incrFixture) projector(dir string, incremental bool) *Projector {
	return &Projector{
		CanonicalPath: f.canon, Policy: Policy{Level: LevelComplete}, Clock: fixedClock{}, Incremental: incremental,
		Sinks: []NamedSink{{"sqlite", NewSQLiteSink(filepath.Join(dir, "graph.db"))}},
	}
}

func (f *incrFixture) run(dir string, incremental bool) Stats {
	f.t.Helper()
	st, err := f.projector(dir, incremental).Run(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	return st
}

// sameAsFull projects the canonical store from scratch and requires the incremental graph.db to
// have exactly the same nodes and edges (ids, types, endpoints, properties and content hashes).
func (f *incrFixture) sameAsFull(label string) {
	f.t.Helper()
	full := f.t.TempDir()
	f.run(full, false)
	if err := CompareDBs(filepath.Join(full, "graph.db"), filepath.Join(f.dir, "graph.db")); err != nil {
		f.t.Fatalf("%s: incremental differs from full rebuild: %v", label, err)
	}
}

func (f *incrFixture) resolve() {
	f.t.Helper()
	if _, err := f.store.Resolve(context.Background(), canonical.ResolveOptions{}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *incrFixture) upsert(r *model.Record) {
	f.t.Helper()
	if _, err := f.store.UpsertRecord(context.Background(), r); err != nil {
		f.t.Fatal(err)
	}
}

func TestIncrementalEqualsFullRebuild(t *testing.T) {
	f := newIncrFixture(t)
	ctx := context.Background()
	mod := time.Date(2024, 4, 1, 0, 0, 0, 0, time.UTC)

	// First run: nothing to build on, so it is a full build that records the state.
	st := f.run(f.dir, true)
	if st.Mode != "full" || st.FullReason == "" {
		t.Fatalf("first run: mode=%q reason=%q", st.Mode, st.FullReason)
	}
	f.sameAsFull("first run")
	if _, err := os.Stat(StatePath(filepath.Join(f.dir, "graph.db"))); err != nil {
		t.Fatalf("no state file: %v", err)
	}

	// Nothing changed: no work, graph.db untouched byte for byte.
	before, _ := os.ReadFile(filepath.Join(f.dir, "graph.db"))
	st = f.run(f.dir, true)
	after, _ := os.ReadFile(filepath.Join(f.dir, "graph.db"))
	if st.Mode != "unchanged" || st.Changed != 0 || !bytes.Equal(before, after) {
		t.Fatalf("no-change run: mode=%q changed=%d identical=%v", st.Mode, st.Changed, bytes.Equal(before, after))
	}
	f.sameAsFull("no change")

	steps := []struct {
		name string
		do   func()
		min  int // vulnerabilities the run must have re-projected at least
	}{
		{"kev change", func() {
			if _, err := f.store.UpsertKEV(ctx, model.KEV{CVE: "CVE-2024-1000", DateAdded: "2024-03-01", DueDate: "2024-04-22", Ransomware: "unknown"}); err != nil {
				t.Fatal(err)
			}
		}, 1},
		{"new epss date", func() {
			if _, err := f.store.UpsertEPSS(ctx, model.EPSS{CVE: "CVE-2024-1000", Score: 0.7, Percentile: 0.97, Date: "2024-03-03"}); err != nil {
				t.Fatal(err)
			}
		}, 1},
		{"unlinked kev and epss do not touch anything", func() {
			if _, err := f.store.UpsertKEV(ctx, model.KEV{CVE: "CVE-2098-0002"}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.UpsertEPSS(ctx, model.EPSS{CVE: "CVE-2098-0003", Score: 0.1, Percentile: 0.1, Date: "2024-03-03"}); err != nil {
				t.Fatal(err)
			}
		}, 0},
		{"record changed: package and weakness", func() {
			f.upsert(&model.Record{
				Source: "nvd", ID: "CVE-2024-1000", Summary: "fixture nvd v2", Published: mod, Modified: mod.Add(time.Hour),
				Weaknesses: []string{"CWE-79", "CWE-89"},
				Affected: []model.Affected{
					{Kind: "package", Ecosystem: "npm", Name: "fix-pkg", Ranges: []model.Range{{Type: "SEMVER", Events: []model.Event{{Introduced: "0.5.0"}, {Fixed: "1.0.2"}}}}},
					{Kind: "package", Ecosystem: "Maven", Name: "org.example:new", Versions: []string{"3.0"}},
				},
				References: []model.Reference{{Type: "FIX", URL: "https://example.test/fix2"}},
			})
		}, 1},
		{"new advisory joins an existing vulnerability, new CVE appears", func() {
			f.upsert(&model.Record{Source: "ghsa", ID: "GHSA-new1-new1-new1", Aliases: []string{"CVE-2024-1000"}, Summary: "joins", Modified: mod,
				Affected: []model.Affected{{Kind: "package", Ecosystem: "npm", Name: "fix-pkg", Versions: []string{"0.9.0"}}}})
			f.upsert(&model.Record{Source: "nvd", ID: "CVE-2024-7777", Summary: "brand new", Published: mod, Modified: mod,
				Affected: []model.Affected{{Kind: "package", Ecosystem: "npm", Name: "fix-pkg", Versions: []string{"0.9.0"}}, {Kind: "product", Vendor: "Acme", Name: "Gadget", Bounds: []model.Bound{{StartIncl: "1", EndExcl: "2"}}}}})
			f.resolve()
			if _, err := f.store.UpsertKEV(ctx, model.KEV{CVE: "CVE-2024-7777", DateAdded: "2024-04-02"}); err != nil {
				t.Fatal(err)
			}
		}, 2},
		{"two vulnerabilities merge", func() {
			f.upsert(&model.Record{Source: "osv", ID: "ZZ-ONE-1", Summary: "one", Modified: mod, Affected: []model.Affected{{Kind: "package", Ecosystem: "PyPI", Name: "merge-a", Versions: []string{"1"}}}})
			f.upsert(&model.Record{Source: "osv", ID: "ZZ-TWO-2", Summary: "two", Modified: mod, Affected: []model.Affected{{Kind: "package", Ecosystem: "PyPI", Name: "merge-b", Versions: []string{"2"}}}})
			f.resolve()
			f.runAndCompare("separate")
			f.upsert(&model.Record{Source: "osv", ID: "ZZ-BRIDGE-3", Aliases: []string{"ZZ-ONE-1", "ZZ-TWO-2"}, Summary: "bridge", Modified: mod,
				Affected: []model.Affected{{Kind: "package", Ecosystem: "PyPI", Name: "merge-a", Versions: []string{"1"}}}})
			f.resolve()
		}, 1},
		{"record withdrawn", func() {
			f.upsert(&model.Record{Source: "nvd", ID: "CVE-2024-7777", Summary: "brand new", Published: mod, Modified: mod.Add(2 * time.Hour), Withdrawn: mod.Add(2 * time.Hour),
				Affected: []model.Affected{{Kind: "package", Ecosystem: "npm", Name: "fix-pkg", Versions: []string{"0.9.0"}}}})
		}, 1},
	}
	for _, s := range steps {
		s.do()
		st := f.runAndCompare(s.name)
		if s.min == 0 {
			if st.Mode != "unchanged" {
				t.Errorf("%s: mode=%q changed=%d, want unchanged", s.name, st.Mode, st.Changed)
			}
		} else if st.Mode != "incremental" || st.Changed < s.min {
			t.Errorf("%s: mode=%q changed=%d, want incremental with at least %d", s.name, st.Mode, st.Changed, s.min)
		}
	}
	// An incremental run touches few vulnerabilities compared with the whole graph.
	if st := f.runAndCompare("final"); st.Vulnerabilities < 3 {
		t.Fatalf("final vulnerabilities = %d", st.Vulnerabilities)
	}
}

// runAndCompare runs an incremental projection and requires the result to equal a full rebuild.
func (f *incrFixture) runAndCompare(label string) Stats {
	f.t.Helper()
	st := f.run(f.dir, true)
	f.sameAsFull(label)
	return st
}

func TestIncrementalFallsBackToFullBuild(t *testing.T) {
	f := newIncrFixture(t)
	f.run(f.dir, true)
	graphPath := filepath.Join(f.dir, "graph.db")
	statePath := StatePath(graphPath)

	// A plain full build replaces graph.db without a token: the state no longer belongs to it.
	f.run(f.dir, false)
	if st := f.run(f.dir, true); st.Mode != "full" || !strings.Contains(st.FullReason, "do not belong together") {
		t.Fatalf("after full rebuild: mode=%q reason=%q", st.Mode, st.FullReason)
	}
	// Missing state file.
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if st := f.run(f.dir, true); st.Mode != "full" || st.FullReason == "" {
		t.Fatalf("missing state: mode=%q reason=%q", st.Mode, st.FullReason)
	}
	// A different level needs a different graph.
	p := f.projector(f.dir, true)
	p.Policy = Policy{Level: LevelCore}
	if st, err := p.Run(context.Background()); err != nil || st.Mode != "full" || !strings.Contains(st.FullReason, "level") {
		t.Fatalf("level change: %+v %v", st, err)
	}
	f.sameAsFullLevel(LevelCore)
	// Corrupt state file.
	if err := os.WriteFile(statePath, []byte("not a database"), 0o644); err != nil {
		t.Fatal(err)
	}
	p = f.projector(f.dir, true)
	p.Policy = Policy{Level: LevelCore}
	if st, err := p.Run(context.Background()); err != nil || st.Mode != "full" {
		t.Fatalf("corrupt state: %+v %v", st, err)
	}
	f.sameAsFullLevel(LevelCore)
}

func (f *incrFixture) sameAsFullLevel(l Level) {
	f.t.Helper()
	full := f.t.TempDir()
	p := f.projector(full, false)
	p.Policy = Policy{Level: l}
	if _, err := p.Run(context.Background()); err != nil {
		f.t.Fatal(err)
	}
	if err := CompareDBs(filepath.Join(full, "graph.db"), filepath.Join(f.dir, "graph.db")); err != nil {
		f.t.Fatalf("level %s: %v", l, err)
	}
}

func TestIncrementalRejectsOtherSinksAndHistory(t *testing.T) {
	f := newIncrFixture(t)
	dir := t.TempDir()
	p, _ := newProj(f.canon, dir, false)
	p.Incremental = true
	if _, err := p.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "exactly one sink") {
		t.Fatalf("three sinks: %v", err)
	}
	p = &Projector{CanonicalPath: f.canon, Incremental: true, Sinks: []NamedSink{{"jsonl", NewJSONLSink(filepath.Join(dir, "j"))}}}
	if _, err := p.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "sqlite sink only") {
		t.Fatalf("jsonl: %v", err)
	}
	p = f.projector(dir, true)
	p.History = true
	if _, err := p.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "history") {
		t.Fatalf("history: %v", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("rejected runs left files: %v", ents)
	}
}

func TestIncrementalNeedsChangeFeed(t *testing.T) {
	f := newIncrFixture(t)
	for _, tbl := range []string{"projection_touch", "projection_meta"} {
		if _, err := f.store.DB.Exec(`DROP TABLE ` + tbl); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.projector(f.dir, true).Run(context.Background()); !errors.Is(err, ErrNoChangeFeed) {
		t.Fatalf("err = %v", err)
	}
}

// A failure at any point leaves the previous graph.db and state file byte-identical and no
// temporary files behind; the next run still works.
func TestSwapIsAtomicOnFailure(t *testing.T) {
	f := newIncrFixture(t)
	f.run(f.dir, true)
	graphPath := filepath.Join(f.dir, "graph.db")
	statePath := StatePath(graphPath)
	snapshot := func() (g, s []byte) {
		g, _ = os.ReadFile(graphPath)
		s, _ = os.ReadFile(statePath)
		return
	}
	g0, s0 := snapshot()
	listing := func() []string {
		ents, _ := os.ReadDir(f.dir)
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		return names
	}
	want := listing()
	check := func(label string) {
		t.Helper()
		g, s := snapshot()
		if !bytes.Equal(g, g0) || !bytes.Equal(s, s0) {
			t.Fatalf("%s: previous graph.db or state was modified", label)
		}
		if got := listing(); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("%s: files after failure %v, before %v", label, got, want)
		}
	}
	t.Cleanup(func() { testFailpoint = nil })

	// Incremental apply fails after a batch was applied to the copy.
	if _, err := f.store.UpsertKEV(context.Background(), model.KEV{CVE: "CVE-2024-1000", DateAdded: "2024-03-09", Ransomware: "known"}); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("injected failure")
	testFailpoint = func(stage string) error {
		if stage == "apply-batch" {
			return boom
		}
		return nil
	}
	if _, err := f.projector(f.dir, true).Run(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("incremental failure: %v", err)
	}
	check("incremental apply")

	// Context cancelled before any work.
	testFailpoint = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.projector(f.dir, true).Run(ctx); err == nil {
		t.Fatal("expected an error from a cancelled context")
	}
	check("cancelled")

	// A full build (state missing, so incremental falls back) fails before the sinks commit.
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	s0 = nil
	want = listing()
	testFailpoint = func(stage string) error {
		if stage == "full-before-commit" {
			return boom
		}
		return nil
	}
	if _, err := f.projector(f.dir, true).Run(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("full failure: %v", err)
	}
	if g, _ := snapshot(); !bytes.Equal(g, g0) {
		t.Fatal("full build failure modified the old graph.db")
	}
	if got := listing(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("full build failure left files: %v, before %v", got, want)
	}

	// Recovery: the same run now succeeds and equals a full rebuild.
	testFailpoint = nil
	f.run(f.dir, true)
	f.sameAsFull("after recovery")
	if st := f.run(f.dir, true); st.Mode != "unchanged" {
		t.Fatalf("mode after recovery = %q", st.Mode)
	}
}

// A sink that fails during a full (non-incremental) projection leaves the old graph.db alone,
// also now that the sink commits in batches.
func TestBatchedSQLiteSinkFailureKeepsOldFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "graph.db")
	if err := os.WriteFile(path, []byte("old graph"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewSQLiteSink(path)
	if err := s.Begin(context.Background(), SinkMeta{Level: LevelComplete}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < sqliteBatch*2+5; i++ { // crosses two batch commits
		if err := s.WriteNode(Node{ID: "n:" + itoa(i), Type: NodeVendor}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.WriteNode(Node{ID: "n:7", Type: NodeVendor}); !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("duplicate id: %v", err)
	}
	if err := s.Abort(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "old graph" {
		t.Fatal("old graph.db modified")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("temp files left: %v", ents)
	}
}

func itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{digits[i%10]}, b...)
	}
	return string(b)
}
