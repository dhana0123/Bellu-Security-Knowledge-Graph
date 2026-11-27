package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/osv"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/graph"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/pack"
)

func fixtureCanon(t *testing.T, files ...string) string {
	t.Helper()
	ctx := context.Background()
	st, err := canonical.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "graph", f))
		if err != nil {
			t.Fatal(err)
		}
		var docs []json.RawMessage
		if err := json.Unmarshal(data, &docs); err != nil {
			t.Fatal(err)
		}
		for _, d := range docs {
			rec, err := osv.Parse("osv", d)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.UpsertRecord(ctx, rec); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := st.Resolve(ctx, canonical.ResolveOptions{}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "canonical.db")
	if _, err := st.DB.Exec(`VACUUM INTO ?`, p); err != nil {
		t.Fatal(err)
	}
	return p
}

type chain struct {
	pkg   [3]string
	man   [3]pack.Manifest
	delta [2]string // S->T, T->U
}

func buildChain(t *testing.T) chain {
	t.Helper()
	var c chain
	sets := [][]string{{"snapshot_S.json"}, {"snapshot_S.json", "snapshot_T.json"}, {"snapshot_S.json", "snapshot_T.json", "snapshot_U.json"}}
	for i, s := range sets {
		p, m, err := pack.BuildSnapshot(context.Background(), pack.SnapshotOptions{
			CanonicalPath: fixtureCanon(t, s...), OutDir: t.TempDir(), Level: graph.LevelComplete,
			Clock: tclock{time.Date(2024, time.Month(i+1), 1, 0, 0, 0, 0, time.UTC)},
		})
		if err != nil {
			t.Fatal(err)
		}
		c.pkg[i], c.man[i] = p, m
	}
	for i := 0; i < 2; i++ {
		p, _, err := pack.BuildDelta(context.Background(), pack.DeltaOptions{BasePackage: c.pkg[i], TargetPackage: c.pkg[i+1], OutDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		c.delta[i] = p
	}
	return c
}

func dbHashOf(t *testing.T, in *Installer, id string) string {
	return hashOf(t, in.p("snapshots", id, pack.FileGraphDB))
}

func pkgDBHash(t *testing.T, pkg string) string {
	return hashOf(t, extractTo(t, pkg))
}

func extractTo(t *testing.T, pkg string) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "x")
	if _, err := extract(pkg, d); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(d, pack.FileGraphDB)
}

func installS(t *testing.T, c chain) *Installer {
	in := newInstaller(t)
	if _, err := in.Install(context.Background(), c.pkg[0]); err != nil {
		t.Fatal(err)
	}
	return in
}

func assertUntouched(t *testing.T, in *Installer, id, dbHash string) {
	t.Helper()
	st, err := in.Status()
	if err != nil || st.InstalledID != id {
		t.Fatalf("state %+v %v", st, err)
	}
	if h := hashOf(t, in.p("current", pack.FileGraphDB)); h != dbHash {
		t.Fatal("current graph.db changed")
	}
	if _, err := pack.LogicalDigest(in.p("current", pack.FileGraphDB)); err != nil {
		t.Fatal(err)
	}
	for _, n := range snapDirs(t, in) {
		if filepath.Ext(n) == ".partial" {
			t.Fatalf("partial left: %s", n)
		}
	}
}

func TestApplyDelta(t *testing.T) {
	c := buildChain(t)
	in := installS(t, c)
	st, err := in.Apply(context.Background(), c.delta[0], ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if st.InstalledID != c.man[1].SnapshotID || st.PreviousID != c.man[0].SnapshotID || len(st.AppliedDeltas) != 1 ||
		st.AppliedDeltas[0].Base != c.man[0].SnapshotID || st.AppliedDeltas[0].Target != c.man[1].SnapshotID {
		t.Fatalf("state %+v", st)
	}
	got, err := in.Status()
	if err != nil || got.InstalledID != st.InstalledID {
		t.Fatal(got, err)
	}
	if d, err := pack.LogicalDigest(in.p("current", pack.FileGraphDB)); err != nil || d != c.man[1].LogicalDigest {
		t.Fatalf("digest %q %v", d, err)
	}
	if _, err := os.Stat(in.p("current", pack.FileManifest)); err != nil {
		t.Fatal(err)
	}

	// chain T -> U; S is pruned.
	st, err = in.Apply(context.Background(), c.delta[1], ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if st.InstalledID != c.man[2].SnapshotID || len(st.AppliedDeltas) != 2 {
		t.Fatalf("state %+v", st)
	}
	dirs := snapDirs(t, in)
	if len(dirs) != 2 {
		t.Fatalf("dirs %v", dirs)
	}
	for _, d := range dirs {
		if d == c.man[0].SnapshotID {
			t.Fatal("older snapshot not pruned")
		}
	}
	if d, _ := pack.LogicalDigest(in.p("current", pack.FileGraphDB)); d != c.man[2].LogicalDigest {
		t.Fatal("digest U")
	}
}

func TestApplyBaseMismatch(t *testing.T) {
	c := buildChain(t)
	in := installS(t, c)
	h := hashOf(t, in.p("current", pack.FileGraphDB))
	_, err := in.Apply(context.Background(), c.delta[1], ApplyOptions{})
	var be *BaseMismatchError
	if !errors.Is(err, ErrBaseMismatch) || !errors.As(err, &be) || be.Expected != c.man[1].SnapshotID || be.Actual != c.man[0].SnapshotID {
		t.Fatalf("err %v", err)
	}
	assertUntouched(t, in, c.man[0].SnapshotID, h)
}

func TestApplyTamperedDelta(t *testing.T) {
	c := buildChain(t)
	in := installS(t, c)
	h := hashOf(t, in.p("current", pack.FileGraphDB))
	e := readEntries(t, c.delta[0])
	e[pack.FileDelta] = bytes.Replace(e[pack.FileDelta], []byte("\"summary\":\""), []byte("\"summary\":\"x"), 1)
	bad := filepath.Join(t.TempDir(), "bad.tar.gz")
	writePkg(t, bad, e)
	_, err := in.Apply(context.Background(), bad, ApplyOptions{})
	var ce *ChecksumError
	if !errors.As(err, &ce) || ce.File != pack.FileDelta || !errors.Is(err, pack.ErrChecksum) {
		t.Fatalf("err %v", err)
	}
	assertUntouched(t, in, c.man[0].SnapshotID, h)
}

func TestApplyFailureRemovesPartial(t *testing.T) {
	c := buildChain(t)
	for _, step := range []string{"after-ops", "verify", "rename"} {
		in := installS(t, c)
		h := hashOf(t, in.p("current", pack.FileGraphDB))
		in.applyHook = func(s string) error {
			if s == step {
				return errors.New("injected")
			}
			return nil
		}
		_, err := in.Apply(context.Background(), c.delta[0], ApplyOptions{})
		if err == nil {
			t.Fatalf("%s: want error", step)
		}
		assertUntouched(t, in, c.man[0].SnapshotID, h)
		if len(snapDirs(t, in)) != 1 {
			t.Fatalf("%s: dirs %v", step, snapDirs(t, in))
		}
	}
}

func TestApplyThreshold(t *testing.T) {
	c := buildChain(t)
	in := installS(t, c)
	for _, th := range []int{-1, 100_000_001} {
		if _, err := in.Apply(context.Background(), c.delta[0], ApplyOptions{Threshold: th}); err == nil {
			t.Fatalf("threshold %d accepted", th)
		}
	}
	h := hashOf(t, in.p("current", pack.FileGraphDB))
	// over threshold without a full snapshot: error, nothing changed
	if _, err := in.Apply(context.Background(), c.delta[0], ApplyOptions{Threshold: 1}); err == nil {
		t.Fatal("want error without FullSnapshot")
	}
	assertUntouched(t, in, c.man[0].SnapshotID, h)
	// wrong full snapshot
	if _, err := in.Apply(context.Background(), c.delta[0], ApplyOptions{Threshold: 1, FullSnapshot: c.pkg[2]}); err == nil {
		t.Fatal("want error for wrong full snapshot")
	}
	assertUntouched(t, in, c.man[0].SnapshotID, h)
	st, err := in.Apply(context.Background(), c.delta[0], ApplyOptions{Threshold: 1, FullSnapshot: c.pkg[1]})
	if err != nil {
		t.Fatal(err)
	}
	if st.InstalledID != c.man[1].SnapshotID || st.PreviousID != c.man[0].SnapshotID || len(st.AppliedDeltas) != 0 {
		t.Fatalf("state %+v", st)
	}
	if dbHashOf(t, in, st.InstalledID) != pkgDBHash(t, c.pkg[1]) {
		t.Fatal("full install db differs")
	}
}
