package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/osv"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/graph"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/pack"
)

type tclock struct{ t time.Time }

func (c tclock) Now() time.Time { return c.t }

func canonFile(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	st, err := canonical.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "graph", "snapshot_U.json"))
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
	mod := time.Date(2024, 2, 11, 0, 0, 0, 0, time.UTC)
	if _, err := st.UpsertRecord(ctx, &model.Record{Source: "nvd", ID: "CVE-2024-1000", Summary: "x", Published: mod, Modified: mod,
		Affected: []model.Affected{{Kind: "package", Ecosystem: "npm", Name: "fix-pkg", Versions: []string{"1.0.0"}}}}); err != nil {
		t.Fatal(err)
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

func build(t *testing.T, canon string, at time.Time) (string, pack.Manifest) {
	t.Helper()
	p, m, err := pack.BuildSnapshot(context.Background(), pack.SnapshotOptions{
		CanonicalPath: canon, OutDir: filepath.Join(t.TempDir(), "out"), Level: graph.LevelCore, Clock: tclock{at},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, m
}

func readEntries(t *testing.T, p string) map[string][]byte {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out[h.Name], _ = io.ReadAll(tr)
	}
}

func writePkg(t *testing.T, p string, entries map[string][]byte) {
	t.Helper()
	var names []string
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(entries[n]))}); err != nil {
			t.Fatal(err)
		}
		tw.Write(entries[n])
	}
	tw.Close()
	zw.Close()
}

// withSchema rewrites a package so it declares another schema version, with
// consistent checksums.
func withSchema(t *testing.T, src, ver string) string {
	t.Helper()
	e := readEntries(t, src)
	var m map[string]any
	if err := json.Unmarshal(e[pack.FileManifest], &m); err != nil {
		t.Fatal(err)
	}
	m["schema_version"] = ver
	e[pack.FileManifest], _ = json.Marshal(m)
	e[pack.FileSchemaVer] = []byte(fmt.Sprintf(`{"schema_version":%q}`, ver))
	var names []string
	for n := range e {
		if n != pack.FileChecksums {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var sums bytes.Buffer
	for _, n := range names {
		s := sha256.Sum256(e[n])
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(s[:]), n)
	}
	e[pack.FileChecksums] = sums.Bytes()
	out := filepath.Join(t.TempDir(), "v.tar.gz")
	writePkg(t, out, e)
	return out
}

func newInstaller(t *testing.T) *Installer {
	return &Installer{
		DataDir: filepath.Join(t.TempDir(), "data"),
		Clock:   tclock{time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)},
		Sleep:   func(context.Context, time.Duration) error { return nil },
	}
}

func hashOf(t *testing.T, p string) string {
	t.Helper()
	h, err := hashFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func snapDirs(t *testing.T, in *Installer) []string {
	t.Helper()
	es, err := os.ReadDir(in.p("snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestInstallFileAndStatus(t *testing.T) {
	canon := canonFile(t)
	pkg, m := build(t, canon, time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC))
	in := newInstaller(t)
	if _, err := in.Status(); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("want ErrNotInstalled, got %v", err)
	}
	st, err := in.Install(context.Background(), pkg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := in.Status()
	if err != nil {
		t.Fatal(err)
	}
	if got.InstalledID != m.SnapshotID || st.InstalledID != m.SnapshotID || got.Level != graph.LevelCore ||
		!got.CreatedAt.Equal(m.CreatedAt) || len(got.RecordCounts.Nodes) == 0 ||
		got.InstalledAt != in.Clock.Now() || got.AppliedDeltas == nil {
		t.Fatalf("bad state: %+v", got)
	}
	target, err := os.Readlink(in.p("current"))
	if err != nil || target != filepath.Join("snapshots", m.SnapshotID) {
		t.Fatalf("current -> %q, %v", target, err)
	}
	want := readEntries(t, pkg)[pack.FileGraphDB]
	have, err := os.ReadFile(in.p("current", "graph.db"))
	if err != nil || !bytes.Equal(want, have) {
		t.Fatalf("graph.db mismatch: %v", err)
	}
	if _, err := os.Stat(in.p("current", "manifest.json")); err != nil {
		t.Fatal(err)
	}
}

func TestInstallURLAndRetries(t *testing.T) {
	pkg, m := build(t, canonFile(t), time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC))
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			atomic.AddInt32(&calls, 1)
			http.Error(w, "boom", 500)
			return
		}
		http.ServeFile(w, r, pkg)
	}))
	defer srv.Close()
	in := newInstaller(t)
	st, err := in.Install(context.Background(), srv.URL+"/snap.tar.gz")
	if err != nil || st.InstalledID != m.SnapshotID {
		t.Fatalf("%v %+v", err, st)
	}
	if es, _ := os.ReadDir(in.p("downloads")); len(es) != 0 {
		t.Fatalf("downloads not cleaned: %v", es)
	}
	if _, err := in.Install(context.Background(), srv.URL+"/bad"); !errors.Is(err, ErrNetwork) {
		t.Fatalf("want ErrNetwork, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("attempts = %d, want 3", calls)
	}
	if s, _ := in.Status(); s.InstalledID != m.SnapshotID {
		t.Fatal("installed snapshot changed after failure")
	}
}

func TestTamperedLeavesPreviousUntouched(t *testing.T) {
	canon := canonFile(t)
	pkg1, m1 := build(t, canon, time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC))
	pkg2, _ := build(t, canon, time.Date(2024, 3, 2, 0, 0, 0, 0, time.UTC))
	in := newInstaller(t)
	if _, err := in.Install(context.Background(), pkg1); err != nil {
		t.Fatal(err)
	}
	before := hashOf(t, in.p("current", "graph.db"))
	e := readEntries(t, pkg2)
	e[pack.FileGraphDB][len(e[pack.FileGraphDB])/2] ^= 0xff
	bad := filepath.Join(t.TempDir(), "bad.tar.gz")
	writePkg(t, bad, e)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, bad) }))
	defer srv.Close()
	for _, src := range []string{bad, srv.URL + "/x"} {
		_, err := in.Install(context.Background(), src)
		var pe *pack.PackageError
		if !errors.As(err, &pe) {
			t.Fatalf("want PackageError, got %v", err)
		}
	}
	if d := snapDirs(t, in); len(d) != 1 || d[0] != m1.SnapshotID {
		t.Fatalf("snapshot dirs: %v", d)
	}
	if es, _ := os.ReadDir(in.p("downloads")); len(es) != 0 {
		t.Fatalf("download left behind: %v", es)
	}
	target, _ := os.Readlink(in.p("current"))
	if target != filepath.Join("snapshots", m1.SnapshotID) || hashOf(t, in.p("current", "graph.db")) != before {
		t.Fatal("installed snapshot changed")
	}
	if s, _ := in.Status(); s.InstalledID != m1.SnapshotID {
		t.Fatal("state changed")
	}
}

func TestUnsupportedSchema(t *testing.T) {
	pkg, _ := build(t, canonFile(t), time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC))
	in := newInstaller(t)
	for _, v := range []string{"2", "999", "x"} {
		_, err := in.Install(context.Background(), withSchema(t, pkg, v))
		if !errors.Is(err, ErrUnsupportedSchema) {
			t.Fatalf("version %s: %v", v, err)
		}
	}
	if _, err := in.Status(); !errors.Is(err, ErrNotInstalled) {
		t.Fatal("state written for unsupported schema")
	}
	if _, err := os.Stat(in.p("current")); err == nil {
		t.Fatal("current created")
	}
}

func TestReinstallIdempotentAndKeepsTwo(t *testing.T) {
	canon := canonFile(t)
	var pkgs []string
	var ids []string
	for i := 1; i <= 3; i++ {
		p, m := build(t, canon, time.Date(2024, 3, i, 0, 0, 0, 0, time.UTC))
		pkgs, ids = append(pkgs, p), append(ids, m.SnapshotID)
	}
	in := newInstaller(t)
	ctx := context.Background()
	if _, err := in.Install(ctx, pkgs[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Install(ctx, pkgs[0]); err != nil {
		t.Fatal(err)
	}
	if d := snapDirs(t, in); len(d) != 1 {
		t.Fatalf("after reinstall: %v", d)
	}
	if _, err := in.Install(ctx, pkgs[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Install(ctx, pkgs[1]); err != nil { // previous must survive
		t.Fatal(err)
	}
	if d := snapDirs(t, in); len(d) != 2 {
		t.Fatalf("want 2 dirs: %v", d)
	}
	if _, err := in.Install(ctx, pkgs[2]); err != nil {
		t.Fatal(err)
	}
	d := snapDirs(t, in)
	sort.Strings(d)
	if len(d) != 2 || d[0] != ids[1] || d[1] != ids[2] {
		t.Fatalf("want %v, got %v", ids[1:], d)
	}
	if s, _ := in.Status(); s.InstalledID != ids[2] {
		t.Fatal("wrong current")
	}
}

func TestExtractRejectsUnsafePaths(t *testing.T) {
	for _, name := range []string{"/graph.db", "../graph.db", "a/../graph.db"} {
		p := filepath.Join(t.TempDir(), "x.tar.gz")
		writePkg(t, p, map[string][]byte{name: []byte("x")})
		if _, err := extract(p, filepath.Join(t.TempDir(), "out")); err == nil {
			t.Fatalf("%q accepted", name)
		}
	}
}
