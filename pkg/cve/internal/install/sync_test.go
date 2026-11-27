package install

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/pack"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/intel"
)

// publishDir copies the chain's packages into a served directory and writes index.json.
func publishDir(t *testing.T, c chain) (string, Index) {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"snapshots", "deltas"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cp := func(src, dst string) {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, dst), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for i, p := range c.pkg {
		cp(p, filepath.Join("snapshots", c.man[i].SnapshotID+".tar.gz"))
	}
	cp(c.delta[0], "deltas/d0.tar.gz")
	cp(c.delta[1], "deltas/d1.tar.gz")
	idx, err := WriteIndex(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	return dir, idx
}

func TestBuildIndex(t *testing.T) {
	c := buildChain(t)
	_, idx := publishDir(t, c)
	if len(idx.Snapshots) != 3 || len(idx.Deltas) != 2 || idx.Latest.ID != c.man[2].SnapshotID {
		t.Fatalf("%+v", idx)
	}
	for _, d := range idx.Deltas {
		if d.SHA256 == "" || d.Size == 0 || d.URL == "" {
			t.Fatalf("%+v", d)
		}
	}
	if _, err := BuildIndex(t.TempDir(), ""); err == nil {
		t.Fatal("empty dir accepted")
	}
}

func TestSyncDeltaChain(t *testing.T) {
	c := buildChain(t)
	dir, _ := publishDir(t, c)
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()
	in := installS(t, c)
	old, err := intel.OpenInstalled(in.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	res, err := in.Sync(context.Background(), srv.URL+"/index.json", SyncOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.From != c.man[0].SnapshotID || res.To != c.man[2].SnapshotID || res.FullSnapshot ||
		len(res.AppliedDeltas) != 2 || res.AppliedDeltas[0] != c.man[1].SnapshotID {
		t.Fatalf("%+v", res)
	}
	st, _ := in.Status()
	if st.InstalledID != c.man[2].SnapshotID || len(st.AppliedDeltas) != 2 {
		t.Fatalf("%+v", st)
	}
	// Old handle still answers; new handle sees the new snapshot.
	if _, err := old.GetVulnerability(context.Background(), "nonexistent-id"); err != nil && !errors.Is(err, intel.ErrNotFound) {
		t.Fatalf("old handle: %v", err)
	}
	nw, err := intel.OpenInstalled(in.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Close()
	if _, err := nw.GetVulnerability(context.Background(), "nonexistent-id"); err != nil && !errors.Is(err, intel.ErrNotFound) {
		t.Fatalf("new handle: %v", err)
	}
	// Already latest: no-op.
	res, err = in.Sync(context.Background(), filepath.Join(dir, "index.json"), SyncOptions{})
	if err != nil || res.To != c.man[2].SnapshotID || len(res.AppliedDeltas) != 0 || res.FullSnapshot {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestSyncFullSnapshotConfirmation(t *testing.T) {
	c := buildChain(t)
	dir, idx := publishDir(t, c)
	index := filepath.Join(dir, "index.json")
	in := newInstaller(t)
	var gotSize int64
	_, err := in.Sync(context.Background(), index, SyncOptions{Confirm: func(n int64, id string) bool { gotSize = n; return false }})
	if !errors.Is(err, ErrConfirmationRequired) || gotSize != idx.Latest.Size || gotSize == 0 {
		t.Fatalf("%v %d", err, gotSize)
	}
	if _, err := in.Status(); !errors.Is(err, ErrNotInstalled) {
		t.Fatal("installed after decline")
	}
	if _, err := in.Sync(context.Background(), index, SyncOptions{}); !errors.Is(err, ErrConfirmationRequired) {
		t.Fatal(err)
	}
	res, err := in.Sync(context.Background(), index, SyncOptions{Confirm: func(int64, string) bool { return true }})
	if err != nil || !res.FullSnapshot || res.To != c.man[2].SnapshotID {
		t.Fatalf("%+v %v", res, err)
	}
	if st, _ := in.Status(); st.InstalledID != c.man[2].SnapshotID {
		t.Fatalf("%+v", st)
	}
}

func TestSyncChecksumMismatch(t *testing.T) {
	c := buildChain(t)
	dir, idx := publishDir(t, c)
	idx.Deltas[0].SHA256 = "00" + idx.Deltas[0].SHA256[2:]
	if err := writeJSON(filepath.Join(dir, "index.json"), idx); err != nil {
		t.Fatal(err)
	}
	in := installS(t, c)
	h := hashOf(t, in.p("current", pack.FileGraphDB))
	_, err := in.Sync(context.Background(), filepath.Join(dir, "index.json"), SyncOptions{})
	var ce *ChecksumError
	if !errors.As(err, &ce) || ce.File != idx.Deltas[0].URL || !errors.Is(err, pack.ErrChecksum) {
		t.Fatalf("%v", err)
	}
	assertUntouched(t, in, c.man[0].SnapshotID, h)
}

func TestSyncNetworkFailureKeepsLastApplied(t *testing.T) {
	c := buildChain(t)
	dir, idx := publishDir(t, c)
	var hits int32
	fs := http.FileServer(http.Dir(dir))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if "/"+idx.Deltas[1].URL == r.URL.Path {
			atomic.AddInt32(&hits, 1)
			http.Error(w, "boom", 500)
			return
		}
		fs.ServeHTTP(w, r)
	}))
	defer srv.Close()
	in := installS(t, c)
	res, err := in.Sync(context.Background(), srv.URL+"/index.json", SyncOptions{})
	if !errors.Is(err, ErrNetwork) || hits != MaxAttempts {
		t.Fatalf("%v hits=%d", err, hits)
	}
	if res.To != c.man[1].SnapshotID || len(res.AppliedDeltas) != 1 {
		t.Fatalf("%+v", res)
	}
	if st, _ := in.Status(); st.InstalledID != c.man[1].SnapshotID {
		t.Fatalf("%+v", st)
	}
}

func writeJSON(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o644)
}
