package baseline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bellu/bskg/internal/httpx"
)

type fakeStore struct {
	objs  map[string][]byte
	fails map[string]int // transient failures before success
	gets  int
}

func (s *fakeStore) Get(_ context.Context, _, key string) (io.ReadCloser, error) {
	s.gets++
	if s.fails[key] > 0 {
		s.fails[key]--
		return nil, httpx.Retryable(errors.New("boom"))
	}
	b, ok := s.objs[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

type noSleep struct{ slept []time.Duration }

func (c *noSleep) Now() time.Time { return time.Unix(0, 0) }
func (c *noSleep) Sleep(_ context.Context, d time.Duration) error {
	c.slept = append(c.slept, d)
	return nil
}

func testManifest(t *testing.T) (*Manifest, map[string][]byte) {
	t.Helper()
	m := &Manifest{
		Upstream: Upstream{Repo: "r", Commit: "1111111111111111111111111111111111111111", CopiedOn: "2024-01-02"},
		Bucket:   BucketRef{Name: "b", Prefix: "vulkg/x/"},
	}
	data := map[string][]byte{}
	repo := map[string]string{
		LogicalHasExploit:         "import/Vulnerabiliy_HAS_EXPLOIT_Exploit_relationship.csv",
		LogicalDomainRelationship: "import/DomainNodes_Vulnerabiliy_HAS_REFERENCE_Domain_relationship.csv",
	}
	for _, l := range RequiredLogicalFiles {
		rn := repo[l]
		if rn == "" {
			rn = "import/" + l + ".csv"
		}
		sn := ScriptNameFor(rn)
		content := []byte("content of " + l)
		sum := sha256.Sum256(content)
		key := "vulkg/x/" + sn
		data[key] = content
		m.Files = append(m.Files, ManifestFile{Logical: l, RepoName: rn, ScriptName: sn, Key: key,
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(content))})
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	return m, data
}

func TestFetchDownloadsAndCaches(t *testing.T) {
	m, data := testManifest(t)
	st := &fakeStore{objs: data}
	f := &Fetcher{Store: st, CacheDir: t.TempDir(), Retry: httpx.DownloadPolicy, Clock: &noSleep{}}
	paths, err := f.Fetch(context.Background(), m)
	if err != nil || len(paths) != 8 {
		t.Fatalf("paths=%d err=%v", len(paths), err)
	}
	if st.gets != 8 {
		t.Fatalf("gets=%d", st.gets)
	}
	if _, err := f.Fetch(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if st.gets != 8 {
		t.Fatalf("cache not used, gets=%d", st.gets)
	}
	matches, _ := filepath.Glob(filepath.Join(f.CacheDir, "*.part"))
	if len(matches) != 0 {
		t.Fatalf("leftover part files: %v", matches)
	}
}

func TestFetchRetriesWithBackoff(t *testing.T) {
	m, data := testManifest(t)
	key := m.Files[0].Key
	clk := &noSleep{}
	f := &Fetcher{Store: &fakeStore{objs: data, fails: map[string]int{key: 3}}, CacheDir: t.TempDir(), Retry: httpx.DownloadPolicy, Clock: clk}
	if _, err := f.Fetch(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	if len(clk.slept) != 3 || clk.slept[0] != want[0] || clk.slept[1] != want[1] || clk.slept[2] != want[2] {
		t.Fatalf("slept=%v", clk.slept)
	}
	f2 := &Fetcher{Store: &fakeStore{objs: data, fails: map[string]int{key: 4}}, CacheDir: t.TempDir(), Retry: httpx.DownloadPolicy, Clock: &noSleep{}}
	if _, err := f2.Fetch(context.Background(), m); err == nil {
		t.Fatal("expected failure after retries")
	}
}

func TestFetchChecksumMismatchDeletesAndReports(t *testing.T) {
	m, data := testManifest(t)
	bad := m.Files[2]
	data[bad.Key] = []byte("tampered")
	f := &Fetcher{Store: &fakeStore{objs: data}, CacheDir: t.TempDir(), Retry: httpx.DownloadPolicy, Clock: &noSleep{}}
	paths, err := f.Fetch(context.Background(), m)
	var ce *ChecksumError
	if !errors.As(err, &ce) || paths != nil {
		t.Fatalf("err=%v paths=%v", err, paths)
	}
	sum := sha256.Sum256([]byte("tampered"))
	if ce.File != bad.ScriptName || ce.Expected != bad.SHA256 || ce.Actual != hex.EncodeToString(sum[:]) {
		t.Fatalf("bad error: %+v", ce)
	}
	for _, n := range []string{bad.ScriptName, bad.ScriptName + ".part"} {
		if _, err := os.Stat(filepath.Join(f.CacheDir, n)); !os.IsNotExist(err) {
			t.Fatalf("%s should not exist", n)
		}
	}
}

func TestFetchReplacesCorruptCacheEntry(t *testing.T) {
	m, data := testManifest(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, m.Files[0].ScriptName), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{Store: &fakeStore{objs: data}, CacheDir: dir, Retry: httpx.DownloadPolicy, Clock: &noSleep{}}
	if _, err := f.Fetch(context.Background(), m); err != nil {
		t.Fatal(err)
	}
}

func TestFetchLocalDir(t *testing.T) {
	m, data := testManifest(t)
	dir := t.TempDir()
	for _, mf := range m.Files {
		if err := os.WriteFile(filepath.Join(dir, mf.ScriptName), data[mf.Key], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f := &Fetcher{LocalDir: dir} // no store: no object store contact
	if paths, err := f.Fetch(context.Background(), m); err != nil || len(paths) != 8 {
		t.Fatalf("err=%v", err)
	}
	// Missing file.
	missing := m.Files[3].ScriptName
	_ = os.Remove(filepath.Join(dir, missing))
	var me *MissingFileError
	if _, err := f.Fetch(context.Background(), m); !errors.As(err, &me) || me.File != missing {
		t.Fatalf("err=%v", err)
	}
	// Corrupt file is reported and left in place.
	_ = os.WriteFile(filepath.Join(dir, missing), []byte("x"), 0o600)
	var ce *ChecksumError
	if _, err := f.Fetch(context.Background(), m); !errors.As(err, &ce) || ce.File != missing {
		t.Fatalf("err=%v", err)
	}
}
