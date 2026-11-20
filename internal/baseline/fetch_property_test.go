package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bellu/bskg/internal/httpx"
	"pgregory.net/rapid"
)

// Feature: bellu-security-knowledge-graph, Property 25: Checksum verification
// **Validates: Requirements 3.4, 3.5**
func TestPropertyChecksumVerification(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		content := rapid.SliceOfN(rapid.Byte(), 0, 512).Draw(rt, "content")
		match := rapid.Bool().Draw(rt, "match")
		useLocal := rapid.Bool().Draw(rt, "local")
		other := rapid.SliceOfN(rapid.Byte(), 1, 64).Draw(rt, "other")

		m, data := testManifest(&testing.T{})
		target := rapid.IntRange(0, len(m.Files)-1).Draw(rt, "target")
		mf := &m.Files[target]
		want := sha256.Sum256(content)
		if !match {
			// Manifest hash for different content (guaranteed different from content's hash).
			o := sha256.Sum256(append(append([]byte{}, content...), other...))
			want = o
		}
		mf.SHA256 = hex.EncodeToString(want[:])
		actual := sha256.Sum256(content)
		actualHex := hex.EncodeToString(actual[:])

		dir := t.TempDir()
		f := &Fetcher{Retry: httpx.DownloadPolicy, Clock: &noSleep{}}
		var filePath string
		if useLocal {
			f.LocalDir = filepath.Join(dir, "local")
			filePath = filepath.Join(f.LocalDir, mf.ScriptName)
			for _, x := range m.Files {
				c := data[x.Key]
				if x.Logical == mf.Logical {
					c = content
				} else {
					sum := sha256.Sum256(c)
					_ = sum
				}
				if err := os.MkdirAll(f.LocalDir, 0o750); err != nil {
					rt.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(f.LocalDir, x.ScriptName), c, 0o640); err != nil {
					rt.Fatal(err)
				}
			}
		} else {
			f.CacheDir = filepath.Join(dir, "cache")
			filePath = filepath.Join(f.CacheDir, mf.ScriptName)
			data[mf.Key] = content
			f.Store = &fakeStore{objs: data, fails: map[string]int{}}
		}

		paths, err := f.Fetch(t.Context(), m)
		if match {
			if err != nil {
				rt.Fatalf("matching hash rejected: %v", err)
			}
			if paths[mf.Logical] != filePath {
				rt.Fatalf("path %q, want %q", paths[mf.Logical], filePath)
			}
			return
		}
		var ce *ChecksumError
		if !errors.As(err, &ce) {
			rt.Fatalf("want ChecksumError, got %v", err)
		}
		if paths != nil {
			rt.Fatal("paths returned on failure")
		}
		if ce.File != mf.ScriptName || ce.Expected != mf.SHA256 || ce.Actual != actualHex {
			rt.Fatalf("bad error fields: %+v", ce)
		}
		if msg := err.Error(); !strings.Contains(msg, ce.Expected) || !strings.Contains(msg, ce.Actual) {
			rt.Fatalf("message lacks hashes: %s", msg)
		}
		if !useLocal {
			// Downloaded file and partial file must both be gone.
			for _, p := range []string{filePath, filePath + ".part"} {
				if _, serr := os.Stat(p); !errors.Is(serr, os.ErrNotExist) {
					rt.Fatalf("%s remains after mismatch", p)
				}
			}
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 26: Manifest validation
// (file set: exactly the eight logical files once each)
// **Validates: Requirements 3.1, 24.6**
func TestPropertyManifestFileSet(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		m := validManifest()
		switch rapid.IntRange(0, 3).Draw(rt, "mutation") {
		case 0: // remove one file
			i := rapid.IntRange(0, len(m.Files)-1).Draw(rt, "i")
			m.Files = append(m.Files[:i], m.Files[i+1:]...)
		case 1: // duplicate one file
			i := rapid.IntRange(0, len(m.Files)-1).Draw(rt, "i")
			m.Files = append(m.Files, m.Files[i])
		case 2: // unknown logical name
			i := rapid.IntRange(0, len(m.Files)-1).Draw(rt, "i")
			m.Files[i].Logical = rapid.StringMatching(`Unknown[A-Za-z]{1,8}`).Draw(rt, "name")
		case 3: // order permutation stays valid
			i := rapid.IntRange(0, len(m.Files)-1).Draw(rt, "i")
			j := rapid.IntRange(0, len(m.Files)-1).Draw(rt, "j")
			m.Files[i], m.Files[j] = m.Files[j], m.Files[i]
			if err := m.Validate(); err != nil {
				rt.Fatalf("permutation rejected: %v", err)
			}
			return
		}
		if err := m.Validate(); err == nil {
			rt.Fatalf("manifest with wrong file set accepted (%d files)", len(m.Files))
		}
	})
}
