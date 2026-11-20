package baseline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/bellu/bskg/internal/httpx"
)

// ObjectStore reads objects from a bucket. Implementations return errors that
// are worth retrying wrapped with httpx.Retryable.
type ObjectStore interface {
	Get(ctx context.Context, bucket, key string) (io.ReadCloser, error)
}

// ChecksumError reports a file whose SHA-256 differs from the manifest.
type ChecksumError struct {
	File     string
	Expected string
	Actual   string
}

func (e *ChecksumError) Error() string {
	return fmt.Sprintf("baseline file %s: checksum mismatch: expected %s, actual %s", e.File, e.Expected, e.Actual)
}

// MissingFileError reports a file that is absent from the local override directory.
type MissingFileError struct {
	File string
	Dir  string
}

func (e *MissingFileError) Error() string {
	return fmt.Sprintf("baseline file %s is missing from directory %s", e.File, e.Dir)
}

// Fetcher makes the eight baseline files available locally and verified.
type Fetcher struct {
	Store    ObjectStore // used when LocalDir is empty
	LocalDir string      // BSKG_BASELINE_DIR override; no object store contact
	CacheDir string
	Retry    httpx.Policy
	Clock    httpx.Clock
	Log      *slog.Logger
}

// Fetch verifies or downloads every manifest file and returns logical name to
// local path. It touches no graph. On any failure no path map is returned, so
// a caller never starts loading with an unverified file set.
func (f *Fetcher) Fetch(ctx context.Context, m *Manifest) (map[string]string, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	log := f.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	paths := make(map[string]string, len(m.Files))
	for _, mf := range m.Files {
		var p string
		var err error
		if f.LocalDir != "" {
			p, err = f.local(mf)
		} else {
			p, err = f.cached(ctx, m, mf, log)
		}
		if err != nil {
			return nil, err
		}
		log.Info("baseline file verified", "file", mf.ScriptName)
		paths[mf.Logical] = p
	}
	return paths, nil
}

func (f *Fetcher) local(mf ManifestFile) (string, error) {
	p := filepath.Join(f.LocalDir, mf.ScriptName)
	got, err := hashFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return "", &MissingFileError{File: mf.ScriptName, Dir: f.LocalDir}
	}
	if err != nil {
		return "", fmt.Errorf("baseline file %s: %w", mf.ScriptName, err)
	}
	if !strings.EqualFold(got, mf.SHA256) {
		return "", &ChecksumError{File: mf.ScriptName, Expected: strings.ToLower(mf.SHA256), Actual: got}
	}
	return p, nil
}

func (f *Fetcher) cached(ctx context.Context, m *Manifest, mf ManifestFile, log *slog.Logger) (string, error) {
	if f.Store == nil {
		return "", errors.New("baseline: no object store configured")
	}
	if err := os.MkdirAll(f.CacheDir, 0o750); err != nil {
		return "", fmt.Errorf("baseline cache: %w", err)
	}
	dst := filepath.Join(f.CacheDir, mf.ScriptName)
	if got, err := hashFile(dst); err == nil {
		if strings.EqualFold(got, mf.SHA256) {
			return dst, nil
		}
		log.Warn("cached baseline file does not match manifest; downloading again", "file", mf.ScriptName)
		_ = os.Remove(dst)
	}
	part := dst + ".part"
	err := httpx.Do(ctx, f.Retry, f.Clock, func(int) error {
		return f.download(ctx, m.Bucket.Name, mf.Key, part)
	})
	if err != nil {
		_ = os.Remove(part)
		return "", fmt.Errorf("baseline file %s: download failed: %w", mf.ScriptName, err)
	}
	got, err := hashFile(part)
	if err != nil {
		_ = os.Remove(part)
		return "", fmt.Errorf("baseline file %s: %w", mf.ScriptName, err)
	}
	if !strings.EqualFold(got, mf.SHA256) {
		_ = os.Remove(part)
		return "", &ChecksumError{File: mf.ScriptName, Expected: strings.ToLower(mf.SHA256), Actual: got}
	}
	if err := os.Rename(part, dst); err != nil {
		return "", fmt.Errorf("baseline file %s: %w", mf.ScriptName, err)
	}
	return dst, nil
}

func (f *Fetcher) download(ctx context.Context, bucket, key, part string) error {
	rc, err := f.Store.Get(ctx, bucket, key)
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil {
		_ = out.Close()
		return httpx.Retryable(err)
	}
	return out.Close()
}

func hashFile(p string) (string, error) {
	fh, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
