// Package install installs Bellu snapshot packages into a local data
// directory and tracks the installed state.
//
// Data directory layout:
//
//	<data-dir>/snapshots/<id>/graph.db, manifest.json
//	<data-dir>/current -> snapshots/<id>   (relative symlink)
//	<data-dir>/state.json
//	<data-dir>/downloads/                  (temporary downloads)
//
// The current symlink requires a POSIX filesystem; Windows is not supported.
package install

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/graph"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/pack"
)

// Network policy for URL sources.
const (
	RequestTimeout = 30 * time.Second
	MaxAttempts    = 3
)

// Errors.
var (
	ErrNotInstalled      = errors.New("install: no snapshot installed")
	ErrUnsupportedSchema = errors.New("install: unsupported schema version")
	ErrNetwork           = errors.New("install: network error")
)

// Clock supplies the current time.
type Clock interface{ Now() time.Time }

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

// AppliedDelta records one applied delta package.
type AppliedDelta struct {
	Base      string    `json:"base"`
	Target    string    `json:"target"`
	AppliedAt time.Time `json:"applied_at"`
}

// State is the content of state.json.
type State struct {
	InstalledID   string            `json:"installed_id"`
	PreviousID    string            `json:"previous_id,omitempty"`
	Level         graph.Level       `json:"level"`
	Ecosystems    []string          `json:"ecosystems"`
	CreatedAt     time.Time         `json:"created_at"`
	RecordCounts  pack.RecordCounts `json:"record_counts"`
	AppliedDeltas []AppliedDelta    `json:"applied_deltas"`
	InstalledAt   time.Time         `json:"installed_at"`
}

// Installer installs snapshots into DataDir.
type Installer struct {
	DataDir string
	HTTP    *http.Client // nil: client with a 30 s connect and response-header timeout
	Clock   Clock        // nil: wall clock
	// Sleep waits between download attempts; nil uses a context-aware timer
	// with 1 s, 2 s backoff.
	Sleep func(ctx context.Context, d time.Duration) error

	// PreSwap, when set, is called with the fully built but not yet renamed
	// snapshot directory (graph.db and manifest.json) before it becomes a
	// snapshot. An error aborts the install and removes the directory.
	PreSwap func(ctx context.Context, dir string) error
	// applyHook is a test seam called at named steps of Apply.
	applyHook func(step string) error
}

func (in *Installer) now() time.Time {
	if in.Clock != nil {
		return in.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

func (in *Installer) client() *http.Client {
	if in.HTTP != nil {
		return in.HTTP
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: RequestTimeout}).DialContext,
		TLSHandshakeTimeout:   RequestTimeout,
		ResponseHeaderTimeout: RequestTimeout,
	}}
}

func (in *Installer) p(parts ...string) string {
	return filepath.Join(append([]string{in.DataDir}, parts...)...)
}

// Status returns the installed state, or ErrNotInstalled.
func (in *Installer) Status() (State, error) {
	b, err := os.ReadFile(in.p("state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return State{}, ErrNotInstalled
	}
	if err != nil {
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, fmt.Errorf("install: reading state.json: %w", err)
	}
	if s.InstalledID == "" {
		return State{}, ErrNotInstalled
	}
	return s, nil
}

// Install fetches src (a file path or http(s) URL), verifies it and makes it
// the current snapshot. On failure the installed snapshot is untouched and
// any download is deleted.
func (in *Installer) Install(ctx context.Context, src string) (State, error) {
	if in.DataDir == "" {
		return State{}, errors.New("install: DataDir is required")
	}
	pkgPath := src
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		dl := in.p("downloads")
		if err := os.MkdirAll(dl, 0o755); err != nil {
			return State{}, err
		}
		tmp, err := in.download(ctx, src, dl)
		if tmp != "" {
			defer os.Remove(tmp)
		}
		if err != nil {
			return State{}, err
		}
		pkgPath = tmp
	}
	m, err := pack.VerifyPackage(pkgPath)
	if err != nil {
		return State{}, err
	}
	if err := checkSchema(m.SchemaVersion); err != nil {
		return State{}, err
	}
	snaps := in.p("snapshots")
	if err := os.MkdirAll(snaps, 0o755); err != nil {
		return State{}, err
	}
	partial := filepath.Join(snaps, m.SnapshotID+".partial")
	final := filepath.Join(snaps, m.SnapshotID)
	_ = os.RemoveAll(partial)
	dbSum, err := extract(pkgPath, partial)
	if err != nil {
		_ = os.RemoveAll(partial)
		return State{}, err
	}
	if err := in.preSwap(ctx, partial); err != nil {
		_ = os.RemoveAll(partial)
		return State{}, err
	}
	// Reuse an existing identical snapshot directory (idempotent reinstall).
	if cur, err := hashFile(filepath.Join(final, pack.FileGraphDB)); err == nil && cur == dbSum {
		_ = os.RemoveAll(partial)
	} else {
		_ = os.RemoveAll(final)
		if err := os.Rename(partial, final); err != nil {
			_ = os.RemoveAll(partial)
			return State{}, err
		}
		if err := syncDir(snaps); err != nil {
			return State{}, err
		}
	}

	old, oldErr := in.Status()
	st := State{
		InstalledID:   m.SnapshotID,
		Level:         m.DistributionLevel,
		Ecosystems:    append([]string{}, m.Ecosystems...),
		CreatedAt:     m.CreatedAt,
		RecordCounts:  m.RecordCounts,
		AppliedDeltas: []AppliedDelta{},
		InstalledAt:   in.now(),
	}
	if oldErr == nil {
		if old.InstalledID != st.InstalledID {
			st.PreviousID = old.InstalledID
		} else {
			st.PreviousID = old.PreviousID
		}
	}
	if err := in.writeState(st); err != nil {
		return State{}, err
	}
	if err := in.swapCurrent(m.SnapshotID); err != nil {
		return State{}, err
	}
	in.prune(st)
	return st, nil
}

func (in *Installer) preSwap(ctx context.Context, dir string) error {
	if in.PreSwap == nil {
		return nil
	}
	if err := in.PreSwap(ctx, dir); err != nil {
		return fmt.Errorf("install: pre-swap check: %w", err)
	}
	return nil
}

func checkSchema(v string) error {
	n, err := strconv.Atoi(v)
	max, _ := strconv.Atoi(graph.SchemaVersion)
	if err != nil || n < 1 || n > max {
		return fmt.Errorf("%w: %q (this build supports up to %d)", ErrUnsupportedSchema, v, max)
	}
	return nil
}

func (in *Installer) download(ctx context.Context, url, dir string) (string, error) {
	var last error
	for attempt := 1; attempt <= MaxAttempts; attempt++ {
		if attempt > 1 {
			d := time.Duration(1<<(attempt-2)) * time.Second
			var err error
			if in.Sleep != nil {
				err = in.Sleep(ctx, d)
			} else {
				t := time.NewTimer(d)
				select {
				case <-ctx.Done():
					err = ctx.Err()
				case <-t.C:
				}
				t.Stop()
			}
			if err != nil {
				return "", err
			}
		}
		tmp, retry, err := in.downloadOnce(ctx, url, dir)
		if err == nil {
			return tmp, nil
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		last = err
		if !retry {
			break
		}
	}
	return "", fmt.Errorf("%w: %v", ErrNetwork, last)
}

// downloadOnce returns the temp file path (also on error, so the caller can
// remove it), whether a retry is sensible, and the error.
func (in *Installer) downloadOnce(ctx context.Context, url, dir string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false, err
	}
	resp, err := in.client().Do(req)
	if err != nil {
		return "", true, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		retry := resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
		return "", retry, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	f, err := os.CreateTemp(dir, "download-*.tar.gz")
	if err != nil {
		return "", false, err
	}
	name := f.Name()
	_, err = io.Copy(f, resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(name)
		return "", true, err
	}
	return name, false, nil
}

// extract writes graph.db and manifest.json from an already verified package
// into dir, re-checking entry names and the graph.db checksum. It returns the
// graph.db sha256.
func extract(pkgPath, dir string) (string, error) {
	f, err := os.Open(pkgPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	zr, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return "", err
	}
	defer zr.Close()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	tr := tar.NewReader(zr)
	var dbSum, listed string
	var haveManifest bool
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if h.Name == "" || path.IsAbs(h.Name) || strings.HasPrefix(h.Name, "/") ||
			strings.Contains(h.Name, "\\") || path.Clean(h.Name) != h.Name {
			return "", fmt.Errorf("install: unsafe tar entry %q", h.Name)
		}
		for _, seg := range strings.Split(h.Name, "/") {
			if seg == ".." {
				return "", fmt.Errorf("install: unsafe tar entry %q", h.Name)
			}
		}
		if h.Typeflag != tar.TypeReg {
			return "", fmt.Errorf("install: tar entry %q is not a regular file", h.Name)
		}
		switch h.Name {
		case pack.FileChecksums:
			b, err := io.ReadAll(io.LimitReader(tr, 1<<20))
			if err != nil {
				return "", err
			}
			for _, line := range strings.Split(string(b), "\n") {
				if len(line) > 66 && line[66:] == pack.FileGraphDB {
					listed = line[:64]
				}
			}
		case pack.FileGraphDB, pack.FileManifest:
			sum, err := writeFile(filepath.Join(dir, h.Name), tr)
			if err != nil {
				return "", err
			}
			if h.Name == pack.FileGraphDB {
				dbSum = sum
			} else {
				haveManifest = true
			}
		}
	}
	if dbSum == "" || !haveManifest || dbSum != listed {
		return "", errors.New("install: package is missing graph.db or manifest.json, or graph.db checksum changed")
	}
	if err := syncDir(dir); err != nil {
		return "", err
	}
	return dbSum, nil
}

func writeFile(p string, r io.Reader) (string, error) {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), r)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func syncDir(d string) error {
	f, err := os.Open(d)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

func (in *Installer) writeState(s State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := in.p("state.json.tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, in.p("state.json")); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(in.DataDir)
}

func (in *Installer) swapCurrent(id string) error {
	tmp := in.p("current.new")
	_ = os.Remove(tmp)
	if err := os.Symlink(filepath.Join("snapshots", id), tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, in.p("current")); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(in.DataDir)
}

// prune keeps the current and previous snapshot directories only.
func (in *Installer) prune(s State) {
	entries, err := os.ReadDir(in.p("snapshots"))
	if err != nil {
		return
	}
	for _, e := range entries {
		if n := e.Name(); n != s.InstalledID && n != s.PreviousID {
			_ = os.RemoveAll(in.p("snapshots", n))
		}
	}
}
