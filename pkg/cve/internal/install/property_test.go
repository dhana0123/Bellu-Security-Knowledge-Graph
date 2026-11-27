package install

import (
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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/pack"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/intel"
)

// copyTree copies dir src to dst, preserving symlinks.
func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			l, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(l, target)
		case fi.IsDir():
			return os.MkdirAll(target, 0o755)
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(target, b, 0o644)
		}
	})
}

// queryAnswer returns a comparable rendering of GetVulnerability(id).
func queryAnswer(dataDir, id string) (string, error) {
	c, err := intel.OpenInstalled(dataDir)
	if err != nil {
		return "", err
	}
	defer c.Close()
	return answerOf(c, id)
}

func answerOf(c intel.Client, id string) (string, error) {
	v, err := c.GetVulnerability(context.Background(), id)
	if errors.Is(err, intel.ErrNotFound) {
		return "not-found", nil
	}
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(v)
	return string(b), err
}

type snapshotView struct {
	link, dbHash, state, answer string
	dirs                        []string
}

func viewOf(dataDir string) (snapshotView, error) {
	var v snapshotView
	var err error
	if v.link, err = os.Readlink(filepath.Join(dataDir, "current")); err != nil {
		return v, err
	}
	if v.dbHash, err = hashFile(filepath.Join(dataDir, "current", pack.FileGraphDB)); err != nil {
		return v, err
	}
	b, err := os.ReadFile(filepath.Join(dataDir, "state.json"))
	if err != nil {
		return v, err
	}
	v.state = string(b)
	if v.answer, err = queryAnswer(dataDir, "CVE-2024-3000"); err != nil {
		return v, err
	}
	es, err := os.ReadDir(filepath.Join(dataDir, "snapshots"))
	if err != nil {
		return v, err
	}
	for _, e := range es {
		if strings.HasSuffix(e.Name(), ".partial") {
			return v, fmt.Errorf("partial left: %s", e.Name())
		}
		v.dirs = append(v.dirs, e.Name())
	}
	return v, nil
}

// Feature: bellu-security-knowledge-graph, Property 33: Atomic update leaves the installed snapshot intact
// **Validates: Requirements 11.3, 11.4, 11.5, 11.6, 11.9, 13.4, 23.4**
func TestPropertyAtomicUpdateLeavesSnapshotIntact(t *testing.T) {
	c := buildChain(t)
	base := installS(t, c)
	baseDir := base.DataDir

	// Corrupted inputs, built once.
	e := readEntries(t, c.delta[0])
	e[pack.FileDelta] = bytes.Replace(e[pack.FileDelta], []byte("\"summary\":\""), []byte("\"summary\":\"x"), 1)
	tampered := filepath.Join(t.TempDir(), "tampered.tar.gz")
	writePkg(t, tampered, e)
	raw, err := os.ReadFile(c.delta[0])
	if err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(t.TempDir(), "truncated.tar.gz")
	if err := os.WriteFile(truncated, raw[:len(raw)/2], 0o644); err != nil {
		t.Fatal(err)
	}
	// Server that announces the full body but sends only half of it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(raw)))
		_, _ = w.Write(raw[:len(raw)/2])
	}))
	defer srv.Close()

	before, err := viewOf(baseDir)
	if err != nil {
		t.Fatal(err)
	}

	cases := []string{"after-ops", "verify", "rename", "tampered", "wrong-base", "truncated-file", "truncated-download"}
	rapid.Check(t, func(rt *rapid.T) {
		kind := rapid.SampledFrom(cases).Draw(rt, "failure")
		dir := filepath.Join(t.TempDir(), "data")
		if err := copyTree(baseDir, dir); err != nil {
			rt.Fatal(err)
		}
		in := &Installer{DataDir: dir, Clock: base.Clock, Sleep: base.Sleep}
		src := c.delta[0]
		switch kind {
		case "after-ops", "verify", "rename":
			in.applyHook = func(s string) error {
				if s == kind {
					return errors.New("injected")
				}
				return nil
			}
		case "tampered":
			src = tampered
		case "wrong-base":
			src = c.delta[1]
		case "truncated-file":
			src = truncated
		case "truncated-download":
			src = srv.URL + "/d.tar.gz"
		}
		_, err := in.Apply(context.Background(), src, ApplyOptions{})
		if err == nil {
			rt.Fatalf("%s: want error", kind)
		}
		switch kind {
		case "after-ops", "verify", "rename":
			if !strings.Contains(err.Error(), "install: apply step") {
				rt.Fatalf("error does not name the step: %v", err)
			}
		case "tampered":
			var ce *ChecksumError
			if !errors.As(err, &ce) || ce.File != pack.FileDelta {
				rt.Fatalf("want ChecksumError for %s: %v", pack.FileDelta, err)
			}
		case "wrong-base":
			if !errors.Is(err, ErrBaseMismatch) {
				rt.Fatalf("want base mismatch: %v", err)
			}
		case "truncated-download":
			if !errors.Is(err, ErrNetwork) {
				rt.Fatalf("want network error: %v", err)
			}
		}
		after, err := viewOf(dir)
		if err != nil {
			rt.Fatal(err)
		}
		if after.link != before.link || after.dbHash != before.dbHash || after.state != before.state ||
			after.answer != before.answer || strings.Join(after.dirs, ",") != strings.Join(before.dirs, ",") {
			rt.Fatalf("%s: installed snapshot changed\nbefore %+v\nafter  %+v", kind, before, after)
		}
		if es, _ := os.ReadDir(filepath.Join(dir, "downloads")); len(es) != 0 {
			rt.Fatalf("download left behind: %v", es)
		}
	})
}

// A query running concurrently with Apply sees exactly one version: the S
// answer or the T answer, never an error or a mixed state.
func TestQueryDuringSwapSeesOneVersion(t *testing.T) {
	c := buildChain(t)
	ids := []string{"CVE-2024-3000", "GHSA-bridge-0003", "NVD-DISAGREE-1000"}
	answers := func(pkg string) map[string]string {
		in := newInstaller(t)
		if _, err := in.Install(context.Background(), pkg); err != nil {
			t.Fatal(err)
		}
		m := map[string]string{}
		for _, id := range ids {
			a, err := queryAnswer(in.DataDir, id)
			if err != nil {
				t.Fatal(err)
			}
			m[id] = a
		}
		return m
	}
	sAns, tAns := answers(c.pkg[0]), answers(c.pkg[1])
	diff := false
	for _, id := range ids {
		diff = diff || sAns[id] != tAns[id]
	}
	if !diff {
		t.Fatal("fixture S and T answers are identical; test would prove nothing")
	}

	in := installS(t, c)
	old, err := intel.OpenInstalled(in.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()

	var done atomic.Bool
	var wg sync.WaitGroup
	var applyErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer done.Store(true)
		_, applyErr = in.Apply(context.Background(), c.delta[0], ApplyOptions{})
	}()
	check := func(cl intel.Client, id, who string) {
		a, err := answerOf(cl, id)
		if err != nil {
			t.Errorf("%s %s: %v", who, id, err)
		} else if a != sAns[id] && a != tAns[id] {
			t.Errorf("%s %s: answer matches neither S nor T", who, id)
		}
	}
	n := 0
	for !done.Load() || n < 20 {
		for _, id := range ids {
			check(old, id, "old handle")
		}
		if fresh, err := intel.OpenInstalled(in.DataDir); err != nil {
			t.Errorf("reopen: %v", err)
		} else {
			for _, id := range ids {
				check(fresh, id, "fresh handle")
			}
			fresh.Close()
		}
		n++
	}
	wg.Wait()
	if applyErr != nil {
		t.Fatal(applyErr)
	}
	for _, id := range ids {
		if a, err := queryAnswer(in.DataDir, id); err != nil || a != tAns[id] {
			t.Fatalf("after apply %s: want T answer, got %v", id, err)
		}
	}
}

func TestSyncTimeoutIsNetworkError(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
		_, _ = io.WriteString(w, "{}")
	}))
	defer srv.Close()
	in := newInstaller(t)
	in.HTTP = &http.Client{Timeout: 50 * time.Millisecond}
	_, err := in.Sync(context.Background(), srv.URL+"/index.json", SyncOptions{})
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("want ErrNetwork, got %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != MaxAttempts {
		t.Fatalf("attempts %d, want %d", got, MaxAttempts)
	}
	if _, err := in.Status(); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("status after failed sync: %v", err)
	}
}

func TestStatusFieldsAfterApply(t *testing.T) {
	c := buildChain(t)
	in := installS(t, c)
	if _, err := in.Apply(context.Background(), c.delta[0], ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	st, err := in.Status()
	if err != nil {
		t.Fatal(err)
	}
	m := c.man[1]
	if st.InstalledID != m.SnapshotID || st.PreviousID != c.man[0].SnapshotID || st.Level != m.DistributionLevel ||
		!st.CreatedAt.Equal(m.CreatedAt) || st.InstalledAt.IsZero() || len(st.AppliedDeltas) != 1 ||
		st.AppliedDeltas[0].AppliedAt.IsZero() {
		t.Fatalf("status %+v", st)
	}
}
