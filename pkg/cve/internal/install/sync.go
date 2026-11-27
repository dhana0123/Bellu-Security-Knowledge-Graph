package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/graph"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/pack"
)

// ErrConfirmationRequired is returned when a full snapshot download is needed
// and the caller declined (or gave no way to confirm).
var ErrConfirmationRequired = errors.New("install: full snapshot download requires confirmation")

// SyncOptions configures Sync.
type SyncOptions struct {
	// Confirm is called with the size in bytes and id of the full snapshot
	// before it is downloaded, when no delta chain exists. A nil Confirm
	// declines. The CLI passes an always-true function for --yes.
	Confirm func(sizeBytes int64, id string) bool
	// Threshold is passed to Apply (0 = DefaultThreshold).
	Threshold int
}

// SyncResult reports what Sync did.
type SyncResult struct {
	From          string   // installed id before the sync ("" when none)
	To            string   // installed id after the sync
	AppliedDeltas []string // target ids of the applied deltas, in order
	FullSnapshot  bool     // the full latest snapshot was installed
}

// Sync brings the installation up to date with the index at indexURL (a file
// path or http(s) URL).
//
// It follows the shortest delta chain (breadth first; ties broken by target
// id) from the installed id to the index's latest id, downloading each delta,
// checking its sha256 against the index and applying it. state.json is
// updated after every delta, so after a failure the last applied version
// stays active. Without a chain, or with nothing installed, Confirm is asked
// about the full snapshot; the installed snapshot is kept until the new one
// has verified. Network failures (30 s timeout, 3 attempts) return
// ErrNetwork. A sha256 mismatch returns *ChecksumError and changes nothing.
//
// The swap only renames the current symlink and keeps the previous snapshot
// directory, so SDK handles opened earlier keep reading the snapshot they
// opened; open a new handle (pkg/intel.OpenInstalled) to see the new one.
func (in *Installer) Sync(ctx context.Context, indexURL string, opts SyncOptions) (SyncResult, error) {
	var res SyncResult
	idx, err := in.loadIndex(ctx, indexURL)
	if err != nil {
		return res, err
	}
	st, stErr := in.Status()
	installed := stErr == nil
	if stErr != nil && !errors.Is(stErr, ErrNotInstalled) {
		return res, stErr
	}
	if installed {
		res.From = st.InstalledID
	}
	latest := idx.Latest
	if installed && !sameTarget(st, latest.Level, latest.Ecosystems) {
		var best *IndexSnapshot
		for i, s := range idx.Snapshots {
			if sameTarget(st, s.Level, s.Ecosystems) && (best == nil || s.CreatedAt.After(best.CreatedAt)) {
				best = &idx.Snapshots[i]
			}
		}
		if best != nil {
			latest = *best
		}
	}
	if latest.ID == "" {
		return res, errors.New("install: index has no latest snapshot")
	}
	if installed && st.InstalledID == latest.ID {
		res.To = latest.ID
		return res, nil
	}
	if installed {
		if chain, ok := findChain(idx.Deltas, st, latest.ID); ok {
			return in.applyChain(ctx, indexURL, idx, chain, latest, opts, res)
		}
	}
	if opts.Confirm == nil || !opts.Confirm(latest.Size, latest.ID) {
		return res, ErrConfirmationRequired
	}
	if err := in.installEntry(ctx, indexURL, latest); err != nil {
		return res, err
	}
	res.To, res.FullSnapshot = latest.ID, true
	return res, nil
}

func (in *Installer) applyChain(ctx context.Context, indexURL string, idx Index, chain []IndexDelta, latest IndexSnapshot, opts SyncOptions, res SyncResult) (SyncResult, error) {
	res.To = res.From
	for _, d := range chain {
		path, cleanup, err := in.fetchVerified(ctx, resolveURL(indexURL, d.URL), d.URL, d.SHA256)
		if err != nil {
			return res, err
		}
		ao := ApplyOptions{Threshold: opts.Threshold}
		for _, s := range idx.Snapshots {
			if s.ID == d.Target {
				ao.FullSnapshot = resolveURL(indexURL, s.URL)
			}
		}
		st, err := in.Apply(ctx, path, ao)
		cleanup()
		if err != nil {
			return res, err
		}
		res.To = st.InstalledID
		res.AppliedDeltas = append(res.AppliedDeltas, d.Target)
	}
	return res, nil
}

func (in *Installer) installEntry(ctx context.Context, indexURL string, s IndexSnapshot) error {
	path, cleanup, err := in.fetchVerified(ctx, resolveURL(indexURL, s.URL), s.URL, s.SHA256)
	if err != nil {
		return err
	}
	defer cleanup()
	_, err = in.Install(ctx, path)
	return err
}

// fetchVerified returns a local copy of src and checks its sha256.
func (in *Installer) fetchVerified(ctx context.Context, src, name, want string) (string, func(), error) {
	path, cleanup, err := in.fetch(ctx, src)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	got, err := hashFile(path)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	if !strings.EqualFold(got, want) {
		cleanup()
		return "", func() {}, &ChecksumError{File: name, Err: pack.ErrChecksum}
	}
	return path, cleanup, nil
}

func (in *Installer) loadIndex(ctx context.Context, indexURL string) (Index, error) {
	if in.DataDir == "" {
		return Index{}, errors.New("install: DataDir is required")
	}
	path, cleanup, err := in.fetch(ctx, indexURL)
	if err != nil {
		cleanup()
		return Index{}, err
	}
	defer cleanup()
	b, err := os.ReadFile(path)
	if err != nil {
		return Index{}, err
	}
	var idx Index
	if err := json.Unmarshal(b, &idx); err != nil {
		return Index{}, fmt.Errorf("install: reading index: %w", err)
	}
	return idx, nil
}

// resolveURL resolves ref against the index location.
func resolveURL(indexURL, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	if strings.HasPrefix(indexURL, "http://") || strings.HasPrefix(indexURL, "https://") {
		base, err := url.Parse(indexURL)
		r, err2 := url.Parse(ref)
		if err != nil || err2 != nil {
			return ref
		}
		return base.ResolveReference(r).String()
	}
	if filepath.IsAbs(ref) {
		return ref
	}
	return filepath.Join(filepath.Dir(indexURL), filepath.FromSlash(ref))
}

func sameTarget(st State, level graph.Level, eco []string) bool {
	return st.Level == level && sameSet(st.Ecosystems, eco)
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// findChain returns the shortest delta path from the installed id to target.
func findChain(deltas []IndexDelta, st State, target string) ([]IndexDelta, bool) {
	next := map[string][]IndexDelta{}
	for _, d := range deltas {
		if d.Level != "" && d.Level != st.Level {
			continue
		}
		if d.Ecosystems != nil && !sameSet(d.Ecosystems, st.Ecosystems) {
			continue
		}
		next[d.Base] = append(next[d.Base], d)
	}
	for k := range next {
		sort.Slice(next[k], func(i, j int) bool { return next[k][i].Target < next[k][j].Target })
	}
	prev := map[string]IndexDelta{}
	seen := map[string]bool{st.InstalledID: true}
	queue := []string{st.InstalledID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, d := range next[cur] {
			if seen[d.Target] {
				continue
			}
			seen[d.Target] = true
			prev[d.Target] = d
			if d.Target == target {
				var out []IndexDelta
				for id := target; id != st.InstalledID; id = prev[id].Base {
					out = append([]IndexDelta{prev[id]}, out...)
				}
				return out, true
			}
			queue = append(queue, d.Target)
		}
	}
	return nil, false
}
