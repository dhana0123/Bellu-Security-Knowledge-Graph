package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Adopt makes a snapshot directory that was built elsewhere under DataDir
// (typically a staging directory on the same filesystem) the current snapshot.
// st describes it. The directory is renamed into snapshots/<id>, state.json is
// written, current is swapped atomically, and snapshots other than the new and
// the previous one are removed.
//
// If the commit is interrupted after state.json is written and before the
// swap, Reconcile completes it.
func (in *Installer) Adopt(dir string, st State) error {
	if in.DataDir == "" {
		return errors.New("install: DataDir is required")
	}
	if st.InstalledID == "" {
		return errors.New("install: adopt: empty snapshot id")
	}
	old, oldErr := in.Status()
	if oldErr == nil && old.InstalledID == st.InstalledID {
		return fmt.Errorf("install: adopt: snapshot %s is already current", st.InstalledID)
	}
	snaps := in.p("snapshots")
	if err := os.MkdirAll(snaps, 0o755); err != nil {
		return err
	}
	final := filepath.Join(snaps, st.InstalledID)
	if err := os.RemoveAll(final); err != nil {
		return err
	}
	if err := os.Rename(dir, final); err != nil {
		return err
	}
	if err := syncDir(snaps); err != nil {
		return err
	}
	st.PreviousID = ""
	if oldErr == nil {
		st.PreviousID = old.InstalledID
	}
	if st.InstalledAt.IsZero() {
		st.InstalledAt = in.now()
	}
	if err := in.writeState(st); err != nil {
		return err
	}
	if err := in.swapCurrent(st.InstalledID); err != nil {
		// Keep state.json consistent with current.
		if oldErr == nil {
			_ = in.writeState(old)
		} else {
			_ = os.Remove(in.p("state.json"))
		}
		return err
	}
	in.prune(st)
	return nil
}

// Reconcile completes an interrupted Adopt: when state.json names a snapshot
// whose directory exists but current points elsewhere, it swaps current. It
// also removes leftover .partial directories. It returns whether it swapped.
func (in *Installer) Reconcile() (bool, error) {
	if entries, err := os.ReadDir(in.p("snapshots")); err == nil {
		for _, e := range entries {
			if filepath.Ext(e.Name()) == ".partial" {
				_ = os.RemoveAll(in.p("snapshots", e.Name()))
			}
		}
	}
	st, err := in.Status()
	if errors.Is(err, ErrNotInstalled) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	want := filepath.Join("snapshots", st.InstalledID)
	if got, err := os.Readlink(in.p("current")); err == nil && got == want {
		return false, nil
	}
	if _, err := os.Stat(in.p("snapshots", st.InstalledID, "graph.db")); err != nil {
		return false, fmt.Errorf("install: state names %s but its snapshot directory is unusable: %w", st.InstalledID, err)
	}
	if err := in.swapCurrent(st.InstalledID); err != nil {
		return false, err
	}
	in.prune(st)
	return true, nil
}
