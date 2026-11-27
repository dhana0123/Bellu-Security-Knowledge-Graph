package install

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/pack"
)

// Delta size threshold: deltas with more changed records than the threshold
// are replaced by a full snapshot install.
const (
	DefaultThreshold = 100_000
	MinThreshold     = 1
	MaxThreshold     = 100_000_000
)

// ErrBaseMismatch is matched (errors.Is) by *BaseMismatchError.
var ErrBaseMismatch = errors.New("install: delta base does not match the installed snapshot")

// BaseMismatchError reports a delta whose base is not the installed snapshot.
type BaseMismatchError struct {
	Expected string // base snapshot id the delta needs
	Actual   string // installed snapshot id
}

func (e *BaseMismatchError) Error() string {
	return fmt.Sprintf("install: delta requires base %s but %s is installed", e.Expected, e.Actual)
}

// Is makes errors.Is(err, ErrBaseMismatch) true.
func (e *BaseMismatchError) Is(target error) bool { return target == ErrBaseMismatch }

// ChecksumError reports a delta file whose checksum does not match.
type ChecksumError struct {
	File string
	Err  error
}

func (e *ChecksumError) Error() string {
	return fmt.Sprintf("install: checksum mismatch in %s", e.File)
}

// Unwrap keeps errors.Is(err, pack.ErrChecksum) true.
func (e *ChecksumError) Unwrap() error { return e.Err }

// ApplyOptions configures Apply.
type ApplyOptions struct {
	// Threshold is the changed-record count above which the full target
	// snapshot is installed instead. 0 means DefaultThreshold.
	Threshold int
	// FullSnapshot is the path or URL of the target full snapshot package,
	// required when the delta exceeds the threshold.
	FullSnapshot string
}

// Apply applies the delta package src (path or URL) to the installed
// snapshot. On any failure before the swap the installed snapshot and
// state.json are untouched and the partial directory is removed.
func (in *Installer) Apply(ctx context.Context, src string, opts ApplyOptions) (State, error) {
	if in.DataDir == "" {
		return State{}, errors.New("install: DataDir is required")
	}
	th := opts.Threshold
	if th == 0 {
		th = DefaultThreshold
	}
	if th < MinThreshold || th > MaxThreshold {
		return State{}, fmt.Errorf("install: threshold %d out of range %d..%d", th, MinThreshold, MaxThreshold)
	}
	step := func(name string, err error) error {
		var ce *ChecksumError
		var be *BaseMismatchError
		if errors.As(err, &ce) || errors.As(err, &be) {
			return err
		}
		return fmt.Errorf("install: apply step %q: %w", name, err)
	}

	pkgPath, cleanup, err := in.fetch(ctx, src)
	if err != nil {
		return State{}, step("fetch", err)
	}
	defer cleanup()

	dm, err := pack.VerifyDelta(pkgPath)
	if err != nil {
		var pe *pack.PackageError
		if errors.Is(err, pack.ErrChecksum) && errors.As(err, &pe) {
			return State{}, &ChecksumError{File: pe.File, Err: err}
		}
		return State{}, step("verify", err)
	}
	if err := checkSchema(dm.SchemaVersion); err != nil {
		return State{}, err
	}
	old, err := in.Status()
	if err != nil {
		return State{}, err
	}
	if dm.BaseSnapshotID != old.InstalledID {
		return State{}, &BaseMismatchError{Expected: dm.BaseSnapshotID, Actual: old.InstalledID}
	}

	if dm.Counts.ChangedRecords > int64(th) {
		return in.applyFull(ctx, dm, opts.FullSnapshot)
	}

	snaps := in.p("snapshots")
	partial := filepath.Join(snaps, dm.TargetSnapshotID+".partial")
	final := filepath.Join(snaps, dm.TargetSnapshotID)
	_ = os.RemoveAll(partial)
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(partial)
		}
	}()

	if err := os.MkdirAll(partial, 0o755); err != nil {
		return State{}, step("prepare", err)
	}
	dbPath := filepath.Join(partial, pack.FileGraphDB)
	if err := copyFile(in.p("current", pack.FileGraphDB), dbPath); err != nil {
		return State{}, step("copy", err)
	}
	if err := in.applyToDB(ctx, pkgPath, dbPath, dm); err != nil {
		return State{}, err
	}
	if err := in.hook("verify"); err != nil {
		return State{}, step("verify-target", err)
	}
	if err := verifyTarget(ctx, dbPath, dm); err != nil {
		return State{}, step("verify-target", err)
	}
	if err := writeTargetManifest(partial, dbPath, dm); err != nil {
		return State{}, step("manifest", err)
	}
	if err := fsyncFile(dbPath); err != nil {
		return State{}, step("fsync", err)
	}
	if err := syncDir(partial); err != nil {
		return State{}, step("fsync", err)
	}
	if err := in.preSwap(ctx, partial); err != nil {
		return State{}, err
	}
	if err := in.hook("rename"); err != nil {
		return State{}, step("rename", err)
	}
	if _, err := os.Stat(final); err == nil {
		if err := os.RemoveAll(final); err != nil {
			return State{}, step("rename", err)
		}
	}
	if err := os.Rename(partial, final); err != nil {
		return State{}, step("rename", err)
	}
	committed = true // the directory is now a complete snapshot, not a partial
	if err := syncDir(snaps); err != nil {
		return State{}, step("rename", err)
	}

	st := State{
		InstalledID:  dm.TargetSnapshotID,
		PreviousID:   old.InstalledID,
		Level:        dm.DistributionLevel,
		Ecosystems:   append([]string{}, dm.Ecosystems...),
		CreatedAt:    dm.CreatedAt,
		RecordCounts: dm.RecordCounts,
		AppliedDeltas: append(append([]AppliedDelta{}, old.AppliedDeltas...),
			AppliedDelta{Base: old.InstalledID, Target: dm.TargetSnapshotID, AppliedAt: in.now()}),
		InstalledAt: in.now(),
	}
	if err := in.writeState(st); err != nil {
		return State{}, step("state", err)
	}
	if err := in.swapCurrent(st.InstalledID); err != nil {
		return State{}, step("swap", err)
	}
	in.prune(st)
	return st, nil
}

func (in *Installer) hook(step string) error {
	if in.applyHook != nil {
		return in.applyHook(step)
	}
	return nil
}

// applyFull installs the full target snapshot in place of an oversized delta.
func (in *Installer) applyFull(ctx context.Context, dm pack.DeltaManifest, full string) (State, error) {
	if full == "" {
		return State{}, fmt.Errorf("install: delta changes %d records, above the threshold; a full snapshot (FullSnapshot) is required", dm.Counts.ChangedRecords)
	}
	pkg, cleanup, err := in.fetch(ctx, full)
	if err != nil {
		return State{}, fmt.Errorf("install: apply step %q: %w", "fetch-full", err)
	}
	defer cleanup()
	m, err := pack.VerifyPackage(pkg)
	if err != nil {
		return State{}, fmt.Errorf("install: apply step %q: %w", "verify-full", err)
	}
	if m.SnapshotID != dm.TargetSnapshotID {
		return State{}, fmt.Errorf("install: full snapshot %s is not the delta target %s", m.SnapshotID, dm.TargetSnapshotID)
	}
	return in.Install(ctx, pkg)
}

// fetch returns a local path for src, downloading URLs into downloads/.
func (in *Installer) fetch(ctx context.Context, src string) (string, func(), error) {
	if !(strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://")) {
		return src, func() {}, nil
	}
	dl := in.p("downloads")
	if err := os.MkdirAll(dl, 0o755); err != nil {
		return "", nil, err
	}
	tmp, err := in.download(ctx, src, dl)
	if tmp != "" {
		return tmp, func() { _ = os.Remove(tmp) }, err
	}
	return "", func() {}, err
}

// applyToDB applies delta.jsonl to dbPath in one transaction and updates meta.
func (in *Installer) applyToDB(ctx context.Context, pkgPath, dbPath string, dm pack.DeltaManifest) (err error) {
	step := func(name string, err error) error {
		return fmt.Errorf("install: apply step %q: %w", name, err)
	}
	ops, err := openEntry(pkgPath, pack.FileDelta)
	if err != nil {
		return step("read-ops", err)
	}
	defer ops.Close()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return step("open", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return step("begin", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = pack.ApplyOps(ctx, tx, ops); err != nil {
		return step("apply-ops", err)
	}
	if err = in.hook("after-ops"); err != nil {
		return step("apply-ops", err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE meta SET value=? WHERE key='created_at'`,
		dm.CreatedAt.UTC().Format("2006-01-02T15:04:05Z")); err != nil {
		return step("meta", err)
	}
	if err = tx.Commit(); err != nil {
		return step("commit", err)
	}
	if err = db.Close(); err != nil {
		return step("close", err)
	}
	return nil
}

// verifyTarget checks the applied database against the delta manifest.
func verifyTarget(ctx context.Context, dbPath string, dm pack.DeltaManifest) error {
	d, err := pack.LogicalDigest(dbPath)
	if err != nil {
		return err
	}
	if d != dm.LogicalDigest {
		return fmt.Errorf("logical digest %s does not match expected %s", d, dm.LogicalDigest)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	for table, want := range map[string]map[string]int64{"nodes": dm.RecordCounts.Nodes, "edges": dm.RecordCounts.Edges} {
		got := map[string]int64{}
		rows, err := db.QueryContext(ctx, `SELECT type, COUNT(*) FROM `+table+` GROUP BY type`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var t string
			var n int64
			if err := rows.Scan(&t, &n); err != nil {
				rows.Close()
				return err
			}
			got[t] = n
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for t, n := range want {
			if got[t] != n {
				return fmt.Errorf("%s count for %q is %d, expected %d", table, t, got[t], n)
			}
			delete(got, t)
		}
		for t, n := range got {
			if n != 0 {
				return fmt.Errorf("%s count for %q is %d, expected 0", table, t, n)
			}
		}
	}
	return nil
}

// writeTargetManifest writes manifest.json for a delta-built snapshot.
func writeTargetManifest(dir, dbPath string, dm pack.DeltaManifest) error {
	engine, version, err := metaEngine(dbPath)
	if err != nil {
		return err
	}
	m := struct {
		pack.Manifest
		BuiltFromDelta string `json:"built_from_delta"`
	}{
		Manifest: pack.Manifest{
			Product:           pack.Product,
			SnapshotID:        dm.TargetSnapshotID,
			SchemaVersion:     dm.SchemaVersion,
			DatabaseEngine:    engine,
			EngineVersion:     version,
			CreatedAt:         dm.CreatedAt,
			DistributionLevel: dm.DistributionLevel,
			Ecosystems:        dm.Ecosystems,
			RecordCounts:      dm.RecordCounts,
			LogicalDigest:     dm.LogicalDigest,
		},
		BuiltFromDelta: dm.BaseSnapshotID,
	}
	if m.Ecosystems == nil {
		m.Ecosystems = []string{}
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	_, err = writeFile(filepath.Join(dir, pack.FileManifest), strings.NewReader(string(b)+"\n"))
	return err
}

func metaEngine(dbPath string) (engine, version string, err error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return "", "", err
	}
	defer db.Close()
	if err = db.QueryRow(`SELECT value FROM meta WHERE key='engine'`).Scan(&engine); err != nil {
		return "", "", err
	}
	if err = db.QueryRow(`SELECT value FROM meta WHERE key='engine_version'`).Scan(&version); err != nil {
		return "", "", err
	}
	return engine, version, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

func fsyncFile(p string) error {
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

type entryReader struct {
	io.Reader
	closers []io.Closer
}

func (e *entryReader) Close() error {
	for _, c := range e.closers {
		_ = c.Close()
	}
	return nil
}

// openEntry streams the named entry of a tar.gz package.
func openEntry(pkg, name string) (io.ReadCloser, error) {
	f, err := os.Open(pkg)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		f.Close()
		return nil, err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			zr.Close()
			f.Close()
			return nil, fmt.Errorf("%s not found in %s", name, filepath.Base(pkg))
		}
		if err != nil {
			zr.Close()
			f.Close()
			return nil, err
		}
		if h.Name == name {
			return &entryReader{Reader: tr, closers: []io.Closer{zr, f}}, nil
		}
	}
}
