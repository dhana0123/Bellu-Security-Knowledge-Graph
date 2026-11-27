package pack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/graph"
)

// SnapshotOptions configures BuildSnapshot.
type SnapshotOptions struct {
	CanonicalPath string
	OutDir        string
	Level         graph.Level // core, ecosystem or complete
	Ecosystems    []string
	History       bool
	Clock         graph.Clock // nil means wall clock
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

type fixedClock time.Time

func (c fixedClock) Now() time.Time { return time.Time(c) }

// BuildSnapshot projects the canonical store into a snapshot package in OutDir.
// The canonical store is opened read-only. The package is written as
// <name>.partial, verified, then renamed; on any error nothing is left behind.
func BuildSnapshot(ctx context.Context, opts SnapshotOptions) (string, Manifest, error) {
	switch opts.Level {
	case graph.LevelCore, graph.LevelEcosystem, graph.LevelComplete:
	default:
		return "", Manifest{}, fmt.Errorf("%w: %q", graph.ErrUnknownLevel, string(opts.Level))
	}
	if opts.OutDir == "" || opts.CanonicalPath == "" {
		return "", Manifest{}, errors.New("pack: CanonicalPath and OutDir are required")
	}
	eco := dedupeSorted(opts.Ecosystems)
	if len(eco) > MaxEcosystems {
		return "", Manifest{}, fmt.Errorf("pack: %d ecosystems exceeds %d", len(eco), MaxEcosystems)
	}
	for _, e := range eco {
		if e == "" {
			return "", Manifest{}, errors.New("pack: empty ecosystem name")
		}
	}
	clk := opts.Clock
	if clk == nil {
		clk = wallClock{}
	}
	created := clk.Now().UTC().Truncate(time.Second)

	work, err := os.MkdirTemp("", "bellu-pack-*")
	if err != nil {
		return "", Manifest{}, err
	}
	defer os.RemoveAll(work)
	dbPath := filepath.Join(work, FileGraphDB)

	proj := &graph.Projector{
		CanonicalPath: opts.CanonicalPath,
		Policy:        graph.Policy{Level: opts.Level, Ecosystems: eco},
		Sinks:         []graph.NamedSink{{Name: "sqlite", Sink: graph.NewSQLiteSink(dbPath)}},
		History:       opts.History,
		Engine:        graph.Engine,
		Clock:         fixedClock(created),
	}
	if _, err := proj.Run(ctx); err != nil {
		return "", Manifest{}, err
	}

	m, stats, err := inspectGraphDB(ctx, dbPath, opts.Level)
	if err != nil {
		return "", Manifest{}, err
	}
	m.CreatedAt = created
	m.Ecosystems = eco
	if m.Ecosystems == nil {
		m.Ecosystems = []string{}
	}
	m.SnapshotID = SnapshotIDFor(created, m.LogicalDigest)
	m.Product = Product

	sources, err := sourceCounts(ctx, opts.CanonicalPath)
	if err != nil {
		return "", Manifest{}, err
	}

	files := map[string][]byte{}
	if files[FileManifest], err = marshal(m); err != nil {
		return "", Manifest{}, err
	}
	if files[FileSources], err = marshal(map[string]any{"sources": sources}); err != nil {
		return "", Manifest{}, err
	}
	if files[FileSchemaVer], err = marshal(map[string]string{"schema_version": m.SchemaVersion}); err != nil {
		return "", Manifest{}, err
	}
	if files[FileStatistics], err = marshal(stats); err != nil {
		return "", Manifest{}, err
	}
	sums := map[string]string{}
	for n, b := range files {
		s := sha256.Sum256(b)
		sums[n] = hex.EncodeToString(s[:])
	}
	if sums[FileGraphDB], err = hashFile(dbPath); err != nil {
		return "", Manifest{}, err
	}
	files[FileChecksums] = formatChecksums(sums)

	if err := ctx.Err(); err != nil {
		return "", Manifest{}, err
	}
	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return "", Manifest{}, err
	}
	final := filepath.Join(opts.OutDir, fmt.Sprintf("bellu-%s-%s.tar.gz", opts.Level, m.SnapshotID))
	partial := final + ".partial"
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(partial)
		}
	}()
	if err := writeTarGz(partial, files, dbPath, created); err != nil {
		return "", Manifest{}, err
	}
	got, err := VerifyPackage(partial)
	if err != nil {
		return "", Manifest{}, fmt.Errorf("pack: verifying built package: %w", err)
	}
	if got.SnapshotID != m.SnapshotID || got.LogicalDigest != m.LogicalDigest {
		return "", Manifest{}, errors.New("pack: built package manifest differs from expected")
	}
	if err := os.Rename(partial, final); err != nil {
		return "", Manifest{}, err
	}
	ok = true
	if d, err := os.Open(opts.OutDir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return final, got, nil
}

func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func marshal(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
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

func roURI(p string) string {
	u := url.URL{Scheme: "file", Opaque: (&url.URL{Path: p}).EscapedPath(), RawQuery: "mode=ro"}
	return u.String()
}

type statistics struct {
	Nodes      map[string]int64 `json:"nodes"`
	Edges      map[string]int64 `json:"edges"`
	TotalNodes int64            `json:"total_nodes"`
	TotalEdges int64            `json:"total_edges"`
}

// inspectGraphDB reads meta, per-type counts and the logical digest.
func inspectGraphDB(ctx context.Context, p string, level graph.Level) (Manifest, statistics, error) {
	var m Manifest
	st := statistics{Nodes: map[string]int64{}, Edges: map[string]int64{}}
	db, err := sql.Open("sqlite", roURI(p))
	if err != nil {
		return m, st, err
	}
	defer db.Close()
	meta := map[string]string{}
	rows, err := db.QueryContext(ctx, `SELECT key, value FROM meta`)
	if err != nil {
		return m, st, err
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return m, st, err
		}
		meta[k] = v
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return m, st, err
	}
	rows.Close()
	m.SchemaVersion, m.DatabaseEngine, m.EngineVersion = meta["schema_version"], meta["engine"], meta["engine_version"]
	m.DistributionLevel = level

	for _, t := range graph.NodeTypesFor(level) {
		st.Nodes[t] = 0
	}
	for _, t := range graph.EdgeTypesFor(level) {
		st.Edges[t] = 0
	}
	for table, dst := range map[string]map[string]int64{"nodes": st.Nodes, "edges": st.Edges} {
		r, err := db.QueryContext(ctx, `SELECT type, COUNT(*) FROM `+table+` GROUP BY type`)
		if err != nil {
			return m, st, err
		}
		for r.Next() {
			var ty string
			var n int64
			if err := r.Scan(&ty, &n); err != nil {
				r.Close()
				return m, st, err
			}
			dst[ty] = n
		}
		if err := r.Err(); err != nil {
			r.Close()
			return m, st, err
		}
		r.Close()
	}
	for _, n := range st.Nodes {
		st.TotalNodes += n
	}
	for _, n := range st.Edges {
		st.TotalEdges += n
	}
	m.RecordCounts = RecordCounts{Nodes: st.Nodes, Edges: st.Edges}

	// Logical digest: sorted lines "edge\t<h>" then "node\t<h>" (sorted overall).
	dg := sha256.New()
	for _, kind := range []struct{ name, table string }{{"edge", "edges"}, {"node", "nodes"}} {
		r, err := db.QueryContext(ctx, `SELECT h FROM `+kind.table+` ORDER BY h`)
		if err != nil {
			return m, st, err
		}
		for r.Next() {
			var h string
			if err := r.Scan(&h); err != nil {
				r.Close()
				return m, st, err
			}
			fmt.Fprintf(dg, "%s\t%s\n", kind.name, h)
		}
		if err := r.Err(); err != nil {
			r.Close()
			return m, st, err
		}
		r.Close()
	}
	m.LogicalDigest = hex.EncodeToString(dg.Sum(nil))
	return m, st, nil
}

type sourceInfo struct {
	Source string `json:"source"`
	Count  int64  `json:"count"`
}

func sourceCounts(ctx context.Context, canonicalPath string) ([]sourceInfo, error) {
	store, err := canonical.OpenReadOnly(canonicalPath)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	rows, err := store.DB.QueryContext(ctx, `SELECT source, COUNT(*) FROM source_record GROUP BY source ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []sourceInfo{}
	for rows.Next() {
		var s sourceInfo
		if err := rows.Scan(&s.Source, &s.Count); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func writeTarGz(dest string, files map[string][]byte, dbPath string, mtime time.Time) (err error) {
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = f.Close()
		}
	}()
	zw := gzip.NewWriter(f) // header has no name or mtime
	tw := tar.NewWriter(zw)
	names := append([]string(nil), SnapshotFiles...)
	sort.Strings(names)
	for _, n := range names {
		var size int64
		var src io.Reader
		if n == FileGraphDB {
			g, err := os.Open(dbPath)
			if err != nil {
				return err
			}
			defer g.Close()
			fi, err := g.Stat()
			if err != nil {
				return err
			}
			size, src = fi.Size(), g
		} else {
			b := files[n]
			size, src = int64(len(b)), bytesReader(b)
		}
		hdr := &tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: size, ModTime: mtime, Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := io.Copy(tw, src); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
