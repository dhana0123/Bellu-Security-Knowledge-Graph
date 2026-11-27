package pack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/osv"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/graph"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

type tclock struct{ t time.Time }

func (c tclock) Now() time.Time { return c.t }

func canonFile(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	st, err := canonical.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "graph", "snapshot_U.json"))
	if err != nil {
		t.Fatal(err)
	}
	var docs []json.RawMessage
	if err := json.Unmarshal(data, &docs); err != nil {
		t.Fatal(err)
	}
	for _, d := range docs {
		rec, err := osv.Parse("osv", d)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.UpsertRecord(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	mod := time.Date(2024, 2, 11, 0, 0, 0, 0, time.UTC)
	if _, err := st.UpsertRecord(ctx, &model.Record{Source: "nvd", ID: "CVE-2024-1000", Summary: "x", Published: mod, Modified: mod,
		Affected: []model.Affected{{Kind: "package", Ecosystem: "npm", Name: "fix-pkg", Versions: []string{"1.0.0"}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Resolve(ctx, canonical.ResolveOptions{}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "canonical.db")
	if _, err := st.DB.Exec(`VACUUM INTO ?`, p); err != nil {
		t.Fatal(err)
	}
	return p
}

func fileHash(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return string(s[:])
}

func readEntries(t *testing.T, p string) map[string][]byte {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = b
	}
}

func writePkg(t *testing.T, p string, entries map[string][]byte, hdr func(*tar.Header)) {
	t.Helper()
	var names []string
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	for _, n := range names {
		h := &tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(entries[n]))}
		if hdr != nil {
			hdr(h)
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write(entries[n])
	}
	tw.Close()
	zw.Close()
}

func build(t *testing.T, canon string, lvl graph.Level, at time.Time) (string, Manifest) {
	t.Helper()
	p, m, err := BuildSnapshot(context.Background(), SnapshotOptions{
		CanonicalPath: canon, OutDir: filepath.Join(t.TempDir(), "out"), Level: lvl, Clock: tclock{at},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, m
}

func TestBuildAndVerify(t *testing.T) {
	canon := canonFile(t)
	at := time.Date(2024, 5, 1, 12, 30, 45, 0, time.UTC)
	for _, lvl := range []graph.Level{graph.LevelCore, graph.LevelEcosystem, graph.LevelComplete} {
		p, m := build(t, canon, lvl, at)
		if !strings.HasPrefix(filepath.Base(p), "bellu-"+string(lvl)+"-20240501T123045Z-") || !strings.HasSuffix(p, ".tar.gz") {
			t.Fatalf("name %s", p)
		}
		if _, err := VerifyPackage(p); err != nil {
			t.Fatal(err)
		}
		ents := readEntries(t, p)
		var names []string
		for n := range ents {
			names = append(names, n)
		}
		sort.Strings(names)
		if strings.Join(names, ",") != strings.Join(SnapshotFiles, ",") {
			t.Fatalf("entries %v", names)
		}
		if m.Product != Product || m.DistributionLevel != lvl || m.SchemaVersion != graph.SchemaVersion ||
			m.DatabaseEngine != graph.Engine || m.EngineVersion == "" || !m.CreatedAt.Equal(at) {
			t.Fatalf("manifest %+v", m)
		}
		// counts match graph.db
		dbp := filepath.Join(t.TempDir(), "g.db")
		os.WriteFile(dbp, ents[FileGraphDB], 0o644)
		db, _ := sql.Open("sqlite", dbp)
		defer db.Close()
		var total int64
		for _, c := range m.RecordCounts.Nodes {
			total += c
		}
		var n int64
		db.QueryRow(`SELECT COUNT(*) FROM nodes`).Scan(&n)
		if n != total || total == 0 {
			t.Fatalf("%s node count %d vs %d", lvl, n, total)
		}
		for ty, c := range m.RecordCounts.Edges {
			var e int64
			db.QueryRow(`SELECT COUNT(*) FROM edges WHERE type=?`, ty).Scan(&e)
			if e != c {
				t.Fatalf("edge %s %d vs %d", ty, e, c)
			}
		}
		var s struct {
			Sources []sourceInfo `json:"sources"`
		}
		if err := json.Unmarshal(ents[FileSources], &s); err != nil || len(s.Sources) == 0 {
			t.Fatalf("sources %v %s", err, ents[FileSources])
		}
	}
}

func TestDeterministicLogicalContent(t *testing.T) {
	canon := canonFile(t)
	p1, m1 := build(t, canon, graph.LevelComplete, time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC))
	p2, m2 := build(t, canon, graph.LevelComplete, time.Date(2025, 6, 2, 3, 4, 5, 0, time.UTC))
	if m1.LogicalDigest != m2.LogicalDigest || m1.SnapshotID == m2.SnapshotID ||
		m1.SnapshotID[16:] != m2.SnapshotID[16:] {
		t.Fatalf("%+v %+v", m1, m2)
	}
	if !equalJSON(m1.RecordCounts, m2.RecordCounts) {
		t.Fatal("counts differ")
	}
	e1, e2 := readEntries(t, p1), readEntries(t, p2)
	d1, d2 := filepath.Join(t.TempDir(), "a.db"), filepath.Join(t.TempDir(), "b.db")
	os.WriteFile(d1, e1[FileGraphDB], 0o644)
	os.WriteFile(d2, e2[FileGraphDB], 0o644)
	for _, q := range []string{`SELECT id,type,props,h FROM nodes ORDER BY id`, `SELECT id,type,src,dst,props,h FROM edges ORDER BY id`} {
		if a, b := dump(t, d1, q), dump(t, d2, q); a != b {
			t.Fatal("rows differ")
		}
	}
	// same clock gives byte-identical archives except graph.db meta is identical too
	p3, _ := build(t, canon, graph.LevelComplete, time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC))
	if fileHash(t, p1) != fileHash(t, p3) {
		t.Fatal("same inputs and clock should give identical bytes")
	}
}

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func dump(t *testing.T, p, q string) string {
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var sb strings.Builder
	for rows.Next() {
		v := make([]string, len(cols))
		ptr := make([]any, len(cols))
		for i := range v {
			ptr[i] = &v[i]
		}
		rows.Scan(ptr...)
		sb.WriteString(strings.Join(v, "\x00") + "\n")
	}
	return sb.String()
}

func TestUnsupportedLevelWritesNothing(t *testing.T) {
	canon := canonFile(t)
	out := filepath.Join(t.TempDir(), "out")
	for _, lvl := range []graph.Level{"", "bogus"} {
		_, _, err := BuildSnapshot(context.Background(), SnapshotOptions{CanonicalPath: canon, OutDir: out, Level: lvl})
		if !errors.Is(err, graph.ErrUnknownLevel) {
			t.Fatalf("level %q: %v", lvl, err)
		}
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("OutDir was created")
	}
}

func TestFailureLeavesNoFilesAndCanonicalUnchanged(t *testing.T) {
	canon := canonFile(t)
	before := fileHash(t, canon)
	out := t.TempDir()
	_, _, err := BuildSnapshot(context.Background(), SnapshotOptions{CanonicalPath: filepath.Join(t.TempDir(), "missing.db"), OutDir: out, Level: graph.LevelCore})
	if err == nil {
		t.Fatal("expected error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := BuildSnapshot(ctx, SnapshotOptions{CanonicalPath: canon, OutDir: out, Level: graph.LevelCore}); err == nil {
		t.Fatal("expected cancel error")
	}
	if ents, _ := os.ReadDir(out); len(ents) != 0 {
		t.Fatalf("leftover files: %v", ents)
	}
	if fileHash(t, canon) != before {
		t.Fatal("canonical changed")
	}
	// success also leaves canonical untouched and no partial
	p, _ := build(t, canon, graph.LevelCore, time.Now())
	if _, err := os.Stat(p + ".partial"); !os.IsNotExist(err) {
		t.Fatal("partial remains")
	}
	if fileHash(t, canon) != before {
		t.Fatal("canonical changed after success")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	canon := canonFile(t)
	p, _ := build(t, canon, graph.LevelCore, time.Now())
	good := readEntries(t, p)
	dir := t.TempDir()
	clone := func() map[string][]byte {
		m := map[string][]byte{}
		for k, v := range good {
			m[k] = append([]byte(nil), v...)
		}
		return m
	}
	check := func(name string, entries map[string][]byte, hdr func(*tar.Header), wantFile string) {
		t.Helper()
		q := filepath.Join(dir, name+".tar.gz")
		writePkg(t, q, entries, hdr)
		_, err := VerifyPackage(q)
		var pe *PackageError
		if err == nil || !errors.As(err, &pe) || pe.File != wantFile {
			t.Fatalf("%s: err=%v want file %q", name, err, wantFile)
		}
	}
	// control: rewritten but unmodified package verifies
	writePkg(t, filepath.Join(dir, "ok.tar.gz"), clone(), nil)
	if _, err := VerifyPackage(filepath.Join(dir, "ok.tar.gz")); err != nil {
		t.Fatal(err)
	}
	e := clone()
	e[FileGraphDB][len(e[FileGraphDB])/2] ^= 0xff
	check("tampered", e, nil, FileGraphDB)
	if _, err := VerifyPackage(filepath.Join(dir, "tampered.tar.gz")); !errors.Is(err, ErrChecksum) {
		t.Fatalf("want ErrChecksum, got %v", err)
	}
	e = clone()
	e["extra.txt"] = []byte("x")
	check("extra", e, nil, "extra.txt")
	e = clone()
	delete(e, FileSources)
	check("missing", e, nil, FileSources)
	e = clone()
	e["../evil"] = []byte("x")
	check("dotdot", e, nil, "../evil")
	e = clone()
	e["/abs"] = []byte("x")
	check("abs", e, nil, "/abs")
	check("symlink", clone(), func(h *tar.Header) {
		if h.Name == FileSources {
			h.Typeflag, h.Linkname, h.Size = tar.TypeSymlink, "/etc/passwd", 0
		}
	}, FileSources)
	e = clone()
	e[FileChecksums] = []byte(strings.Replace(string(e[FileChecksums]), FileManifest, "manifest.jsn", 1))
	if _, err := verifyEntries(t, dir, "badsums", e); err == nil {
		t.Fatal("bad checksums list accepted")
	}

	old := MaxPackageSize
	MaxPackageSize = 10
	defer func() { MaxPackageSize = old }()
	if _, err := VerifyPackage(p); err == nil {
		t.Fatal("size limit not enforced")
	}
}

func verifyEntries(t *testing.T, dir, name string, e map[string][]byte) (Manifest, error) {
	q := filepath.Join(dir, name+".tar.gz")
	writePkg(t, q, e, nil)
	return VerifyPackage(q)
}

func TestVerifyDuplicateEntry(t *testing.T) {
	canon := canonFile(t)
	p, _ := build(t, canon, graph.LevelCore, time.Now())
	good := readEntries(t, p)
	q := filepath.Join(t.TempDir(), "dup.tar.gz")
	f, _ := os.Create(q)
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	names := append(append([]string(nil), SnapshotFiles...), FileManifest)
	sort.Strings(names)
	for _, n := range names {
		tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(good[n]))})
		tw.Write(good[n])
	}
	tw.Close()
	zw.Close()
	f.Close()
	_, err := VerifyPackage(q)
	var pe *PackageError
	if !errors.As(err, &pe) || pe.File != FileManifest {
		t.Fatalf("%v", err)
	}
}
