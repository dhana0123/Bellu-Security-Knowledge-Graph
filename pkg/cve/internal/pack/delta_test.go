package pack

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/osv"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/graph"
)

// fixtureCanon builds a canonical file from the named fixtures, loaded in order.
func fixtureCanon(t *testing.T, files ...string) string {
	t.Helper()
	ctx := context.Background()
	st, err := canonical.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "graph", f))
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

func ST(t *testing.T) (sp, tp string, sm, tm Manifest) {
	t.Helper()
	sp, sm = build(t, fixtureCanon(t, "snapshot_S.json"), graph.LevelComplete, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	tp, tm = build(t, fixtureCanon(t, "snapshot_S.json", "snapshot_T.json"), graph.LevelComplete, time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC))
	return
}

func extractDB(t *testing.T, pkg string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "graph.db")
	if err := extractEntry(pkg, FileGraphDB, p); err != nil {
		t.Fatal(err)
	}
	return p
}

func dumpTable(t *testing.T, p, q string) []string {
	t.Helper()
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
	var out []string
	for rows.Next() {
		var a, b, c, d string
		if err := rows.Scan(&a, &b, &c, &d); err != nil {
			t.Fatal(err)
		}
		out = append(out, a+"|"+b+"|"+c+"|"+d)
	}
	return out
}

func sameRows(t *testing.T, a, b string) {
	t.Helper()
	for _, q := range []string{
		`SELECT id,type,props,h FROM nodes ORDER BY id`,
		`SELECT id,type,src||'>'||dst,props||h FROM edges ORDER BY id`,
	} {
		ra, rb := dumpTable(t, a, q), dumpTable(t, b, q)
		if strings.Join(ra, "\n") != strings.Join(rb, "\n") {
			t.Fatalf("rows differ for %s: %d vs %d", q, len(ra), len(rb))
		}
	}
}

func applyDelta(t *testing.T, base, deltaPkg string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "applied.db")
	b, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatal(err)
	}
	opsFile := filepath.Join(t.TempDir(), FileDelta)
	if err := extractEntry(deltaPkg, FileDelta, opsFile); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(opsFile)
	defer f.Close()
	db, err := sql.Open("sqlite", dst)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyOps(context.Background(), tx, f); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	db.Close()
	return dst
}

func TestDeltaRoundTrip(t *testing.T) {
	sp, tp, sm, tm := ST(t)
	out := t.TempDir()
	dp, dm, err := BuildDelta(context.Background(), DeltaOptions{BasePackage: sp, TargetPackage: tp, OutDir: out})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(dp) != "bellu-delta-"+sm.SnapshotID+"-to-"+tm.SnapshotID+".tar.gz" {
		t.Fatalf("name %s", dp)
	}
	if _, err := os.Stat(dp + ".partial"); err == nil {
		t.Fatal("partial left")
	}
	vm, err := VerifyDelta(dp)
	if err != nil {
		t.Fatal(err)
	}
	if vm.Kind != "delta" || vm.BaseSnapshotID != sm.SnapshotID || vm.TargetSnapshotID != tm.SnapshotID ||
		vm.LogicalDigest != tm.LogicalDigest || !vm.CreatedAt.Equal(tm.CreatedAt) || dm.Counts.ChangedRecords == 0 {
		t.Fatalf("manifest %+v", vm)
	}
	if vm.Counts.UpsertNodes == 0 {
		t.Fatalf("expected upserts: %+v", vm.Counts)
	}
	applied := applyDelta(t, extractDB(t, sp), dp)
	tdb := extractDB(t, tp)
	if d, err := LogicalDigest(applied); err != nil || d != tm.LogicalDigest {
		t.Fatalf("digest %q %v want %q", d, err, tm.LogicalDigest)
	}
	sameRows(t, applied, tdb)

	// reverse delta exercises deletes
	rp, rm, err := BuildDelta(context.Background(), DeltaOptions{BasePackage: tp, TargetPackage: sp, OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	back := applyDelta(t, tdb, rp)
	if d, _ := LogicalDigest(back); d != sm.LogicalDigest {
		t.Fatal("reverse digest mismatch")
	}
	sameRows(t, back, extractDB(t, sp))
	_ = rm
}

func TestDeltaIdenticalIsEmpty(t *testing.T) {
	sp, _, _, _ := ST(t)
	dp, m, err := BuildDelta(context.Background(), DeltaOptions{BasePackage: sp, TargetPackage: sp, OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if m.Counts != (DeltaCounts{}) {
		t.Fatalf("counts %+v", m.Counts)
	}
	if b := readEntries(t, dp)[FileDelta]; len(b) != 0 {
		t.Fatalf("delta not empty: %q", b)
	}
	if _, err := VerifyDelta(dp); err != nil {
		t.Fatal(err)
	}
}

func TestDeltaLevelMismatch(t *testing.T) {
	sp, _, _, _ := ST(t)
	cp, _ := build(t, fixtureCanon(t, "snapshot_S.json"), graph.LevelCore, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	out := t.TempDir()
	if _, _, err := BuildDelta(context.Background(), DeltaOptions{BasePackage: sp, TargetPackage: cp, OutDir: out}); err == nil {
		t.Fatal("expected level mismatch error")
	}
	if ents, _ := os.ReadDir(out); len(ents) != 0 {
		t.Fatalf("leftovers %v", ents)
	}
}

func TestDeltaOrderingAndTamper(t *testing.T) {
	sp, tp, _, _ := ST(t)
	dp, _, err := BuildDelta(context.Background(), DeltaOptions{BasePackage: tp, TargetPackage: sp, OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ents := readEntries(t, dp)
	lines := strings.Split(strings.TrimSuffix(string(ents[FileDelta]), "\n"), "\n")
	rank, lastID := -1, ""
	for _, l := range lines {
		var o struct{ Op, ID string }
		if err := json.Unmarshal([]byte(l), &o); err != nil {
			t.Fatal(err)
		}
		r := opRank[o.Op]
		if r < rank || (r == rank && o.ID <= lastID) {
			t.Fatalf("order violated at %s", l)
		}
		rank, lastID = r, o.ID
	}
	// tampered content: checksum error
	bad := map[string][]byte{}
	for k, v := range ents {
		bad[k] = v
	}
	bad[FileDelta] = append(append([]byte(nil), ents[FileDelta]...), []byte(`{"op":"delete_node","id":"zzz"}`+"\n")...)
	p := filepath.Join(t.TempDir(), "bad.tar.gz")
	writePkg(t, p, bad, nil)
	if _, err := VerifyDelta(p); err == nil {
		t.Fatal("expected checksum error")
	}
	// consistent checksums but misordered ops: still rejected
	if len(lines) >= 2 {
		swapped := append([]string(nil), lines...)
		swapped[0], swapped[len(swapped)-1] = swapped[len(swapped)-1], swapped[0]
		if swapped[0] != lines[0] {
			body := []byte(strings.Join(swapped, "\n") + "\n")
			mal := map[string][]byte{FileManifest: ents[FileManifest], FileDelta: body}
			mal[FileChecksums] = formatChecksums(map[string]string{FileManifest: sumHex(mal[FileManifest]), FileDelta: sumHex(body)})
			p2 := filepath.Join(t.TempDir(), "mis.tar.gz")
			writePkg(t, p2, mal, nil)
			if _, err := VerifyDelta(p2); err == nil {
				t.Fatal("expected ordering error")
			}
		}
	}
	// extra file rejected
	extra := map[string][]byte{"x": []byte("x")}
	for k, v := range ents {
		extra[k] = v
	}
	p3 := filepath.Join(t.TempDir(), "extra.tar.gz")
	writePkg(t, p3, extra, nil)
	if _, err := VerifyDelta(p3); err == nil {
		t.Fatal("expected unexpected-file error")
	}
}

func sumHex(b []byte) string { return fileHashBytes(b) }

func fileHashBytes(b []byte) string {
	h := sha256Sum(b)
	return h
}

func sha256Sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
