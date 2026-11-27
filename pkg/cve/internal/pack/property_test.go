package pack

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/graph"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// recSpec describes one generated source record. Index i selects the identifier.
type recSpec struct {
	Pkg       int  // package pool index
	Ver       int  // content version, increases Modified and changes the summary
	Withdrawn bool // withdrawn marker
}

type storeSpec map[int]recSpec

const poolSize = 6

var propBase = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func genRecSpec() *rapid.Generator[recSpec] {
	return rapid.Custom(func(t *rapid.T) recSpec {
		return recSpec{
			Pkg:       rapid.IntRange(0, 3).Draw(t, "pkg"),
			Ver:       rapid.IntRange(0, 2).Draw(t, "ver"),
			Withdrawn: rapid.IntRange(0, 4).Draw(t, "wd") == 0,
		}
	})
}

func genStore() *rapid.Generator[storeSpec] {
	return rapid.Custom(func(t *rapid.T) storeSpec {
		s := storeSpec{}
		for i := 0; i < poolSize; i++ {
			if rapid.Bool().Draw(t, fmt.Sprintf("has%d", i)) {
				s[i] = genRecSpec().Draw(t, fmt.Sprintf("rec%d", i))
			}
		}
		return s
	})
}

func genLevel() *rapid.Generator[graph.Level] {
	return rapid.SampledFrom([]graph.Level{graph.LevelCore, graph.LevelEcosystem, graph.LevelComplete})
}

// mutate derives a store B from A by random add, modify, withdraw and remove.
func mutate(t *rapid.T, a storeSpec) storeSpec {
	b := storeSpec{}
	for i := 0; i < poolSize; i++ {
		cur, ok := a[i]
		switch rapid.IntRange(0, 4).Draw(t, fmt.Sprintf("act%d", i)) {
		case 0: // add or replace
			if !ok {
				b[i] = genRecSpec().Draw(t, fmt.Sprintf("add%d", i))
			} else if cur.Ver < 5 {
				cur.Ver++
				b[i] = cur
			}
		case 1: // modify
			if ok {
				cur.Ver++
				cur.Pkg = (cur.Pkg + 1) % 4
				b[i] = cur
			}
		case 2: // withdraw
			if ok {
				cur.Ver++
				cur.Withdrawn = true
				b[i] = cur
			}
		case 3: // remove
		default: // keep
			if ok {
				b[i] = cur
			}
		}
	}
	return b
}

func buildCanonical(dir, name string, spec storeSpec) (string, error) {
	ctx := context.Background()
	st, err := canonical.Open(":memory:")
	if err != nil {
		return "", err
	}
	defer st.Close()
	for i, r := range spec {
		mod := propBase.AddDate(0, 0, 10+r.Ver)
		rec := &model.Record{
			Source: "osv", ID: fmt.Sprintf("GHSA-prop-%04d", i),
			Aliases: []string{fmt.Sprintf("CVE-2024-%04d", 1000+i)},
			Summary: fmt.Sprintf("summary %d v%d", i, r.Ver), Published: propBase, Modified: mod,
			Affected: []model.Affected{{Kind: "package", Ecosystem: "npm", Name: fmt.Sprintf("prop-pkg-%d", r.Pkg),
				Versions: []string{fmt.Sprintf("1.%d.0", r.Ver)}}},
		}
		if r.Withdrawn {
			rec.Withdrawn = mod
		}
		if _, err := st.UpsertRecord(ctx, rec); err != nil {
			return "", err
		}
	}
	if _, err := st.Resolve(ctx, canonical.ResolveOptions{}); err != nil {
		return "", err
	}
	p := filepath.Join(dir, name)
	if _, err := st.DB.Exec(`VACUUM INTO ?`, p); err != nil {
		return "", err
	}
	return p, nil
}

func buildPkg(canon, out string, lvl graph.Level, at time.Time) (string, Manifest, error) {
	return BuildSnapshot(context.Background(), SnapshotOptions{CanonicalPath: canon, OutDir: out, Level: lvl, Clock: tclock{at}})
}

func groupCounts(db *sql.DB, q string) (map[string]int64, error) {
	rows, err := db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var ty string
		var n int64
		if err := rows.Scan(&ty, &n); err != nil {
			return nil, err
		}
		out[ty] = n
	}
	return out, rows.Err()
}

func sameCounts(a, b map[string]int64) bool {
	for k, v := range a {
		if v != 0 && b[k] != v {
			return false
		}
	}
	for k, v := range b {
		if v != 0 && a[k] != v {
			return false
		}
	}
	return true
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Feature: bellu-security-knowledge-graph, Property 31: Snapshot package integrity and logical determinism
// **Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5, 10.10**
func TestProperty31SnapshotIntegrity(t *testing.T) {
	root := t.TempDir()
	n := 0
	rapid.Check(t, func(rt *rapid.T) {
		n++
		dir := filepath.Join(root, fmt.Sprintf("p31-%d", n))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			rt.Fatal(err)
		}
		spec := genStore().Draw(rt, "store")
		lvl := genLevel().Draw(rt, "level")
		canon, err := buildCanonical(dir, "canon.db", spec)
		if err != nil {
			rt.Fatal(err)
		}
		p1, m1, err := buildPkg(canon, filepath.Join(dir, "o1"), lvl, time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC))
		if err != nil {
			rt.Fatal(err)
		}
		p2, m2, err := buildPkg(canon, filepath.Join(dir, "o2"), lvl, time.Date(2026, 6, 2, 3, 4, 5, 0, time.UTC))
		if err != nil {
			rt.Fatal(err)
		}
		vm, err := VerifyPackage(p1)
		if err != nil {
			rt.Fatalf("verify: %v", err)
		}
		if vm.LogicalDigest != m1.LogicalDigest {
			rt.Fatal("verified manifest differs")
		}
		// exactly the six files
		dest := t.TempDir()
		want := map[string]bool{}
		for _, f := range SnapshotFiles {
			want[f] = true
			if err := os.MkdirAll(filepath.Dir(filepath.Join(dest, f)), 0o755); err != nil {
				rt.Fatal(err)
			}
			if err := extractEntry(p1, f, filepath.Join(dest, f)); err != nil {
				rt.Fatalf("missing %s: %v", f, err)
			}
		}
		if len(SnapshotFiles) != 6 {
			rt.Fatalf("SnapshotFiles has %d entries", len(SnapshotFiles))
		}
		if err := extractEntry(p1, "unexpected-entry", filepath.Join(dest, "x")); err == nil {
			rt.Fatal("unexpected entry present")
		}
		// checksums: every file but itself, correct 64-hex digests
		raw, err := os.ReadFile(filepath.Join(dest, FileChecksums))
		if err != nil {
			rt.Fatal(err)
		}
		seen := map[string]bool{}
		for _, l := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
			parts := strings.SplitN(l, "  ", 2)
			if len(parts) != 2 || !hex64.MatchString(parts[0]) {
				rt.Fatalf("bad checksum line %q", l)
			}
			b, err := os.ReadFile(filepath.Join(dest, parts[1]))
			if err != nil || sha256Sum(b) != parts[0] {
				rt.Fatalf("checksum mismatch for %s", parts[1])
			}
			seen[parts[1]] = true
		}
		for f := range want {
			if f != FileChecksums && !seen[f] {
				rt.Fatalf("checksums missing %s", f)
			}
		}
		if seen[FileChecksums] {
			rt.Fatal("checksums lists itself")
		}
		// manifest counts equal graph.db counts
		db, err := sql.Open("sqlite", filepath.Join(dest, FileGraphDB))
		if err != nil {
			rt.Fatal(err)
		}
		defer db.Close()
		nc, err := groupCounts(db, `SELECT type, COUNT(*) FROM nodes GROUP BY type`)
		if err != nil {
			rt.Fatal(err)
		}
		ec, err := groupCounts(db, `SELECT type, COUNT(*) FROM edges GROUP BY type`)
		if err != nil {
			rt.Fatal(err)
		}
		if !sameCounts(nc, m1.RecordCounts.Nodes) || !sameCounts(ec, m1.RecordCounts.Edges) {
			rt.Fatalf("counts differ: db %v %v manifest %+v", nc, ec, m1.RecordCounts)
		}
		// determinism across clocks
		if m1.LogicalDigest != m2.LogicalDigest || !equalJSON(m1.RecordCounts, m2.RecordCounts) {
			rt.Fatal("logical content differs between builds")
		}
		if _, err := VerifyPackage(p2); err != nil {
			rt.Fatal(err)
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 32: Delta correctness
// **Validates: Requirements 11.1, 11.2, 11.10, 23.1**
func TestProperty32DeltaCorrectness(t *testing.T) {
	root := t.TempDir()
	n := 0
	rapid.Check(t, func(rt *rapid.T) {
		n++
		dir := filepath.Join(root, fmt.Sprintf("p32-%d", n))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			rt.Fatal(err)
		}
		a := genStore().Draw(rt, "A")
		b := mutate(rt, a)
		lvl := genLevel().Draw(rt, "level")
		ca, err := buildCanonical(dir, "a.db", a)
		if err != nil {
			rt.Fatal(err)
		}
		cb, err := buildCanonical(dir, "b.db", b)
		if err != nil {
			rt.Fatal(err)
		}
		pa, ma, err := buildPkg(ca, filepath.Join(dir, "oa"), lvl, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
		if err != nil {
			rt.Fatal(err)
		}
		pb, mb, err := buildPkg(cb, filepath.Join(dir, "ob"), lvl, time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC))
		if err != nil {
			rt.Fatal(err)
		}
		dp, dm, err := BuildDelta(context.Background(), DeltaOptions{BasePackage: pa, TargetPackage: pb, OutDir: filepath.Join(dir, "od")})
		if err != nil {
			rt.Fatal(err)
		}
		if _, err := VerifyDelta(dp); err != nil {
			rt.Fatal(err)
		}
		// manifest counts equal the number of delta lines of each kind
		opsFile := filepath.Join(dir, "ops")
		if err := extractEntry(dp, FileDelta, opsFile); err != nil {
			rt.Fatal(err)
		}
		raw, _ := os.ReadFile(opsFile)
		lines := 0
		if len(raw) > 0 {
			lines = strings.Count(string(raw), "\n")
		}
		c := dm.Counts
		if got := c.UpsertNodes + c.DeleteNodes + c.UpsertEdges + c.DeleteEdges; got != int64(lines) {
			rt.Fatalf("delta counts %+v vs %d lines", c, lines)
		}
		// apply to a copy of A's graph.db
		abase := filepath.Join(dir, "base.db")
		if err := extractEntry(pa, FileGraphDB, abase); err != nil {
			rt.Fatal(err)
		}
		db, err := sql.Open("sqlite", abase)
		if err != nil {
			rt.Fatal(err)
		}
		tx, err := db.Begin()
		if err != nil {
			rt.Fatal(err)
		}
		f, _ := os.Open(opsFile)
		err = ApplyOps(context.Background(), tx, f)
		f.Close()
		if err != nil {
			tx.Rollback()
			db.Close()
			rt.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			rt.Fatal(err)
		}
		db.Close()
		got, err := LogicalDigest(abase)
		if err != nil {
			rt.Fatal(err)
		}
		if got != mb.LogicalDigest {
			rt.Fatalf("applied digest %s want %s (base %s)", got, mb.LogicalDigest, ma.LogicalDigest)
		}
	})
}

// Chain S -> T -> U: applying delta(S,T) then delta(T,U) to S yields U.
// Also checks S + delta(S,T) equals a full rebuild of T (R23.1).
func TestDeltaChainSTU(t *testing.T) {
	at := func(m time.Month) time.Time { return time.Date(2024, m, 1, 0, 0, 0, 0, time.UTC) }
	sp, sm := build(t, fixtureCanon(t, "snapshot_S.json"), graph.LevelComplete, at(1))
	tp, tm := build(t, fixtureCanon(t, "snapshot_S.json", "snapshot_T.json"), graph.LevelComplete, at(2))
	up, um := build(t, fixtureCanon(t, "snapshot_S.json", "snapshot_T.json", "snapshot_U.json"), graph.LevelComplete, at(3))
	if sm.LogicalDigest == tm.LogicalDigest || tm.LogicalDigest == um.LogicalDigest {
		t.Fatal("fixtures should yield distinct states")
	}
	ctx := context.Background()
	d1, _, err := BuildDelta(ctx, DeltaOptions{BasePackage: sp, TargetPackage: tp, OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	d2, _, err := BuildDelta(ctx, DeltaOptions{BasePackage: tp, TargetPackage: up, OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	afterT := applyDelta(t, extractDB(t, sp), d1)
	if d, err := LogicalDigest(afterT); err != nil || d != tm.LogicalDigest {
		t.Fatalf("T digest %q %v", d, err)
	}
	afterU := applyDelta(t, afterT, d2)
	if d, err := LogicalDigest(afterU); err != nil || d != um.LogicalDigest {
		t.Fatalf("U digest %q %v want %q", d, err, um.LogicalDigest)
	}
	sameRows(t, afterU, extractDB(t, up))
}
