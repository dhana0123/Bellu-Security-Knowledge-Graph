package canonical

// Task 88.6: cross-source dedupe and correlation, stable ids, collisions, incremental
// equivalence, bounded fuzzy matching and a scale test. All data is generated in the tests.
//
// The scale test uses 200000 records by default and 20000 with `go test -short`
// (testing.Short only reduces the size, it never skips). Full-size run:
//
//	CGO_ENABLED=0 go test -count=1 -run TestResolveScale -v ./internal/canonical

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

const (
	scaleRecordsFull  = 200_000
	scaleRecordsShort = 20_000
	// Stated limits for the full-size run. Short mode scales the time bound down.
	scaleTimeBound = 90 * time.Second
	scaleHeapBound = 1_500_000_000 // bytes of peak runtime.MemStats.HeapAlloc during Resolve
)

func upsert(t testing.TB, s *Store, recs ...*model.Record) {
	t.Helper()
	for _, r := range recs {
		if r.Modified.IsZero() {
			r.Modified = time.Unix(1700000000, 0)
		}
		if _, err := s.UpsertRecord(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
}

func mustResolve(t testing.TB, s *Store, opts ResolveOptions) ResolveReport {
	t.Helper()
	rep, err := s.Resolve(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// resolutionState dumps everything Resolve owns, without timestamps, in a stable order.
func resolutionState(t testing.TB, s *Store) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for name, q := range map[string]string{
		"vulnerability":            `SELECT id FROM vulnerability ORDER BY id`,
		"vulnerability_identifier": `SELECT value||'>'||vulnerability_id FROM vulnerability_identifier ORDER BY 1`,
		"record_vulnerability":     `SELECT source||':'||external_id||'>'||vulnerability_id||'/'||method FROM record_vulnerability ORDER BY 1`,
		"entity_resolution":        `SELECT left_id||'|'||right_id||'|'||method||'|'||confidence||'|'||decision FROM entity_resolution ORDER BY 1`,
	} {
		rows, err := s.DB.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		list := []string{}
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				t.Fatal(err)
			}
			list = append(list, v)
		}
		rows.Close()
		out[name] = list
	}
	return out
}

func sameState(t testing.TB, label string, a, b map[string][]string) {
	t.Helper()
	for k := range a {
		if !reflect.DeepEqual(a[k], b[k]) {
			t.Fatalf("%s: %s differs\n a(%d)=%.400v\n b(%d)=%.400v", label, k, len(a[k]), a[k], len(b[k]), b[k])
		}
	}
}

func rec(source, id string, aliases ...string) *model.Record {
	return &model.Record{Source: source, ID: id, Aliases: aliases}
}

// ---- one CVE across NVD, GHSA and OSV PYSEC ----

func TestResolveScaleSameCVEAcrossNVDGHSAOSV(t *testing.T) {
	const cve = "CVE-2023-37920"
	mk := func() []*model.Record {
		return []*model.Record{
			rec("nvd", cve),
			rec("ghsa", "GHSA-xqr8-7jwr-rhp7", cve),
			rec("osv", "PYSEC-2023-135", "GHSA-xqr8-7jwr-rhp7", cve),
		}
	}
	// Every insertion order gives the same single vulnerability with three source records.
	orders := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	var first map[string][]string
	for _, o := range orders {
		s := resolveStore(t, nil)
		recs := mk()
		for _, i := range o {
			upsert(t, s, recs[i])
		}
		rep := mustResolve(t, s, ResolveOptions{})
		if rep.Groups != 1 || rep.Memberships != 3 || rep.Collisions != 0 {
			t.Fatalf("order %v: report %+v", o, rep)
		}
		want := map[string][]string{cve: {"ghsa:GHSA-xqr8-7jwr-rhp7", "nvd:" + cve, "osv:PYSEC-2023-135"}}
		if got := membership(t, s); !reflect.DeepEqual(got, want) {
			t.Fatalf("order %v: membership %v want %v", o, got, want)
		}
		if n := countRows(t, s, `SELECT COUNT(*) FROM source_record`); n != 3 {
			t.Fatalf("source records = %d", n)
		}
		var id string
		if err := s.DB.QueryRow(`SELECT vulnerability_id FROM vulnerability_identifier WHERE value='PYSEC-2023-135'`).Scan(&id); err != nil || id != cve {
			t.Fatalf("PYSEC id resolves to %q (%v)", id, err)
		}
		st := resolutionState(t, s)
		if first == nil {
			first = st
		} else {
			sameState(t, fmt.Sprintf("order %v", o), first, st)
		}
	}
}

// ---- stable ids ----

func TestResolveScaleStableIDs(t *testing.T) {
	s := resolveStore(t, nil)
	for i := 0; i < 50; i++ {
		cve := fmt.Sprintf("CVE-2024-%04d", i)
		ghsa := fmt.Sprintf("GHSA-aaaa-bbbb-%04d", i)
		upsert(t, s, rec("nvd", cve), rec("ghsa", ghsa, cve), rec("osv", fmt.Sprintf("PYSEC-2024-%d", i), ghsa, cve))
	}
	upsert(t, s, rec("ghsa", "GHSA-solo-0000-0001"), rec("osv", "OSV-solo-1", "GHSA-solo-0000-0001"))
	mustResolve(t, s, ResolveOptions{})
	before := resolutionState(t, s)

	// Rerun: identical ids, nothing new.
	rep := mustResolve(t, s, ResolveOptions{})
	if rep.NewDecisions != 0 {
		t.Fatalf("rerun wrote decisions: %+v", rep)
	}
	sameState(t, "rerun", before, resolutionState(t, s))
	mustResolve(t, s, ResolveOptions{Full: true})
	sameState(t, "full rerun", before, resolutionState(t, s))

	// An unrelated record leaves every existing assignment untouched.
	upsert(t, s, rec("ghsa", "GHSA-zzzz-zzzz-zzzz", "CVE-2030-0001"), rec("osv", "OSV-unrelated"))
	mustResolve(t, s, ResolveOptions{})
	after := resolutionState(t, s)
	for _, k := range []string{"vulnerability", "vulnerability_identifier", "record_vulnerability", "entity_resolution"} {
		have := map[string]bool{}
		for _, v := range after[k] {
			have[v] = true
		}
		for _, v := range before[k] {
			if !have[v] {
				t.Fatalf("%s row %q changed after adding an unrelated record", k, v)
			}
		}
	}
	if got, want := len(after["vulnerability"]), len(before["vulnerability"])+2; got != want {
		t.Fatalf("vulnerabilities %d, want %d", got, want)
	}
}

// ---- collisions ----

func TestResolveScaleCollisionRecordedNotMerged(t *testing.T) {
	t.Run("record with two CVEs", func(t *testing.T) {
		// Documented rule: a record naming several CVEs joins each CVE group (multi-cve)
		// and never merges them; it is not an identifier collision.
		s := resolveStore(t, nil)
		upsert(t, s, rec("nvd", "CVE-2024-1111"), rec("nvd", "CVE-2024-2222"),
			rec("ghsa", "GHSA-bridge-0000-0001", "CVE-2024-1111", "CVE-2024-2222"))
		rep := mustResolve(t, s, ResolveOptions{})
		if rep.Groups != 2 || rep.Collisions != 0 || rep.Memberships != 4 {
			t.Fatalf("report %+v", rep)
		}
		want := map[string][]string{
			"CVE-2024-1111": {"ghsa:GHSA-bridge-0000-0001", "nvd:CVE-2024-1111"},
			"CVE-2024-2222": {"ghsa:GHSA-bridge-0000-0001", "nvd:CVE-2024-2222"},
		}
		if got := membership(t, s); !reflect.DeepEqual(got, want) {
			t.Fatalf("membership %v want %v", got, want)
		}
		if n := countRows(t, s, `SELECT COUNT(*) FROM record_vulnerability WHERE method='multi-cve'`); n != 2 {
			t.Fatalf("multi-cve memberships = %d", n)
		}
	})
	t.Run("alias chain", func(t *testing.T) {
		s := resolveStore(t, nil)
		upsert(t, s, rec("nvd", "CVE-2024-1111"), rec("nvd", "CVE-2024-2222"),
			rec("ghsa", "GHSA-a", "CVE-2024-1111"),
			rec("osv", "OSV-b", "CVE-2024-2222", "GHSA-a"))
		rep := mustResolve(t, s, ResolveOptions{})
		checkCollision(t, s, rep, "CVE-2024-1111", "CVE-2024-2222", "osv:OSV-b")
	})
}

func checkCollision(t *testing.T, s *Store, rep ResolveReport, a, b, rec string) {
	t.Helper()
	if rep.Groups != 2 || rep.Collisions != 1 {
		t.Fatalf("report %+v", rep)
	}
	n, err := s.CountCollisions(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("CountCollisions = %d, %v", n, err)
	}
	cs, err := s.ListCollisions(context.Background(), 0)
	if err != nil || len(cs) != 1 {
		t.Fatalf("ListCollisions = %+v, %v", cs, err)
	}
	c := cs[0]
	if c.CVEA != a || c.CVEB != b || !strings.Contains(strings.Join(c.Records, ","), rec) || c.RecordedAt == "" {
		t.Fatalf("collision %+v", c)
	}
	// The two CVEs stay separate vulnerabilities and no identifier belongs to both.
	for _, id := range []string{a, b} {
		var v string
		if err := s.DB.QueryRow(`SELECT vulnerability_id FROM vulnerability_identifier WHERE value=?`, id).Scan(&v); err != nil || v != id {
			t.Fatalf("%s resolves to %q (%v)", id, v, err)
		}
	}
	// A rerun and a full pass keep reporting exactly one collision.
	for _, o := range []ResolveOptions{{}, {Full: true}} {
		if r := mustResolve(t, s, o); r.Collisions != 1 {
			t.Fatalf("rerun %+v: %+v", o, r)
		}
	}
}

// ---- incremental == full ----

func TestResolveScaleIncrementalEqualsFull(t *testing.T) {
	later := time.Unix(1800000000, 0)
	base := func() []*model.Record {
		var out []*model.Record
		for i := 0; i < 150; i++ {
			cve := fmt.Sprintf("CVE-2024-%04d", i)
			ghsa := fmt.Sprintf("GHSA-base-%04d", i)
			out = append(out, rec("nvd", cve), rec("ghsa", ghsa, cve), rec("osv", fmt.Sprintf("PYSEC-%d", i), ghsa, cve))
		}
		for i := 0; i < 60; i++ { // groups without a CVE
			g := fmt.Sprintf("GHSA-solo-%04d", i)
			out = append(out, rec("ghsa", g), rec("osv", fmt.Sprintf("OSV-solo-%d", i), g))
		}
		out = append(out, rec("osv", "OSV-bridge-old", "CVE-2024-0001", "CVE-2024-0002")) // existing collision
		return out
	}
	// Changes applied after the first resolve.
	changes := func() []*model.Record {
		l := func(r *model.Record) *model.Record { r.Modified = later; return r }
		return []*model.Record{
			l(rec("osv", "OSV-bridge-new", "CVE-2024-0010", "GHSA-base-0011")),         // new collision (0011 belongs to CVE-2024-0011)
			l(rec("osv", "OSV-bridge-old", "CVE-2024-0001")),                           // collision disappears
			l(rec("osv", "OSV-solo-3", "GHSA-solo-0003", "GHSA-solo-0004")),            // merges two CVE-less groups
			l(rec("nvd", "CVE-2024-0003", "GHSA-solo-0010")),                           // CVE joins a CVE-less group
			l(rec("ghsa", "GHSA-base-0020")),                                           // drops its CVE alias
			rec("nvd", "CVE-2099-0001"), rec("ghsa", "GHSA-new-0001", "CVE-2099-0001"), // brand new group
		}
	}
	a := resolveStore(t, nil)
	upsert(t, a, base()...)
	mustResolve(t, a, ResolveOptions{})
	upsert(t, a, changes()...)
	rep := mustResolve(t, a, ResolveOptions{})
	if rep.Mode != "incremental" || rep.DirtyRecords != len(changes()) {
		t.Fatalf("expected an incremental run over %d dirty records: %+v", len(changes()), rep)
	}
	if rep.RecordsResolved >= 500 {
		t.Fatalf("incremental run loaded %d of ~%d records", rep.RecordsResolved, 150*3+60*2+1)
	}

	b := resolveStore(t, nil) // same final data, resolved once from scratch
	upsert(t, b, base()...)
	upsert(t, b, changes()...)
	repB := mustResolve(t, b, ResolveOptions{})
	if repB.Mode != "full" {
		t.Fatalf("fresh store ran %q", repB.Mode)
	}
	sameState(t, "incremental vs full", resolutionState(t, b), resolutionState(t, a))
	if rep.Collisions != repB.Collisions || rep.Groups != repB.Groups || rep.Memberships != repB.Memberships {
		t.Fatalf("incremental %+v full %+v", rep, repB)
	}
	// A forced full pass over the incrementally built store changes nothing.
	mustResolve(t, a, ResolveOptions{Full: true})
	sameState(t, "full over incremental", resolutionState(t, b), resolutionState(t, a))
	if n := countRows(t, a, `SELECT COUNT(*) FROM resolve_dirty`); n != 0 {
		t.Fatalf("%d records still dirty", n)
	}
}

// ---- bulk generation (direct SQL, one transaction) ----

type genRec struct {
	source, id string
	aliases    []string
	summary    string
	pkg        string
}

// bulkInsert writes records the way UpsertRecord does for the tables Resolve reads
// (source_record, record_identifier, resolve_dirty) in a single transaction.
func bulkInsert(t testing.TB, s *Store, n int, gen func(i int) genRec) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	src, err := tx.PrepareContext(ctx, `INSERT INTO source_record(source,external_id,content_hash,aliases,json,modified,withdrawn,first_seen_at,recorded_at)
VALUES(?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	ident, err := tx.PrepareContext(ctx, `INSERT INTO record_identifier(source,external_id,value) VALUES(?,?,?) ON CONFLICT DO NOTHING`)
	if err != nil {
		t.Fatal(err)
	}
	dirty, err := tx.PrepareContext(ctx, `INSERT INTO resolve_dirty(source,external_id,content_hash) VALUES(?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for i := 0; i < n; i++ {
		g := gen(i)
		r := model.Record{Source: g.source, ID: g.id, Aliases: g.aliases, Summary: g.summary, Modified: time.Unix(1700000000, 0)}
		if g.pkg != "" {
			r.Affected = []model.Affected{{Kind: "package", Name: g.pkg, Ecosystem: "PyPI"}}
		}
		body, _ := json.Marshal(&r)
		hash := fmt.Sprintf("h%d", i)
		all, _ := json.Marshal(append([]string{g.id}, g.aliases...))
		if _, err := src.ExecContext(ctx, g.source, g.id, hash, string(all), string(body), "2023-11-14T22:13:20Z", nil, now, now); err != nil {
			t.Fatal(err)
		}
		for _, v := range cleanIdents(append([]string{g.id}, g.aliases...)) {
			if _, err := ident.ExecContext(ctx, g.source, g.id, v); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := dirty.ExecContext(ctx, g.source, g.id, hash); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func openDisk(t testing.TB) *Store {
	t.Helper()
	s, err := Open(t.TempDir() + "/scale.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// ---- fuzzy matching is blocked, not all-pairs ----

func TestResolveScaleFuzzyIsBounded(t *testing.T) {
	n := 20_000
	if testing.Short() {
		n = 4_000
	}
	s := openDisk(t)
	// Worst case for all-pairs: every record affects the same package. Records come in
	// near-duplicate pairs (same summary, different ids, no shared alias).
	bulkInsert(t, s, n, func(i int) genRec {
		pair := i / 2
		return genRec{
			source:  "osv",
			id:      fmt.Sprintf("OSV-%07d%c", pair, 'a'+byte(i%2)),
			summary: fmt.Sprintf("remote code execution in parser module via crafted input u%d v%d", pair, pair*7),
			pkg:     "samepkg",
		}
	})
	start := time.Now()
	rep := mustResolve(t, s, ResolveOptions{Fuzzy: true, FuzzyThreshold: 0.9})
	took := time.Since(start)
	allPairs := n * (n - 1) / 2
	bound := n * fuzzyWindow
	t.Logf("fuzzy: %d records in one block, %d comparisons (all pairs would be %d), %v", n, rep.FuzzyComparisons, allPairs, took)
	if rep.FuzzyComparisons == 0 || rep.FuzzyComparisons > bound {
		t.Fatalf("comparisons = %d, want 1..%d", rep.FuzzyComparisons, bound)
	}
	if rep.FuzzyComparisons*50 > allPairs {
		t.Fatalf("comparisons %d are not far below all-pairs %d", rep.FuzzyComparisons, allPairs)
	}
	if got := countRows(t, s, `SELECT COUNT(*) FROM candidate_pair`); got < n/2 {
		t.Fatalf("found %d candidate pairs, want at least %d", got, n/2)
	}
	if took > 60*time.Second {
		t.Fatalf("fuzzy resolve took %v", took)
	}
	// Fuzzy output never merges anything.
	if got := countRows(t, s, `SELECT COUNT(*) FROM vulnerability`); got != n {
		t.Fatalf("vulnerabilities = %d, want %d", got, n)
	}
}

// ---- scale ----

func TestResolveScale(t *testing.T) {
	n, bound := scaleRecordsFull, scaleTimeBound
	if testing.Short() {
		n, bound = scaleRecordsShort, scaleTimeBound/4
	}
	s := openDisk(t)

	// Layout per 8-record group g: CVE 2g seen by NVD, GHSA and OSV PYSEC (3 records); a
	// CVE-less GHSA+OSV pair (2); CVE 2g+1 seen by NVD and an OSV record (2); one lone OSV
	// record (1). Every 1000th group also gets an OSV record that names CVE 2g+1 and the
	// GHSA id of CVE 2g, which is an identifier collision between two different CVEs.
	const per = 8
	groups := n / per
	bridges := groups / 1000
	cve := func(x int) string { return fmt.Sprintf("CVE-2022-%07d", x) }
	ghsaOf := func(g int) string { return fmt.Sprintf("GHSA-%04d-%04d-%04d", g%10000, g/10000, 1) }
	total := groups*per + bridges
	bulkInsert(t, s, total, func(i int) genRec {
		if i >= groups*per {
			g := (i - groups*per) * 1000
			return genRec{source: "osv", id: fmt.Sprintf("OSV-BRIDGE-%06d", g), aliases: []string{cve(g*2 + 1), ghsaOf(g)}}
		}
		g, j := i/per, i%per
		switch j {
		case 0:
			return genRec{source: "nvd", id: cve(g * 2)}
		case 1:
			return genRec{source: "ghsa", id: ghsaOf(g), aliases: []string{cve(g * 2)}}
		case 2:
			return genRec{source: "osv", id: fmt.Sprintf("PYSEC-2022-%d", g), aliases: []string{ghsaOf(g), cve(g * 2)}}
		case 3:
			return genRec{source: "ghsa", id: fmt.Sprintf("GHSA-solo-%07d", g)}
		case 4:
			return genRec{source: "osv", id: fmt.Sprintf("OSV-solo-%07d", g), aliases: []string{fmt.Sprintf("GHSA-solo-%07d", g)}}
		case 5:
			return genRec{source: "nvd", id: cve(g*2 + 1)}
		case 6:
			return genRec{source: "osv", id: fmt.Sprintf("PYSEC-2022-%d-b", g), aliases: []string{cve(g*2 + 1)}}
		default:
			return genRec{source: "osv", id: fmt.Sprintf("OSV-lone-%07d", g)}
		}
	})
	wantVulns := groups * 4

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var m runtime.MemStats
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > peak {
				peak = m.HeapAlloc
			}
			select {
			case <-stop:
				return
			case <-tick.C:
			}
		}
	}()
	start := time.Now()
	rep, err := s.Resolve(context.Background(), ResolveOptions{})
	took := time.Since(start)
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("scale: %d records resolved in %v (bound %v); peak HeapAlloc %.0f MB (baseline %.0f MB, bound %.0f MB); report %+v",
		total, took, bound, float64(peak)/1e6, float64(base.HeapAlloc)/1e6, float64(scaleHeapBound)/1e6, rep)
	if took > bound {
		t.Fatalf("resolve took %v, bound %v", took, bound)
	}
	if peak > scaleHeapBound {
		t.Fatalf("peak HeapAlloc %d bytes exceeds %d", peak, scaleHeapBound)
	}
	if rep.Mode != "full" || rep.RecordsResolved != total {
		t.Fatalf("report %+v, want full over %d records", rep, total)
	}
	if rep.Groups != wantVulns || rep.Memberships != total {
		t.Fatalf("groups=%d memberships=%d, want %d and %d", rep.Groups, rep.Memberships, wantVulns, total)
	}
	if rep.Collisions != bridges || bridges == 0 {
		t.Fatalf("collisions = %d, want %d", rep.Collisions, bridges)
	}

	// Spot-check one CVE group and that the three sources share the id.
	m := map[string]bool{}
	rows, err := s.DB.Query(`SELECT source||':'||external_id FROM record_vulnerability WHERE vulnerability_id='CVE-2022-0000004'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var k string
		rows.Scan(&k)
		m[k] = true
	}
	rows.Close()
	want := []string{"nvd:CVE-2022-0000004", "ghsa:GHSA-0002-0000-0001", "osv:PYSEC-2022-2"}
	for _, k := range want {
		if !m[k] {
			t.Fatalf("CVE-2022-0000004 members %v lack %s", m, k)
		}
	}

	// Idempotent rerun and a small incremental run are cheap and change nothing.
	before := countRows(t, s, `SELECT COUNT(*) FROM entity_resolution`)
	start = time.Now()
	rep2 := mustResolve(t, s, ResolveOptions{})
	if rep2.NewDecisions != 0 || rep2.DirtyRecords != 0 {
		t.Fatalf("rerun: %+v", rep2)
	}
	upsert(t, s, rec("ghsa", "GHSA-new-0000-0001", "CVE-2022-0000004"), rec("nvd", "CVE-2088-0001"))
	rep3 := mustResolve(t, s, ResolveOptions{})
	incr := time.Since(start)
	t.Logf("scale: rerun + incremental (2 new records) in %v; incremental %+v", incr, rep3)
	if rep3.Mode != "incremental" || rep3.RecordsResolved > 10 || incr > bound/4 {
		t.Fatalf("incremental run: %+v in %v", rep3, incr)
	}
	if got := countRows(t, s, `SELECT COUNT(*) FROM entity_resolution`); got < before {
		t.Fatalf("entity_resolution shrank %d -> %d", before, got)
	}
}

// ---- KEV and EPSS linkage ----

func enrichLink(t testing.TB, s *Store, table, cve string) (status string, vuln *string) {
	t.Helper()
	var v sql.NullString
	if err := s.DB.QueryRow(`SELECT status, vulnerability_id FROM `+table+` WHERE cve=? ORDER BY 1 LIMIT 1`, cve).Scan(&status, &v); err != nil {
		t.Fatal(err)
	}
	if v.Valid {
		return status, &v.String
	}
	return status, nil
}

func TestResolveScaleKEVEPSSLinkToResolvedID(t *testing.T) {
	ctx := context.Background()
	s := resolveStore(t, nil)
	const early, late = "CVE-2023-37920", "CVE-2022-42969"
	// Enrichment arrives first: both CVEs are unknown, rows are pending and unlinked.
	for _, c := range []string{early, late} {
		if _, err := s.UpsertKEV(ctx, model.KEV{CVE: c, Vendor: "v"}); err != nil {
			t.Fatal(err)
		}
		for _, d := range []string{"2026-11-18", "2026-11-19"} {
			if _, err := s.UpsertEPSS(ctx, model.EPSS{CVE: c, Score: 0.5, Percentile: 0.9, Date: d}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, tb := range []string{"kev", "epss_history"} {
		if st, v := enrichLink(t, s, tb, early); st != "pending" || v != nil {
			t.Fatalf("%s before: %s %v", tb, st, v)
		}
	}
	if ev, _ := s.Enrichment(ctx, early); ev.KEV != nil || ev.EPSS != nil {
		t.Fatalf("pending rows must not be served: %+v", ev)
	}
	// The CVE arrives only as an alias of GHSA and OSV records.
	upsert(t, s, rec("ghsa", "GHSA-xqr8-7jwr-rhp7", early), rec("osv", "PYSEC-2023-135", "GHSA-xqr8-7jwr-rhp7", early))
	rep := mustResolve(t, s, ResolveOptions{})
	if rep.LinkedEnrichment != 3 { // 1 KEV + 2 EPSS history rows of the CVE that arrived
		t.Fatalf("linked %d rows, want 3: %+v", rep.LinkedEnrichment, rep)
	}
	for _, tb := range []string{"kev", "epss_history"} {
		st, v := enrichLink(t, s, tb, early)
		if st != "linked" || v == nil || *v != early {
			t.Fatalf("%s after: %s %v", tb, st, v)
		}
		// The other CVE is still unknown.
		if st, v := enrichLink(t, s, tb, late); st != "pending" || v != nil {
			t.Fatalf("%s %s: %s %v", tb, late, st, v)
		}
	}
	ev, err := s.Enrichment(ctx, early)
	if err != nil || ev.KEV == nil || ev.EPSS == nil || ev.EPSS.Date != "2026-11-19" {
		t.Fatalf("enrichment %+v %v", ev, err)
	}
	// Second CVE arrives later, in an incremental run.
	upsert(t, s, rec("nvd", late))
	rep = mustResolve(t, s, ResolveOptions{})
	if rep.LinkedEnrichment != 3 {
		t.Fatalf("late arrival: %+v", rep)
	}
	for _, tb := range []string{"kev", "epss_history"} {
		if st, v := enrichLink(t, s, tb, late); st != "linked" || v == nil || *v != late {
			t.Fatalf("%s late: %s %v", tb, st, v)
		}
	}
	// Enrichment that arrives after the vulnerability exists is linked immediately.
	upsert(t, s, rec("nvd", "CVE-2024-9999"))
	mustResolve(t, s, ResolveOptions{})
	if _, err := s.UpsertKEV(ctx, model.KEV{CVE: "CVE-2024-9999"}); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkEnrichmentIDs(ctx, false); err != nil {
		t.Fatal(err)
	}
	if st, v := enrichLink(t, s, "kev", "CVE-2024-9999"); st != "linked" || v == nil || *v != "CVE-2024-9999" {
		t.Fatalf("direct: %s %v", st, v)
	}
}

// A multi-CVE advisory is a member of several vulnerabilities. When those components are written
// in different batches, a later batch must not delete the memberships an earlier one wrote
// (found on live OSV PyPI data: CVE-2024-33663 lost its vulnerability). BatchRows=1 puts every
// component in its own transaction.
func TestResolveScaleMultiCVEAcrossBatches(t *testing.T) {
	later := time.Unix(1800000000, 0)
	build := func() []*model.Record {
		var out []*model.Record
		for i := 0; i < 30; i++ {
			a, b, c := fmt.Sprintf("CVE-2024-%04d", i*3), fmt.Sprintf("CVE-2024-%04d", i*3+1), fmt.Sprintf("CVE-2024-%04d", i*3+2)
			out = append(out,
				rec("osv", fmt.Sprintf("PYSEC-%d", i), a, b, fmt.Sprintf("GHSA-m-%d", i)),
				rec("osv", fmt.Sprintf("GHSA-m-%d", i), a, b, fmt.Sprintf("PYSEC-%d", i)),
				rec("nvd", c), rec("ghsa", fmt.Sprintf("GHSA-c-%d", i), c),
			)
		}
		return out
	}
	ref := resolveStore(t, nil)
	upsert(t, ref, build()...)
	mustResolve(t, ref, ResolveOptions{})
	want := resolutionState(t, ref)
	if len(want["vulnerability"]) != 90 || len(want["record_vulnerability"]) != 30*(2+2+1+1) {
		t.Fatalf("reference state: %d vulnerabilities, %d memberships", len(want["vulnerability"]), len(want["record_vulnerability"]))
	}

	s := resolveStore(t, nil)
	upsert(t, s, build()...)
	rep := mustResolve(t, s, ResolveOptions{BatchRows: 1})
	if rep.Groups != 90 {
		t.Fatalf("BatchRows=1: %+v", rep)
	}
	sameState(t, "BatchRows=1", want, resolutionState(t, s))

	// Changing the records and resolving in tiny batches (incremental and full) still matches a
	// fresh resolve of the final data, including memberships of vulnerabilities that vanished.
	changed := []*model.Record{
		{Source: "osv", ID: "PYSEC-0", Aliases: []string{"CVE-2024-0000", "GHSA-m-0"}, Modified: later}, // no longer multi-CVE
		{Source: "osv", ID: "GHSA-m-1", Aliases: []string{"CVE-2024-0003", "CVE-2024-0004", "CVE-2024-0005"}, Modified: later},
	}
	upsert(t, s, changed...)
	fresh := resolveStore(t, nil)
	upsert(t, fresh, build()...)
	upsert(t, fresh, changed...)
	mustResolve(t, fresh, ResolveOptions{})
	mustResolve(t, s, ResolveOptions{BatchRows: 1})
	sameState(t, "after change", resolutionState(t, fresh), resolutionState(t, s))
	mustResolve(t, s, ResolveOptions{BatchRows: 1, Full: true})
	sameState(t, "after full", resolutionState(t, fresh), resolutionState(t, s))
}
