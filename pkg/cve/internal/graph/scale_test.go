package graph

// Task 88.7: projection at scale. All data is generated in the tests.
//
// The heap test projects 50000 vulnerabilities (20000 with `go test -short`; -short only
// reduces the size, it never skips). Stated bound: peak runtime.MemStats.HeapAlloc during the
// projection stays under scaleHeapBound, and it does not depend on the dataset size: the same
// projection of a 5x smaller store peaks at a similar value (checked below with a loose ratio).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

const (
	scaleVulnsFull  = 50_000
	scaleVulnsShort = 20_000
	// Peak HeapAlloc bound for projecting 50000 vulnerabilities (100000 records) to graph.db.
	// Measured peaks are far lower; the bound leaves room for GC timing on slow machines.
	scaleHeapBound = 64 << 20
	// Time bound for the same projection. Short mode divides it by 2.
	scaleTimeBound = 4 * time.Minute
)

// seedScale writes n vulnerabilities straight into a canonical store file with SQL, the way
// ingest and resolve would leave them: two records per vulnerability (an NVD record and an OSV
// advisory), a severity row, a weakness, a patch, and KEV and EPSS rows for some of them.
// unlinkedEPSS extra EPSS rows belong to CVEs no record mentions and must never be projected.
// Shared packages and versions repeat across vulnerabilities, as in real data.
func seedScale(t testing.TB, path string, n, unlinkedEPSS int) {
	t.Helper()
	ctx := context.Background()
	st, err := canonical.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tx, err := st.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	prep := func(q string) *sql.Stmt {
		s, err := tx.PrepareContext(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	insRec := prep(`INSERT INTO source_record(source,external_id,content_hash,aliases,json,modified,withdrawn,first_seen_at,recorded_at) VALUES(?,?,?,?,?,?,?,?,?)`)
	insIdent := prep(`INSERT INTO record_identifier(source,external_id,value) VALUES(?,?,?) ON CONFLICT DO NOTHING`)
	insVuln := prep(`INSERT INTO vulnerability(id) VALUES(?)`)
	insVI := prep(`INSERT INTO vulnerability_identifier(value,vulnerability_id) VALUES(?,?) ON CONFLICT DO NOTHING`)
	insRV := prep(`INSERT INTO record_vulnerability(source,external_id,vulnerability_id,method) VALUES(?,?,?,'exact-identifier')`)
	insSev := prep(`INSERT INTO severity_assessment(source,record_id,type,vector,version,score,rating,published_at,ingested_at,validation,reason) VALUES(?,?,?,?,?,?,?,?,?,?,?)`)
	insCWE := prep(`INSERT INTO weakness_link(vulnerability_id,cwe_id) VALUES(?,?) ON CONFLICT DO NOTHING`)
	insKEV := prep(`INSERT INTO kev(cve,json,recorded_at,status,vulnerability_id) VALUES(?,?,?,'linked',?)`)
	insEPSS := prep(`INSERT INTO epss_history(cve,score_date,score,percentile,status,recorded_at,vulnerability_id) VALUES(?,?,?,?,?,?,?)`)
	now := "2024-01-01T00:00:00Z"
	mod := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	exec := func(s *sql.Stmt, args ...any) {
		if _, err := s.ExecContext(ctx, args...); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < n; i++ {
		cve := fmt.Sprintf("CVE-2024-%06d", i)
		ghsa := fmt.Sprintf("GHSA-aaaa-bbbb-%06d", i)
		pkg := fmt.Sprintf("pkg-%d", i%3000)
		rng := []model.Range{{Type: "SEMVER", Events: []model.Event{{Introduced: "0"}, {Fixed: fmt.Sprintf("1.%d.0", i%40)}}}}
		recs := []model.Record{
			{Source: "nvd", ID: cve, Summary: "synthetic " + cve, Modified: mod, Published: mod, Weaknesses: []string{fmt.Sprintf("CWE-%d", 20+i%80)},
				Affected: []model.Affected{{Kind: "package", Ecosystem: "PyPI", Name: pkg, Versions: []string{fmt.Sprintf("1.%d.0", i%40)}}}},
			{Source: "osv", ID: ghsa, Aliases: []string{cve}, Modified: mod, Published: mod,
				Affected:   []model.Affected{{Kind: "package", Ecosystem: "PyPI", Name: pkg, Ranges: rng}},
				References: []model.Reference{{Type: "FIX", URL: fmt.Sprintf("https://example.test/fix/%d", i)}}},
		}
		exec(insVuln, cve)
		exec(insVI, cve, cve)
		exec(insVI, ghsa, cve)
		for _, r := range recs {
			body, err := json.Marshal(&r)
			if err != nil {
				t.Fatal(err)
			}
			ids, _ := json.Marshal(append([]string{r.ID}, r.Aliases...))
			exec(insRec, r.Source, r.ID, fmt.Sprintf("h%d%s", i, r.Source), string(ids), string(body), "2024-01-01T00:00:00Z", nil, now, now)
			exec(insIdent, r.Source, r.ID, r.ID)
			for _, a := range r.Aliases {
				exec(insIdent, r.Source, r.ID, a)
			}
			exec(insRV, r.Source, r.ID, cve)
		}
		exec(insSev, "nvd", cve, "cvss3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1", 9.8, "CRITICAL", nil, now, "valid", nil)
		exec(insCWE, cve, fmt.Sprintf("CWE-%d", 20+i%80))
		if i%50 == 0 {
			body, _ := json.Marshal(model.KEV{CVE: cve, DateAdded: "2024-02-01", DueDate: "2024-02-22", Ransomware: "unknown"})
			exec(insKEV, cve, string(body), now, cve)
		}
		if i%10 == 0 {
			exec(insEPSS, cve, "2024-03-01", 0.01*float64(i%100), 0.5, "linked", now, cve)
		}
	}
	for i := 0; i < unlinkedEPSS; i++ {
		exec(insEPSS, fmt.Sprintf("CVE-2030-%06d", i), "2024-03-01", 0.001, 0.1, "pending", now, nil)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// heapSampler records the peak HeapAlloc until stop is called.
type heapSampler struct {
	stop chan struct{}
	done sync.WaitGroup
	peak uint64
}

func startHeapSampler() *heapSampler {
	h := &heapSampler{stop: make(chan struct{})}
	h.done.Add(1)
	go func() {
		defer h.done.Done()
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > h.peak {
				h.peak = ms.HeapAlloc
			}
			select {
			case <-h.stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}()
	return h
}

func (h *heapSampler) Stop() uint64 {
	close(h.stop)
	h.done.Wait()
	return h.peak
}

func projectPeakHeap(t *testing.T, canon, out string) (Stats, uint64, time.Duration) {
	t.Helper()
	runtime.GC()
	debug.FreeOSMemory()
	p := &Projector{
		CanonicalPath: canon, Policy: Policy{Level: LevelComplete}, Clock: fixedClock{},
		Sinks: []NamedSink{{"sqlite", NewSQLiteSink(filepath.Join(out, "graph.db"))}},
	}
	hs := startHeapSampler()
	start := time.Now()
	st, err := p.Run(context.Background())
	took := time.Since(start)
	peak := hs.Stop()
	if err != nil {
		t.Fatal(err)
	}
	return st, peak, took
}

func TestProjectionStreamsWithBoundedHeap(t *testing.T) {
	n, bound := scaleVulnsFull, scaleTimeBound
	if testing.Short() {
		n, bound = scaleVulnsShort, scaleTimeBound/2
	}
	dir := t.TempDir()
	canon := filepath.Join(dir, "canonical.db")
	seedScale(t, canon, n, n*2)
	small := filepath.Join(dir, "small.db")
	seedScale(t, small, n/5, n*2/5)

	outSmall, outBig := filepath.Join(dir, "o-small"), filepath.Join(dir, "o-big")
	_, peakSmall, _ := projectPeakHeap(t, small, outSmall)
	st, peakBig, took := projectPeakHeap(t, canon, outBig)
	t.Logf("%d vulnerabilities: nodes=%d edges=%d took=%s peak HeapAlloc=%d MiB (5x smaller store: %d MiB)",
		n, sumInts(st.Nodes), sumInts(st.Edges), took.Round(time.Millisecond), peakBig>>20, peakSmall>>20)

	if st.Vulnerabilities != n {
		t.Fatalf("vulnerabilities = %d, want %d", st.Vulnerabilities, n)
	}
	if took > bound {
		t.Errorf("projection took %s, bound %s", took, bound)
	}
	if peakBig > scaleHeapBound {
		t.Errorf("peak HeapAlloc %d MiB exceeds the bound of %d MiB", peakBig>>20, scaleHeapBound>>20)
	}
	// Streaming means the peak does not follow the dataset: 5x the data must not cost 3x the heap.
	if peakBig > 3*peakSmall+(32<<20) {
		t.Errorf("heap grows with the dataset: %d MiB for %d vulnerabilities vs %d MiB for %d", peakBig>>20, n, peakSmall>>20, n/5)
	}
	// The output is complete and the scratch files are gone.
	db := openRO(t, filepath.Join(outBig, "graph.db"))
	defer db.Close()
	if got := countRows(t, db, `SELECT COUNT(*) FROM nodes WHERE type='Vulnerability'`); got != n {
		t.Fatalf("Vulnerability nodes = %d", got)
	}
	ents, _ := os.ReadDir(outBig)
	for _, e := range ents {
		if e.Name() != "graph.db" {
			t.Errorf("leftover file %s", e.Name())
		}
	}
}

// EPSS and KEV nodes exist only for rows linked to a vulnerability in the graph.
func TestEPSSAndKEVProjectedOnlyWhenLinked(t *testing.T) {
	dir := t.TempDir()
	canon := filepath.Join(dir, "canonical.db")
	const n, unlinked = 200, 5000
	seedScale(t, canon, n, unlinked)
	st, _, _ := projectPeakHeap(t, canon, dir)
	wantEPSS, wantKEV := (n+9)/10, (n+49)/50
	if st.Nodes[NodeEPSSAssessment] != wantEPSS || st.Nodes[NodeKEVEntry] != wantKEV {
		t.Fatalf("EPSS nodes %d (want %d), KEV nodes %d (want %d)", st.Nodes[NodeEPSSAssessment], wantEPSS, st.Nodes[NodeKEVEntry], wantKEV)
	}
	db := openRO(t, filepath.Join(dir, "graph.db"))
	defer db.Close()
	if got := countRows(t, db, `SELECT COUNT(*) FROM nodes WHERE type='EPSSAssessment' AND id LIKE 'epss:CVE-2030-%'`); got != 0 {
		t.Fatalf("%d EPSS nodes for CVEs that are not in the graph", got)
	}
	// Every EPSS and KEV node hangs off a Vulnerability node.
	for _, q := range []string{
		`SELECT COUNT(*) FROM nodes n WHERE n.type IN ('EPSSAssessment','KEVEntry') AND NOT EXISTS (SELECT 1 FROM edges e JOIN nodes v ON v.id=e.src AND v.type='Vulnerability' WHERE e.dst=n.id)`,
	} {
		if got := countRows(t, db, q); got != 0 {
			t.Fatalf("%d orphan EPSS/KEV nodes", got)
		}
	}
}

func openRO(t testing.TB, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", roDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func countRows(t testing.TB, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func sumInts(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// Incremental projection on a synthetic store with heavy sharing (3000 packages across many
// vulnerabilities): after a few direct edits only those vulnerabilities are re-projected and the
// result equals a full rebuild.
func TestIncrementalOnSyntheticStoreReprojectsOnlyChanges(t *testing.T) {
	const n = 3000
	dir := t.TempDir()
	canon := filepath.Join(dir, "canonical.db")
	seedScale(t, canon, n, 1000)
	outInc := filepath.Join(dir, "inc")
	run := func(out string, incremental bool) Stats {
		t.Helper()
		p := &Projector{
			CanonicalPath: canon, Policy: Policy{Level: LevelComplete}, Clock: fixedClock{}, Incremental: incremental,
			Sinks: []NamedSink{{"sqlite", NewSQLiteSink(filepath.Join(out, "graph.db"))}},
		}
		st, err := p.Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	if st := run(outInc, true); st.Mode != "full" || st.Vulnerabilities != n {
		t.Fatalf("first run: %+v", st)
	}

	st, err := canonical.Open(canon)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := st.DB.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	mod := time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)
	for _, i := range []int{3, 17, 400, 2999} { // records rewritten: new package and version
		cve := fmt.Sprintf("CVE-2024-%06d", i)
		r := model.Record{Source: "nvd", ID: cve, Summary: "edited", Modified: mod, Published: mod,
			Affected: []model.Affected{{Kind: "package", Ecosystem: "npm", Name: fmt.Sprintf("edited-%d", i%3), Versions: []string{"9.9.9"}}}}
		body, _ := json.Marshal(&r)
		exec(`UPDATE source_record SET json=?, content_hash=? WHERE source='nvd' AND external_id=?`, string(body), "edited"+cve, cve)
	}
	for _, i := range []int{20, 21} { // new linked EPSS date and KEV
		cve := fmt.Sprintf("CVE-2024-%06d", i)
		exec(`INSERT INTO epss_history(cve,score_date,score,percentile,status,recorded_at,vulnerability_id) VALUES(?,?,?,?,'linked','2024-05-01T00:00:00Z',?)`, cve, "2024-05-01", 0.9, 0.99, cve)
		body, _ := json.Marshal(model.KEV{CVE: cve, DateAdded: "2024-05-01", Ransomware: "unknown"})
		exec(`INSERT INTO kev(cve,json,recorded_at,status,vulnerability_id) VALUES(?,?,?,'linked',?)`, cve, string(body), "2024-05-01T00:00:00Z", cve)
	}
	exec(`INSERT INTO weakness_link(vulnerability_id,cwe_id) VALUES('CVE-2024-000030','CWE-1000')`)
	// One vulnerability disappears (its records and identifiers are removed).
	exec(`DELETE FROM record_vulnerability WHERE vulnerability_id='CVE-2024-000050'`)
	exec(`DELETE FROM vulnerability_identifier WHERE vulnerability_id='CVE-2024-000050'`)
	exec(`DELETE FROM vulnerability WHERE id='CVE-2024-000050'`)
	for i := 0; i < 500; i++ {
		exec(`INSERT INTO epss_history(cve,score_date,score,percentile,status,recorded_at) VALUES(?,?,?,?,'pending','2024-05-01T00:00:00Z')`, fmt.Sprintf("CVE-2031-%06d", i), "2024-05-01", 0.5, 0.5)
	}
	st.Close()

	got := run(outInc, true)
	if got.Mode != "incremental" {
		t.Fatalf("mode = %q", got.Mode)
	}
	if got.Changed < 8 || got.Changed > 20 {
		t.Fatalf("re-projected %d vulnerabilities, expected the ~10 edited ones", got.Changed)
	}
	full := filepath.Join(dir, "full")
	run(full, false)
	if err := CompareDBs(filepath.Join(full, "graph.db"), filepath.Join(outInc, "graph.db")); err != nil {
		t.Fatalf("incremental differs from full: %v", err)
	}
	if got.Vulnerabilities != n-1 {
		t.Fatalf("vulnerabilities = %d, want %d", got.Vulnerabilities, n-1)
	}
}
