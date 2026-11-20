//go:build integration

package baseline_test

// Container-backed properties for the baseline loader. They share the one Neo4j
// test container, empty the database at the start of every iteration, and use
// tiny generated inputs (at most 8 to 12 rows per file), as the design's
// testing strategy prescribes for graph properties.

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"pgregory.net/rapid"

	"github.com/bellu/bskg/internal/baseline"
	"github.com/bellu/bskg/internal/change"
	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/graph/graphtest"
)

type provInfo struct {
	sources []string
	run     string
	ref     string
	hasAt   bool
}

type snapshot struct {
	g    *mgraph
	prov map[string]provInfo // same keys as nodes and rels
	job  map[string]any
}

func isProvKey(k string) bool { return k == "sources" || strings.HasPrefix(k, "p_vulkg_") }

func canonAny(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return "s:" + x, nil
	case int64:
		return fmt.Sprintf("i:%d", x), nil
	case float64:
		return "f:" + formatFloat(x), nil
	case bool:
		return fmt.Sprintf("b:%t", x), nil
	case neo4j.Date:
		return "d:" + time.Time(x).Format("2006-01-02"), nil
	case []any:
		items := make([]string, 0, len(x))
		for _, e := range x {
			switch y := e.(type) {
			case string:
				items = append(items, y)
			case neo4j.Date:
				items = append(items, time.Time(y).Format("2006-01-02"))
			default:
				return "", fmt.Errorf("unsupported list element %T", e)
			}
		}
		return canonList(items), nil
	}
	return "", fmt.Errorf("unsupported property type %T", v)
}

func formatFloat(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

func splitProps(p map[string]any) (map[string]string, provInfo, error) {
	out := map[string]string{}
	var pi provInfo
	for k, v := range p {
		if isProvKey(k) {
			switch k {
			case "sources":
				if l, ok := v.([]any); ok {
					for _, e := range l {
						s, _ := e.(string)
						pi.sources = append(pi.sources, s)
					}
				}
			case "p_vulkg_run":
				pi.run, _ = v.(string)
			case "p_vulkg_ref":
				pi.ref, _ = v.(string)
			case "p_vulkg_at":
				pi.hasAt = v != nil
			}
			continue
		}
		c, err := canonAny(v)
		if err != nil {
			return nil, pi, fmt.Errorf("property %s: %w", k, err)
		}
		out[k] = c
	}
	return out, pi, nil
}

const keyExpr = `coalesce(%[1]s.cveID, %[1]s.eid, %[1]s.authorName, %[1]s.cweID, %[1]s.domainName, %[1]s.productName, %[1]s.vendorName)`

var (
	cypherAllNodes = `MATCH (n) WHERE n:Vulnerability OR n:Exploit OR n:Author OR n:Weakness OR n:Domain OR n:Product OR n:Vendor
RETURN labels(n)[0] AS l, ` + fmt.Sprintf(keyExpr, "n") + ` AS k, properties(n) AS p`
	cypherAllRels = `MATCH (a)-[r:WRITES|EXPLOITS|EXAMPLE_OF|REFERS_TO|AFFECTS|BELONGS_TO]->(b)
RETURN type(r) AS t, labels(a)[0] AS al, ` + fmt.Sprintf(keyExpr, "a") + ` AS ak, labels(b)[0] AS bl, ` +
		fmt.Sprintf(keyExpr, "b") + ` AS bk, properties(r) AS p`
	cypherJobProps = `MATCH (j:Job {name: 'baseline-load'}) RETURN properties(j) AS p`
)

func readSnapshot(ctx context.Context, c *graph.Client) (*snapshot, error) {
	v, err := c.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		s := &snapshot{g: newMGraph(), prov: map[string]provInfo{}}
		res, err := tx.Run(ctx, cypherAllNodes, nil)
		if err != nil {
			return nil, err
		}
		recs, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			l, _ := r.Values[0].(string)
			k, _ := r.Values[1].(string)
			props, pi, err := splitProps(r.Values[2].(map[string]any))
			if err != nil {
				return nil, fmt.Errorf("node %s/%s: %w", l, k, err)
			}
			key := nkey(l, k)
			s.g.nodes[key] = props
			s.prov["n"+sep+key] = pi
		}
		if res, err = tx.Run(ctx, cypherAllRels, nil); err != nil {
			return nil, err
		}
		if recs, err = res.Collect(ctx); err != nil {
			return nil, err
		}
		for _, r := range recs {
			t, _ := r.Values[0].(string)
			al, _ := r.Values[1].(string)
			ak, _ := r.Values[2].(string)
			bl, _ := r.Values[3].(string)
			bk, _ := r.Values[4].(string)
			props, pi, err := splitProps(r.Values[5].(map[string]any))
			if err != nil {
				return nil, fmt.Errorf("relationship %s %s/%s: %w", t, al, ak, err)
			}
			key := strings.Join([]string{t, al, ak, bl, bk}, sep)
			s.g.rels[key] = &mrel{t, al, ak, bl, bk, props}
			s.prov["r"+sep+key] = pi
		}
		if res, err = tx.Run(ctx, cypherJobProps, nil); err != nil {
			return nil, err
		}
		rec, err := res.Single(ctx)
		if err != nil {
			return nil, fmt.Errorf("baseline job node: %w", err)
		}
		s.job = rec.Values[0].(map[string]any)
		return s, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*snapshot), nil
}

func queryInt(ctx context.Context, c *graph.Client, q string) (int64, error) {
	v, err := c.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, q, nil)
		if err != nil {
			return nil, err
		}
		rec, err := r.Single(ctx)
		if err != nil {
			return nil, err
		}
		return rec.Values[0], nil
	})
	if err != nil {
		return 0, err
	}
	n, _ := v.(int64)
	return n, nil
}

type fataler interface {
	Helper()
	Fatalf(format string, args ...any)
}

// verifySnapshot compares the stored graph, job counters, and provenance with
// the model. allowedRuns lists the run ids that may appear in provenance.
func verifySnapshot(t fataler, s *snapshot, want *mgraph, cn modelCounters, commit string, allowedRuns ...string) {
	t.Helper()
	if d := diffGraphs(want, s.g); d != "" {
		t.Fatalf("graph differs from the reference model:\n%s", d)
	}
	jobInt := func(k string) int64 { n, _ := s.job[k].(int64); return n }
	for k, want := range map[string]int64{
		baseline.JobPropBareNodes:         cn.bare,
		baseline.JobPropRejectDeleted:     cn.rejectNodes,
		baseline.JobPropRejectRelsDeleted: cn.rejectRels,
	} {
		if _, ok := s.job[k]; !ok || jobInt(k) != want {
			t.Fatalf("job.%s = %v, want %d", k, s.job[k], want)
		}
	}
	for step, want := range cn.missing {
		k := baseline.JobMissingPrefix + step
		if _, ok := s.job[k]; !ok || jobInt(k) != want {
			t.Fatalf("job.%s = %v, want %d", k, s.job[k], want)
		}
	}
	ok := map[string]bool{}
	for _, r := range allowedRuns {
		ok[r] = true
	}
	var keys []string
	for k := range s.prov {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := s.prov[k]
		show := strings.ReplaceAll(k, sep, "/")
		if len(p.sources) != 1 || p.sources[0] != "vulkg" {
			t.Fatalf("%s: sources = %v, want [vulkg]", show, p.sources)
		}
		if p.ref != commit {
			t.Fatalf("%s: p_vulkg_ref = %q, want the manifest commit %q", show, p.ref, commit)
		}
		if !ok[p.run] {
			t.Fatalf("%s: p_vulkg_run = %q, want one of %v", show, p.run, allowedRuns)
		}
		if !p.hasAt {
			t.Fatalf("%s: p_vulkg_at missing", show)
		}
	}
}

func loadGenerated(ctx context.Context, c *graph.Client, dir string, batch int) (baseline.RunState, *baseline.Manifest, error) {
	m, err := genManifest(dir)
	if err != nil {
		return baseline.RunState{}, nil, err
	}
	st, err := baseline.Load(ctx, baseline.LoadOptions{
		Manifest: m, Fetcher: &baseline.Fetcher{LocalDir: dir}, Client: c, BatchSize: batch,
	})
	return st, m, err
}

// Feature: bellu-security-knowledge-graph, Property 23: Loader matches the reference model
// **Validates: Requirements 4.4, 4.5, 4.6, 4.7, 4.13**
func TestPropertyLoaderMatchesReferenceModel(t *testing.T) {
	c := graphtest.New(t)
	ctx := context.Background()
	dir := t.TempDir()
	rapid.Check(t, func(rt *rapid.T) {
		if err := graphtest.Reset(ctx, c); err != nil {
			rt.Fatalf("reset: %v", err)
		}
		ts := genTables(rt, true)
		batch := rapid.IntRange(1, 6).Draw(rt, "batch")
		if err := writeTables(dir, ts); err != nil {
			rt.Fatal(err)
		}
		st, m, err := loadGenerated(ctx, c, dir, batch)
		if err != nil {
			rt.Fatalf("load: %v", err)
		}
		want := newMGraph()
		cn, err := want.applyLoad(ts)
		if err != nil {
			rt.Fatal(err)
		}
		s, err := readSnapshot(ctx, c)
		if err != nil {
			rt.Fatal(err)
		}
		verifySnapshot(rt, s, want, cn, m.Upstream.Commit, st.RunID)
	})
}

// checkReload loads twice and compares both states with the model. Without bare
// nodes the second load must change nothing (Requirement 4.10).
func checkReload(t *testing.T, allowBare bool) {
	c := graphtest.New(t)
	ctx := context.Background()
	dir := t.TempDir()
	rapid.Check(t, func(rt *rapid.T) {
		if err := graphtest.Reset(ctx, c); err != nil {
			rt.Fatalf("reset: %v", err)
		}
		ts := genTables(rt, allowBare)
		batch := rapid.IntRange(1, 6).Draw(rt, "batch")
		if err := writeTables(dir, ts); err != nil {
			rt.Fatal(err)
		}
		want1 := newMGraph()
		cn1, err := want1.applyLoad(ts)
		if err != nil {
			rt.Fatal(err)
		}
		st1, m, err := loadGenerated(ctx, c, dir, batch)
		if err != nil {
			rt.Fatalf("first load: %v", err)
		}
		s1, err := readSnapshot(ctx, c)
		if err != nil {
			rt.Fatal(err)
		}
		verifySnapshot(rt, s1, want1, cn1, m.Upstream.Commit, st1.RunID)

		want2 := want1.clone()
		cn2, err := want2.applyLoad(ts)
		if err != nil {
			rt.Fatal(err)
		}
		st2, _, err := loadGenerated(ctx, c, dir, batch)
		if err != nil {
			rt.Fatalf("second load: %v", err)
		}
		if st2.RunID == st1.RunID {
			rt.Fatalf("a finished load must not be resumed")
		}
		s2, err := readSnapshot(ctx, c)
		if err != nil {
			rt.Fatal(err)
		}
		if !allowBare {
			if d := diffGraphs(s1.g, s2.g); d != "" {
				rt.Fatalf("second load changed the graph:\n%s", d)
			}
			// Nothing new was written, so every item still carries the first run's provenance.
			verifySnapshot(rt, s2, want2, cn2, m.Upstream.Commit, st1.RunID)
		} else {
			verifySnapshot(rt, s2, want2, cn2, m.Upstream.Commit, st1.RunID, st2.RunID)
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 24: Loader idempotence and resumability
// **Validates: Requirements 4.10, 4.11**
//
// Loading a finished baseline again leaves the graph unchanged when the files
// create no bare nodes.
func TestPropertyLoaderIdempotentReload(t *testing.T) { checkReload(t, false) }

// Feature: bellu-security-knowledge-graph, Property 24: Loader idempotence and resumability
// **Validates: Requirements 4.10**
//
// With bare nodes (add-properties rows without a node row) a reload is not a
// no-op: step 8 leaves the bare nodes in the graph, so on the second load steps
// 5 and 7 find them and add EXPLOITS and EXAMPLE_OF relationships that the first
// load could not create. The loader must still match the model of that reload.
func TestPropertyLoaderReloadWithBareNodesMatchesModel(t *testing.T) { checkReload(t, true) }

// Feature: bellu-security-knowledge-graph, Property 24: Loader idempotence and resumability
// **Validates: Requirements 4.11, 4.13**
//
// Interrupting a load after any step (or before it), then resuming, gives the
// same graph and counters as an uninterrupted load, keeps the run id (so
// provenance run ids stay stable), does not rerun completed steps, and writes
// exactly one baselineLoad Change_Record.
func TestPropertyLoaderResumeEquivalence(t *testing.T) {
	c := graphtest.New(t)
	ctx := context.Background()
	dir := t.TempDir()
	rapid.Check(t, func(rt *rapid.T) {
		if err := graphtest.Reset(ctx, c); err != nil {
			rt.Fatalf("reset: %v", err)
		}
		ts := genTables(rt, true)
		batch := rapid.IntRange(1, 6).Draw(rt, "batch")
		mode := rapid.SampledFrom([]string{"before", "after"}).Draw(rt, "mode")
		if err := writeTables(dir, ts); err != nil {
			rt.Fatal(err)
		}
		m, err := genManifest(dir)
		if err != nil {
			rt.Fatal(err)
		}
		files := map[string]string{}
		for logical, name := range modelScriptNames {
			files[logical] = filepath.Join(dir, name)
		}
		names := []string{}
		for _, s := range (baseline.Loader{}).StepList() {
			names = append(names, s.Name)
		}
		idx := rapid.IntRange(0, len(names)-1).Draw(rt, "interruptAt")

		calls := map[string]int{}
		failed := false
		build := func(st baseline.RunState) []baseline.Step {
			l := baseline.Loader{
				W: baseline.Writer{C: c, BatchSize: batch}, Files: files,
				RunID: st.RunID, Ref: m.Upstream.Commit, At: st.StartedAt,
			}
			steps := l.StepList()
			for i := range steps {
				i, s := i, steps[i]
				steps[i].Run = func(ctx context.Context) error {
					calls[s.Name]++
					if i == idx && mode == "before" && !failed {
						failed = true
						return errors.New("injected interruption before the step")
					}
					if err := s.Run(ctx); err != nil {
						return err
					}
					if i == idx && mode == "after" && !failed {
						failed = true
						return errors.New("injected interruption after the step")
					}
					return nil
				}
			}
			return steps
		}
		r := baseline.Runner{
			Store: baseline.GraphJobStore{C: c}, Commit: m.Upstream.Commit, Build: build, NewRunID: change.NewID,
		}
		st1, err := r.Run(ctx)
		if err == nil || !strings.Contains(err.Error(), names[idx]) {
			rt.Fatalf("want a failure naming step %s, got %v", names[idx], err)
		}
		st2, err := r.Run(ctx)
		if err != nil {
			rt.Fatalf("resume: %v", err)
		}
		if st2.RunID != st1.RunID || st2.LastCompleted != baseline.StepFinalize {
			rt.Fatalf("resume state %+v after %+v", st2, st1)
		}
		for i, n := range names {
			want := 1
			if i == idx {
				want = 2
			}
			if calls[n] != want {
				rt.Fatalf("step %s ran %d times, want %d (interrupted step %s, mode %s)", n, calls[n], want, names[idx], mode)
			}
		}

		want := newMGraph()
		cn, err := want.applyLoad(ts)
		if err != nil {
			rt.Fatal(err)
		}
		s, err := readSnapshot(ctx, c)
		if err != nil {
			rt.Fatal(err)
		}
		verifySnapshot(rt, s, want, cn, m.Upstream.Commit, st1.RunID)
		n, err := queryInt(ctx, c, `MATCH (c:Change {type:'baselineLoad', runId: '`+st1.RunID+`'}) RETURN count(c)`)
		if err != nil || n != 1 {
			rt.Fatalf("baselineLoad records for run %s = %d (err %v), want 1", st1.RunID, n, err)
		}
		if n, err = queryInt(ctx, c, `MATCH (c:Change {type:'baselineLoad'}) RETURN count(c)`); err != nil || n != 1 {
			rt.Fatalf("baselineLoad records = %d (err %v), want 1", n, err)
		}
		if n, err = queryInt(ctx, c, `MATCH (b:BuildMeta {id:'build'}) WHERE b.baselineLoadedAt IS NOT NULL RETURN count(b)`); err != nil || n != 1 {
			rt.Fatalf("BuildMeta.baselineLoadedAt set = %d (err %v), want 1", n, err)
		}
	})
}
