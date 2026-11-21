//go:build integration

package upsert_test

import (
	"context"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/graph/graphtest"
	"github.com/bellu/bskg/internal/source"
	"github.com/bellu/bskg/internal/upsert"
)

const itGHSA = "GHSA-c2f3-4gh5-wxmp"

func runBatch(ctx context.Context, t *testing.T, c *graph.Client, b upsert.Batch) {
	t.Helper()
	_, err := c.Write(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		st, err := upsert.Load(ctx, tx, b)
		if err != nil {
			return nil, err
		}
		w, recs, _ := upsert.Plan(st, b, upsert.RunContext{Source: "ghsa", RunID: "r1", Now: time.Now().UTC()})
		return nil, upsert.Apply(ctx, tx, w, recs)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func count(ctx context.Context, t *testing.T, c *graph.Client, q string, p map[string]any) int64 {
	t.Helper()
	v, err := c.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, q, p)
		if err != nil {
			return nil, err
		}
		rec, err := res.Single(ctx)
		if err != nil {
			return nil, err
		}
		return rec.Values[0], nil
	})
	if err != nil {
		t.Fatal(err)
	}
	n, _ := v.(int64)
	return n
}

// An advisory-keyed Vulnerability that already has relationships is merged
// into the CVE node when a later record names the CVE alias (Requirement 9.7).
func TestAdvisoryMergeIntoCVE(t *testing.T) {
	c := graphtest.New(t)
	ctx := context.Background()
	if _, err := c.Auto(ctx, `
CREATE (a:Vulnerability {cveID: $adv, aliases: ['PYSEC-2021-1'], sources: ['ghsa'], exploitability: 0, exploitDate: [], summary: 'from advisory'})
CREATE (v:Vulnerability {cveID: 'CVE-2021-1001', sources: ['nvd'], exploitability: 0, exploitDate: []})
CREATE (p1:Package {purl: 'pkg:npm/one'}), (p2:Package {purl: 'pkg:npm/two'})
CREATE (a)-[:AFFECTS_PACKAGE {introduced: '1.0.0', sources: ['ghsa']}]->(p1)
CREATE (a)-[:AFFECTS_PACKAGE {introduced: '2.0.0', sources: ['ghsa']}]->(p2)
CREATE (v)-[:AFFECTS_PACKAGE {introduced: '2.0.0', sources: ['osv']}]->(p2)`,
		map[string]any{"adv": itGHSA}); err != nil {
		t.Fatal(err)
	}
	batch := upsert.Batch{{ID: itGHSA, N: source.Normalized{
		Advisory: &source.Advisory{ID: itGHSA, CVEs: []string{"CVE-2021-1001"}},
		Entities: []source.Entity{{Ref: source.Ref{Kind: source.RefAdvisory, Raw: itGHSA}, Props: map[string]any{"description": "d"}}},
	}}}
	for i := 0; i < 2; i++ { // the second run must change nothing
		runBatch(ctx, t, c, batch)
		if n := count(ctx, t, c, `MATCH (a:Vulnerability {cveID: $adv}) RETURN count(a)`, map[string]any{"adv": itGHSA}); n != 0 {
			t.Fatalf("run %d: advisory node still exists", i)
		}
		if n := count(ctx, t, c, `MATCH (:Vulnerability {cveID: 'CVE-2021-1001'})-[r:AFFECTS_PACKAGE]->(:Package) RETURN count(r)`, nil); n != 2 {
			t.Fatalf("run %d: CVE has %d AFFECTS_PACKAGE, want 2 (the duplicate one is skipped)", i, n)
		}
		if n := count(ctx, t, c, `MATCH (v:Vulnerability {cveID: 'CVE-2021-1001'}) WHERE $adv IN v.aliases AND 'PYSEC-2021-1' IN v.aliases AND v.summary = 'from advisory' RETURN count(v)`,
			map[string]any{"adv": itGHSA}); n != 1 {
			t.Fatalf("run %d: aliases or copied properties missing", i)
		}
		if n := count(ctx, t, c, `MATCH (c:Change {type: 'vulnerabilityMerged'}) RETURN count(c)`, nil); n != 1 {
			t.Fatalf("run %d: %d vulnerabilityMerged records, want 1", i, n)
		}
	}
}

// Two CVE aliases: attach to both, never merge, one aliasConflict record.
func TestAdvisoryAliasConflict(t *testing.T) {
	c := graphtest.New(t)
	ctx := context.Background()
	batch := upsert.Batch{{ID: itGHSA, N: source.Normalized{
		Advisory: &source.Advisory{ID: itGHSA, CVEs: []string{"CVE-2021-1001", "CVE-2021-1002"}},
		Entities: []source.Entity{
			{Ref: source.Ref{Kind: source.RefAdvisory, Raw: itGHSA}},
			{Ref: source.Ref{Kind: source.RefPackage, Raw: "pkg:npm/one"}},
		},
		Rels: []source.Rel{{From: source.Ref{Kind: source.RefAdvisory, Raw: itGHSA}, To: source.Ref{Kind: source.RefPackage, Raw: "pkg:npm/one"}, Type: "AFFECTS_PACKAGE"}},
	}}}
	for i := 0; i < 2; i++ {
		runBatch(ctx, t, c, batch)
	}
	if n := count(ctx, t, c, `MATCH (:Vulnerability)-[r:AFFECTS_PACKAGE]->(:Package) RETURN count(r)`, nil); n != 2 {
		t.Fatalf("%d AFFECTS_PACKAGE, want 2", n)
	}
	if n := count(ctx, t, c, `MATCH (c:Change {type: 'aliasConflict'}) RETURN count(c)`, nil); n != 1 {
		t.Fatalf("%d aliasConflict records, want 1", n)
	}
	if n := count(ctx, t, c, `MATCH (v:Vulnerability {cveID: $adv}) RETURN count(v)`, map[string]any{"adv": itGHSA}); n != 0 {
		t.Fatal("no advisory node expected")
	}
}
