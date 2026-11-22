//go:build integration

package validate_test

import (
	"context"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/graph/graphtest"
	"github.com/bellu/bskg/internal/migrate"
	"github.com/bellu/bskg/internal/validate"
)

func TestMain(m *testing.M) { graphtest.Main(m) }

func TestIntegrityOnSmallGraph(t *testing.T) {
	c := graphtest.New(t)
	ctx := context.Background()
	files, err := migrate.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	r := &migrate.Runner{Store: migrate.GraphStore{C: c}, Files: files, Owner: "validate-test"}
	if _, err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE (:Author {authorName:'a'})-[:WRITES]->(e:Exploit {eid:'1'})-[:EXPLOITS]->(:Vulnerability {cveID:'CVE-2020-0001', description:'x'})`,
		`MATCH (e:Exploit {eid:'1'}) CREATE (e)-[:EXPLOITS]->(:Vulnerability {cveID:'CVE-2020-0002', description:'** REJECT ** y'})`,
		`MATCH (a:Author) MATCH (v:Vulnerability {cveID:'CVE-2020-0001'}) CREATE (a)-[:AFFECTS]->(v)`,
	} {
		if _, err := c.Auto(ctx, q, nil); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := validate.Run(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Passed() {
		t.Fatal("expected failure")
	}
	got := map[string]bool{}
	for _, f := range rep.Failed {
		got[f] = true
	}
	// The fixture has no exploitability fields and no BuildMeta, so the
	// exploitability and smoke checks fail as well.
	if !got["reject"] || !got["endpoints:AFFECTS"] || !got["exploitability"] || !got["smoke"] || len(rep.Failed) != 4 {
		t.Fatalf("failed=%v", rep.Failed)
	}
	if rep.Reject.Count != 1 || rep.Reject.Examples[0] != "CVE-2020-0002" {
		t.Fatalf("%+v", rep.Reject)
	}
	counts, err := validate.CollectCounts(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if counts["Vulnerability"] != 2 || counts["EXPLOITS"] != 2 || counts["exploitableVulnerability"] != 2 || counts["exactlyOneExploit"] != 2 {
		t.Fatalf("%v", counts)
	}
}

func migrated(t *testing.T) *graph.Client {
	t.Helper()
	c := graphtest.New(t)
	files, err := migrate.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	r := &migrate.Runner{Store: migrate.GraphStore{C: c}, Files: files, Owner: "validate-test"}
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c
}

func exec(t *testing.T, c *graph.Client, qs ...string) {
	t.Helper()
	for _, q := range qs {
		if _, err := c.Auto(context.Background(), q, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func failedSet(r validate.Report) map[string]bool {
	m := map[string]bool{}
	for _, f := range r.Failed {
		m[f] = true
	}
	return m
}

func TestExploitDataExploitabilityAndUnsetChecks(t *testing.T) {
	c := migrated(t)
	ctx := context.Background()
	exec(t, c,
		`CREATE (v1:Vulnerability {cveID:'CVE-2020-0001', exploitability:1, exploitDate:[date('2020-02-01'), date('2020-03-01')]})
		 CREATE (v2:Vulnerability {cveID:'CVE-2020-0002', exploitability:0, exploitDate:[]})
		 CREATE (v3:Vulnerability {cveID:'CVE-2020-0003', exploitability:1, exploitDate:[date('2020-01-01')], gainedAccess:'x'})
		 CREATE (v4:Vulnerability {cveID:'CVE-2020-0004', exploitability:0, exploitDate:[]})
		 CREATE (e1:Exploit {eid:'1', exploitPublishDate:date('2020-03-01'), exploitType:'remote', platform:'linux', sources:['exploitdb'], p_exploitdb_run:'r', p_exploitdb_at:datetime(), p_exploitdb_ref:'1'})
		 CREATE (e2:Exploit {eid:'2', exploitPublishDate:date('2020-02-01'), code:'#!/bin/sh'})
		 CREATE (e3:Exploit {eid:'3', exploitPublishDate:date('2020-01-01')})
		 CREATE (e1)-[:EXPLOITS]->(v1), (e2)-[:EXPLOITS]->(v1), (e3)-[:EXPLOITS {removed:true}]->(v3), (e3)-[:EXPLOITS]->(v4)`)
	ed, err := validate.CollectExploitData(ctx, c)
	if err != nil || ed.Passed || ed.Count != 1 || ed.Examples[0].EID != "2" || ed.Examples[0].Props[0] != "code" {
		t.Fatalf("%+v %v", ed, err)
	}
	ex, err := validate.CollectExploitability(ctx, c)
	// v3 has only a removed EXPLOITS (inconsistent), v4 has an active one but exploitability 0.
	if err != nil || ex.Passed || ex.Count != 2 || len(ex.Examples) != 2 {
		t.Fatalf("%+v %v", ex, err)
	}
	us, err := validate.CollectUnsetProps(ctx, c)
	if err != nil || us.Passed || us.Count != 1 || us.GainedAccess != 1 || us.Examples[0] != "CVE-2020-0003" {
		t.Fatalf("%+v %v", us, err)
	}
}

func TestSmokeSummaryAndSelectedQueries(t *testing.T) {
	c := migrated(t)
	ctx := context.Background()
	exec(t, c,
		`MERGE (b:BuildMeta {id:'build'}) SET b.buildMode='sample', b.sampleLimit=5`,
		`CREATE (v:Vulnerability {cveID:'CVE-2020-0001', description:'A buffer overflow allows attackers', publishedDate:date('2020-05-05'), v3version:3.1, exploitability:0, exploitDate:[]})
		 CREATE (w:Weakness {cweID:'CWE-120'}) CREATE (v)-[:EXAMPLE_OF]->(w)`)
	qc, err := graph.New(graph.Params{URI: graphtest.URI(), User: "neo4j", Password: graphtest.Password(), Timeout: validate.QueryTimeout})
	if err != nil {
		t.Fatal(err)
	}
	defer qc.Close(ctx)
	out := t.TempDir() + "/report.json"
	rep, err := validate.Execute(ctx, qc, validate.Options{Out: out})
	if err != nil {
		t.Fatal(err)
	}
	// Sample without AFFECTS passes with a warning; products, vendors, domains and exploits are skipped.
	if !rep.Passed() || rep.BuildMode != "sample" || rep.Smoke == nil || !rep.Smoke.Passed || len(rep.Warnings) == 0 {
		t.Fatalf("%+v", rep)
	}
	qs := rep.Queries.([]validate.QueryResult)
	skipped := 0
	for _, q := range qs {
		if q.Skipped {
			skipped++
		} else if !q.Passed || q.Rows < 1 {
			t.Errorf("%+v", q)
		}
	}
	if len(qs) != 9 || skipped != 4 {
		t.Fatalf("queries=%+v", qs)
	}
	// The summary is in BuildMeta.
	recs, err := c.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, `MATCH (b:BuildMeta {id:'build'}) RETURN b.lastValidationStatus AS s, b.lastValidationMode AS m, b.lastValidationEndedAt IS NOT NULL AS e, b.lastValidationFailed AS f`, nil)
		if err != nil {
			return nil, err
		}
		rec, err := r.Single(ctx)
		if err != nil {
			return nil, err
		}
		return rec.AsMap(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	m := recs.(map[string]any)
	if m["s"] != "passed" || m["m"] != "sample" || m["e"] != true || m["f"] != int64(0) {
		t.Fatalf("%v", m)
	}
}

func TestSmokeFullModeFailsOnEmptyGraph(t *testing.T) {
	c := migrated(t)
	exec(t, c, `MERGE (b:BuildMeta {id:'build'}) SET b.buildMode='full'`)
	rep, err := validate.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if !failedSet(rep)["smoke"] || rep.Smoke == nil || rep.Smoke.Passed {
		t.Fatalf("%v", rep.Failed)
	}
}
