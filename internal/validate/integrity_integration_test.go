//go:build integration

package validate_test

import (
	"context"
	"testing"

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
	rep, err := validate.Run(ctx, c, "integrity", nil, nil)
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
	if !got["reject"] || !got["endpoints:AFFECTS"] || len(rep.Failed) != 2 {
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
