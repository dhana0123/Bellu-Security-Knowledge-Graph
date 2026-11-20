//go:build integration

package baseline_test

import (
	"context"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/baseline"
	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/graph/graphtest"
)

func fixtureLoader(c *graph.Client) baseline.Loader {
	d := "../../testdata/baseline/"
	return baseline.Loader{
		W: baseline.Writer{C: c, BatchSize: 7},
		Files: map[string]string{
			baseline.LogicalVulnerabilityNodes:         d + "VulnerabilityNodes.csv",
			baseline.LogicalVulnerabilityAddProperties: d + "VulnerabilityNodesAddProperties.csv",
			baseline.LogicalExploitNodes:               d + "ExploitNodes.csv",
			baseline.LogicalHasExploit:                 d + "Vulnerability_HAS_EXPLOIT_Exploit_relationship.csv",
			baseline.LogicalWeaknessNodes:              d + "WeaknessNodes.csv",
			baseline.LogicalDomainRelationship:         d + "DomainNodes_Vulnerability_HAS_REFERENCE_Domain_relationship.csv",
			baseline.LogicalProductVendorAffects:       d + "ProductNodes_VendorNodes_Vulnerability_AFFECTS_Product_BELONGS_TO_Vendor.csv",
			baseline.LogicalAffectsAddProperty:         d + "AffectsAddProperty.csv",
		},
		RunID: "RUN1", Ref: "deadbeef", At: time.Now(),
	}
}

func count(t *testing.T, c *graph.Client, q string) int64 {
	t.Helper()
	v, err := c.Read(context.Background(), func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
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
		t.Fatal(err)
	}
	n, _ := v.(int64)
	return n
}

func TestSteps1to8Fixture(t *testing.T) {
	c := graphtest.New(t)
	ctx := context.Background()
	l := fixtureLoader(c)

	check := func(label, q string, want int64) {
		t.Helper()
		if got := count(t, c, q); got != want {
			t.Errorf("%s: got %d want %d", label, got, want)
		}
	}

	if err := l.Steps1to8(ctx); err != nil {
		t.Fatal(err)
	}
	check("Vulnerability", `MATCH (n:Vulnerability) RETURN count(n)`, 43)
	check("Exploit", `MATCH (n:Exploit) RETURN count(n)`, 15)
	check("Author", `MATCH (n:Author) RETURN count(n)`, 10)
	check("Weakness", `MATCH (n:Weakness) RETURN count(n)`, 12)
	check("WRITES", `MATCH ()-[r:WRITES]->() RETURN count(r)`, 15)
	check("EXPLOITS", `MATCH ()-[r:EXPLOITS]->() RETURN count(r)`, 14)
	check("EXAMPLE_OF", `MATCH ()-[r:EXAMPLE_OF]->() RETURN count(r)`, 28)
	check("missing_exploits_rel", `MATCH (j:Job {name:'baseline-load'}) RETURN j.missing_exploits_rel`, 3)
	check("missing_example_of", `MATCH (j:Job {name:'baseline-load'}) RETURN j.missing_example_of`, 6)
	check("missing_writes", `MATCH (j:Job {name:'baseline-load'}) RETURN j.missing_writes`, 0)
	check("bareNodes", `MATCH (j:Job {name:'baseline-load'}) RETURN j.bareNodes`, 3)
	check("marker removed", `MATCH (v:Vulnerability) WHERE v.bskgBare IS NOT NULL RETURN count(v)`, 0)

	// Decimal scores, first-row-wins on duplicates, bare node shape.
	check("decimal v2impactScore", `MATCH (v:Vulnerability {cveID:'CVE-2019-1001'}) WHERE v.v2impactScore = 2.8 RETURN count(v)`, 1)
	check("1005 first row", `MATCH (v:Vulnerability {cveID:'CVE-2019-1005'}) WHERE v.numOfReference = 6 RETURN count(v)`, 1)
	check("1008 last row", `MATCH (v:Vulnerability {cveID:'CVE-2019-1008'}) WHERE v.gainedAccess = 'Gain Privileges' AND v.vulnerabilityType = ['Bypass'] RETURN count(v)`, 1)
	check("bare node props", `MATCH (v:Vulnerability {cveID:'CVE-2018-9001'}) WHERE v.description IS NULL AND v.gainedAccess IS NULL AND v.sources = ['vulkg'] RETURN count(v)`, 1)
	check("provenance on rel", `MATCH ()-[r:EXPLOITS]->() WHERE r.sources = ['vulkg'] AND r.p_vulkg_ref = 'deadbeef' RETURN count(r)`, 14)

	// Idempotent rerun: same counts, bare count unchanged.
	if err := l.Steps1to8(ctx); err != nil {
		t.Fatal(err)
	}
	check("Vulnerability rerun", `MATCH (n:Vulnerability) RETURN count(n)`, 43)
	check("EXPLOITS rerun", `MATCH ()-[r:EXPLOITS]->() RETURN count(r)`, 14)
	check("bareNodes rerun", `MATCH (j:Job {name:'baseline-load'}) RETURN j.bareNodes`, 3)
	check("missing rerun", `MATCH (j:Job {name:'baseline-load'}) RETURN j.missing_example_of`, 6)
}

func TestAllStepsFixture(t *testing.T) {
	c := graphtest.New(t)
	ctx := context.Background()
	l := fixtureLoader(c)

	check := func(label, q string, want int64) {
		t.Helper()
		if got := count(t, c, q); got != want {
			t.Errorf("%s: got %d want %d", label, got, want)
		}
	}
	job := func(prop string) string {
		return `MATCH (j:Job {name:'baseline-load'}) RETURN j.` + prop
	}
	verify := func(suffix string) {
		check("Vulnerability"+suffix, `MATCH (n:Vulnerability) RETURN count(n)`, 40)
		check("Domain"+suffix, `MATCH (n:Domain) RETURN count(n)`, 9)
		check("Product"+suffix, `MATCH (n:Product) RETURN count(n)`, 14)
		check("Vendor"+suffix, `MATCH (n:Vendor) RETURN count(n)`, 13)
		check("REFERS_TO"+suffix, `MATCH ()-[r:REFERS_TO]->() RETURN count(r)`, 37)
		check("AFFECTS"+suffix, `MATCH ()-[r:AFFECTS]->() RETURN count(r)`, 37)
		check("BELONGS_TO"+suffix, `MATCH ()-[r:BELONGS_TO]->() RETURN count(r)`, 15)
		check("EXPLOITS"+suffix, `MATCH ()-[r:EXPLOITS]->() RETURN count(r)`, 13)
		check("EXAMPLE_OF"+suffix, `MATCH ()-[r:EXAMPLE_OF]->() RETURN count(r)`, 26)
		check("exploitability=1"+suffix, `MATCH (v:Vulnerability) WHERE v.exploitability = 1 RETURN count(v)`, 12)
		check("exploitability=0"+suffix, `MATCH (v:Vulnerability) WHERE v.exploitability = 0 RETURN count(v)`, 28)
		check("affectedVersion non-empty"+suffix, `MATCH ()-[r:AFFECTS]->() WHERE size(r.affectedVersion) > 0 RETURN count(r)`, 28)
		check("affectedVersion empty"+suffix, `MATCH ()-[r:AFFECTS]->() WHERE size(r.affectedVersion) = 0 RETURN count(r)`, 9)
		check("avRun removed"+suffix, `MATCH ()-[r:AFFECTS]->() WHERE r.avRun IS NOT NULL RETURN count(r)`, 0)
		check("missing_domain_refers"+suffix, job("missing_domain_refers"), 2)
		check("missing_product_affects"+suffix, job("missing_product_affects"), 2)
		check("missing_vendor_belongs"+suffix, job("missing_vendor_belongs"), 0)
		check("missing_affected_version"+suffix, job("missing_affected_version"), 2)
		check("rejectDeleted"+suffix, job("rejectDeleted"), 3)
		check("bareNodes"+suffix, job("bareNodes"), 3)
		check("openssl type"+suffix, `MATCH (p:Product {productName:'openssl'}) WHERE p.productType = 'Application' RETURN count(p)`, 1)
		check("linux_kernel type"+suffix, `MATCH (p:Product {productName:'linux_kernel'}) WHERE p.productType = 'Operating System' RETURN count(p)`, 1)
		check("big-ip type"+suffix, `MATCH (p:Product {productName:'big-ip'}) WHERE p.productType = 'Hardware' RETURN count(p)`, 1)
		check("numOfVersion 1001 openssl"+suffix, `MATCH (:Vulnerability {cveID:'CVE-2019-1001'})-[r:AFFECTS]->(:Product {productName:'openssl'}) WHERE r.numOfVersion = 3 RETURN count(r)`, 1)
		check("numOfVersion 1002 openssl"+suffix, `MATCH (:Vulnerability {cveID:'CVE-2019-1002'})-[r:AFFECTS]->(:Product {productName:'openssl'}) WHERE r.numOfVersion = 2 RETURN count(r)`, 1)
		check("numOfVersion 9002 nginx"+suffix, `MATCH (:Vulnerability {cveID:'CVE-2018-9002'})-[r:AFFECTS]->(:Product {productName:'nginx'}) WHERE r.numOfVersion = 1 RETURN count(r)`, 1)
		check("dup versions"+suffix, `MATCH (:Vulnerability {cveID:'CVE-2019-1001'})-[r:AFFECTS]->(:Product {productName:'http_server'}) WHERE r.affectedVersion = ['1.0.1','1.0.1'] RETURN count(r)`, 1)
		check("four versions"+suffix, `MATCH (:Vulnerability {cveID:'CVE-2019-1004'})-[r:AFFECTS]->(:Product {productName:'firefox'}) WHERE r.affectedVersion = ['1.0.1','1.0.2','1.0.3','1.0.4'] RETURN count(r)`, 1)
		check("exploitDate 1002"+suffix, `MATCH (v:Vulnerability {cveID:'CVE-2019-1002'}) WHERE v.exploitDate = [date('2019-02-11'), date('2019-09-20')] RETURN count(v)`, 1)
		check("exploitDate 1022"+suffix, `MATCH (v:Vulnerability {cveID:'CVE-2019-1022'}) WHERE v.exploitDate = [date('2019-05-14')] RETURN count(v)`, 1)
		check("exploitDate empty"+suffix, `MATCH (v:Vulnerability) WHERE v.exploitability = 0 AND size(v.exploitDate) = 0 RETURN count(v)`, 28)
		check("rel provenance"+suffix, `MATCH ()-[r:BELONGS_TO]->() WHERE r.sources = ['vulkg'] RETURN count(r)`, 15)
	}

	if err := l.Steps1to8(ctx); err != nil {
		t.Fatal(err)
	}
	if err := l.Steps9to14(ctx); err != nil {
		t.Fatal(err)
	}
	verify("")
	check("rejectRelsDeleted", job("rejectRelsDeleted"), count(t, c, job("rejectRelsDeleted"))) // present
	if count(t, c, job("rejectRelsDeleted")) < 1 {
		t.Error("rejectRelsDeleted should be positive")
	}
	check("no REJECT left", `MATCH (v:Vulnerability) WHERE v.description STARTS WITH '** REJECT **' RETURN count(v)`, 0)

	// Rerun idempotence: REJECT nodes are recreated by steps 1 to 8 and removed again.
	if err := l.Steps1to8(ctx); err != nil {
		t.Fatal(err)
	}
	if err := l.Steps9to14(ctx); err != nil {
		t.Fatal(err)
	}
	verify(" rerun")
}
