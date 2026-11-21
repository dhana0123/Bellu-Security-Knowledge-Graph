//go:build integration

package validate_test

import (
	"context"
	"testing"

	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/graph/graphtest"
	"github.com/bellu/bskg/internal/validate"
)

func queryClient(t *testing.T) *graph.Client {
	t.Helper()
	graphtest.New(t) // starts the container, skips without Docker, resets the database
	c, err := graph.New(graph.Params{URI: graphtest.URI(), User: "neo4j", Password: graphtest.Password(), Timeout: validate.QueryTimeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// All nine queries run on an empty graph without a query error.
func TestQueriesExecuteOnEmptyGraph(t *testing.T) {
	c := queryClient(t)
	ctx := context.Background()
	if _, err := c.Auto(ctx, `CREATE FULLTEXT INDEX VulnerabilityDescriptionFullTextSchema IF NOT EXISTS FOR (v:Vulnerability) ON EACH [v.description]`, nil); err != nil {
		t.Fatal(err)
	}
	params := map[string]map[string]any{
		"lookup_cve":               {"cveID": "CVE-2019-1005"},
		"weakness_vulnerabilities": {"cweID": "CWE-89"},
		"product_vulnerabilities":  {"productName": "openssl"},
		"vendor_products":          {"vendorName": "apache"},
		"vulnerability_exploits":   {"cveID": "CVE-2019-1002"},
		"vulnerability_domains":    {"cveID": "CVE-2019-1004"},
		"fulltext_description":     {"query": "12"},
		"published_range":          {"from": "2019-03-01", "to": "2019-04-30"},
		"cvss_v3_version":          {"v3version": 3.0},
	}
	res, err := validate.RunQueries(ctx, c, params)
	if err != nil || len(res) != 9 {
		t.Fatalf("%d %v", len(res), err)
	}
	for _, r := range res {
		if !r.Passed || r.Rows != 0 {
			t.Errorf("%s: %+v", r.Name, r)
		}
	}
}
