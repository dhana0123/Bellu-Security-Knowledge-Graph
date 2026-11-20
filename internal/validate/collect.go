package validate

import (
	"context"
	"fmt"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
)

// All Cypher here is constant and read-only. Label and relationship names
// cannot be parameters in Cypher, so each has its own constant string.

var nodeCountQueries = map[string]string{
	"Vulnerability": `MATCH (n:Vulnerability) RETURN count(n)`,
	"Exploit":       `MATCH (n:Exploit) RETURN count(n)`,
	"Weakness":      `MATCH (n:Weakness) RETURN count(n)`,
	"Product":       `MATCH (n:Product) RETURN count(n)`,
	"Vendor":        `MATCH (n:Vendor) RETURN count(n)`,
	"Author":        `MATCH (n:Author) RETURN count(n)`,
	"Domain":        `MATCH (n:Domain) RETURN count(n)`,
}

var relCountQueries = map[string]string{
	"EXPLOITS":   `MATCH ()-[r:EXPLOITS]->() RETURN count(r)`,
	"AFFECTS":    `MATCH ()-[r:AFFECTS]->() RETURN count(r)`,
	"BELONGS_TO": `MATCH ()-[r:BELONGS_TO]->() RETURN count(r)`,
	"EXAMPLE_OF": `MATCH ()-[r:EXAMPLE_OF]->() RETURN count(r)`,
	"WRITES":     `MATCH ()-[r:WRITES]->() RETURN count(r)`,
	"REFERS_TO":  `MATCH ()-[r:REFERS_TO]->() RETURN count(r)`,
}

// Derived metrics from the EXPLOITS relationships.
const derivedExploitQuery = `MATCH (v:Vulnerability)<-[:EXPLOITS]-(e:Exploit)
WITH v, count(DISTINCT e) AS c
RETURN count(v) AS exploitable,
       sum(CASE WHEN c = 1 THEN 1 ELSE 0 END) AS one,
       sum(CASE WHEN c > 1 THEN 1 ELSE 0 END) AS many`

type dupQuery struct {
	label, prop, cypher string
}

var dupQueries = []dupQuery{
	{"Vulnerability", "cveID", `MATCH (n:Vulnerability) WITH n.cveID AS k, count(*) AS c WHERE c > 1 RETURN toString(k), c ORDER BY c DESC, toString(k) LIMIT 100`},
	{"Exploit", "eid", `MATCH (n:Exploit) WITH n.eid AS k, count(*) AS c WHERE c > 1 RETURN toString(k), c ORDER BY c DESC, toString(k) LIMIT 100`},
	{"Author", "authorName", `MATCH (n:Author) WITH n.authorName AS k, count(*) AS c WHERE c > 1 RETURN toString(k), c ORDER BY c DESC, toString(k) LIMIT 100`},
	{"Weakness", "cweID", `MATCH (n:Weakness) WITH n.cweID AS k, count(*) AS c WHERE c > 1 RETURN toString(k), c ORDER BY c DESC, toString(k) LIMIT 100`},
	{"Domain", "domainName", `MATCH (n:Domain) WITH n.domainName AS k, count(*) AS c WHERE c > 1 RETURN toString(k), c ORDER BY c DESC, toString(k) LIMIT 100`},
	{"Product", "productName", `MATCH (n:Product) WITH n.productName AS k, count(*) AS c WHERE c > 1 RETURN toString(k), c ORDER BY c DESC, toString(k) LIMIT 100`},
	{"Vendor", "vendorName", `MATCH (n:Vendor) WITH n.vendorName AS k, count(*) AS c WHERE c > 1 RETURN toString(k), c ORDER BY c DESC, toString(k) LIMIT 100`},
}

type endpointQuery struct {
	rule          EndpointRule
	count, sample string
}

var endpointQueries = []endpointQuery{
	{EndpointRules[0],
		`MATCH (a)-[r:WRITES]->(b) WHERE NOT (a:Author AND b:Exploit) RETURN count(r)`,
		`MATCH (a)-[r:WRITES]->(b) WHERE NOT (a:Author AND b:Exploit) RETURN elementId(r), labels(a), labels(b) ORDER BY elementId(r) LIMIT 100`},
	{EndpointRules[1],
		`MATCH (a)-[r:EXPLOITS]->(b) WHERE NOT (a:Exploit AND b:Vulnerability) RETURN count(r)`,
		`MATCH (a)-[r:EXPLOITS]->(b) WHERE NOT (a:Exploit AND b:Vulnerability) RETURN elementId(r), labels(a), labels(b) ORDER BY elementId(r) LIMIT 100`},
	{EndpointRules[2],
		`MATCH (a)-[r:EXAMPLE_OF]->(b) WHERE NOT (a:Vulnerability AND b:Weakness) RETURN count(r)`,
		`MATCH (a)-[r:EXAMPLE_OF]->(b) WHERE NOT (a:Vulnerability AND b:Weakness) RETURN elementId(r), labels(a), labels(b) ORDER BY elementId(r) LIMIT 100`},
	{EndpointRules[3],
		`MATCH (a)-[r:REFERS_TO]->(b) WHERE NOT (a:Vulnerability AND b:Domain) RETURN count(r)`,
		`MATCH (a)-[r:REFERS_TO]->(b) WHERE NOT (a:Vulnerability AND b:Domain) RETURN elementId(r), labels(a), labels(b) ORDER BY elementId(r) LIMIT 100`},
	{EndpointRules[4],
		`MATCH (a)-[r:AFFECTS]->(b) WHERE NOT (a:Vulnerability AND b:Product) RETURN count(r)`,
		`MATCH (a)-[r:AFFECTS]->(b) WHERE NOT (a:Vulnerability AND b:Product) RETURN elementId(r), labels(a), labels(b) ORDER BY elementId(r) LIMIT 100`},
	{EndpointRules[5],
		`MATCH (a)-[r:BELONGS_TO]->(b) WHERE NOT (a:Product AND b:Vendor) RETURN count(r)`,
		`MATCH (a)-[r:BELONGS_TO]->(b) WHERE NOT (a:Product AND b:Vendor) RETURN elementId(r), labels(a), labels(b) ORDER BY elementId(r) LIMIT 100`},
}

const (
	showConstraintsQuery = `SHOW CONSTRAINTS YIELD name, type, labelsOrTypes, properties
RETURN name, type, labelsOrTypes, properties`
	showIndexesQuery = `SHOW INDEXES YIELD name, type, state RETURN name, type, state`

	rejectCountQuery = `MATCH (v:Vulnerability)
WHERE v.description STARTS WITH '** REJECT **' AND coalesce(v.rejected, false) = false
RETURN count(v)`
	rejectSampleQuery = `MATCH (v:Vulnerability)
WHERE v.description STARTS WITH '** REJECT **' AND coalesce(v.rejected, false) = false
RETURN toString(v.cveID) ORDER BY v.cveID LIMIT 100`

	loaderJobQuery = `OPTIONAL MATCH (j:Job {name: 'baseline-load'}) RETURN properties(j)`
)

func readOne(ctx context.Context, c *graph.Client, q string) (neo4j.Record, bool, error) {
	var rec neo4j.Record
	var found bool
	_, err := c.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, q, nil)
		if err != nil {
			return nil, err
		}
		if res.Next(ctx) {
			rec, found = *res.Record(), true
		}
		return nil, res.Err()
	})
	return rec, found, err
}

func readAll(ctx context.Context, c *graph.Client, q string) ([]neo4j.Record, error) {
	v, err := c.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, q, nil)
		if err != nil {
			return nil, err
		}
		var out []neo4j.Record
		for res.Next(ctx) {
			out = append(out, *res.Record())
		}
		return out, res.Err()
	})
	if err != nil {
		return nil, err
	}
	return v.([]neo4j.Record), nil
}

func readInt(ctx context.Context, c *graph.Client, q string) (int64, error) {
	rec, ok, err := readOne(ctx, c, q)
	if err != nil || !ok {
		return 0, err
	}
	n, _ := rec.Values[0].(int64)
	return n, nil
}

// CollectCounts runs the node, relationship, and derived-exploit counts and
// returns the metric map that CompareCounts expects.
func CollectCounts(ctx context.Context, c *graph.Client) (map[string]int64, error) {
	out := map[string]int64{}
	for _, m := range []map[string]string{nodeCountQueries, relCountQueries} {
		for name, q := range m {
			n, err := readInt(ctx, c, q)
			if err != nil {
				return nil, fmt.Errorf("count %s: %w", name, err)
			}
			out[name] = n
		}
	}
	rec, ok, err := readOne(ctx, c, derivedExploitQuery)
	if err != nil {
		return nil, fmt.Errorf("count derived exploit metrics: %w", err)
	}
	if ok {
		out["exploitableVulnerability"], _ = rec.Values[0].(int64)
		out["exactlyOneExploit"], _ = rec.Values[1].(int64)
		out["moreThanOneExploit"], _ = rec.Values[2].(int64)
	}
	return out, nil
}

func strList(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func first(l []string) string {
	if len(l) == 0 {
		return ""
	}
	return l[0]
}

// CollectIntegrity gathers the catalog, duplicate, endpoint, REJECT, and
// loader data. Profile and the count sections are set by the caller.
func CollectIntegrity(ctx context.Context, c *graph.Client) (Inputs, error) {
	var in Inputs
	rows, err := readAll(ctx, c, showConstraintsQuery)
	if err != nil {
		return in, fmt.Errorf("show constraints: %w", err)
	}
	for _, r := range rows {
		cc := CatalogConstraint{Label: first(strList(r.Values[2])), Prop: first(strList(r.Values[3]))}
		cc.Name, _ = r.Values[0].(string)
		cc.Type, _ = r.Values[1].(string)
		in.Constraints = append(in.Constraints, cc)
	}
	rows, err = readAll(ctx, c, showIndexesQuery)
	if err != nil {
		return in, fmt.Errorf("show indexes: %w", err)
	}
	for _, r := range rows {
		var ci CatalogIndex
		ci.Name, _ = r.Values[0].(string)
		ci.Type, _ = r.Values[1].(string)
		ci.State, _ = r.Values[2].(string)
		in.Indexes = append(in.Indexes, ci)
	}
	for _, d := range dupQueries {
		rows, err := readAll(ctx, c, d.cypher)
		if err != nil {
			return in, fmt.Errorf("duplicates %s: %w", d.label, err)
		}
		var g []DuplicateGroup
		for _, r := range rows {
			v, _ := r.Values[0].(string)
			n, _ := r.Values[1].(int64)
			g = append(g, DuplicateGroup{Value: v, Count: n})
		}
		in.Duplicates = append(in.Duplicates, NewDuplicateCheck(d.label, d.prop, g))
	}
	for _, e := range endpointQueries {
		n, err := readInt(ctx, c, e.count)
		if err != nil {
			return in, fmt.Errorf("endpoints %s: %w", e.rule.Type, err)
		}
		var ex []EndpointExample
		if n > 0 {
			rows, err := readAll(ctx, c, e.sample)
			if err != nil {
				return in, fmt.Errorf("endpoints %s: %w", e.rule.Type, err)
			}
			for _, r := range rows {
				id, _ := r.Values[0].(string)
				ex = append(ex, EndpointExample{ID: id, FromLabels: strList(r.Values[1]), ToLabels: strList(r.Values[2])})
			}
		}
		in.Endpoints = append(in.Endpoints, NewEndpointCheck(e.rule, n, ex))
	}
	n, err := readInt(ctx, c, rejectCountQuery)
	if err != nil {
		return in, fmt.Errorf("reject check: %w", err)
	}
	var ids []string
	if n > 0 {
		rows, err := readAll(ctx, c, rejectSampleQuery)
		if err != nil {
			return in, fmt.Errorf("reject check: %w", err)
		}
		for _, r := range rows {
			s, _ := r.Values[0].(string)
			ids = append(ids, s)
		}
	}
	in.Reject = NewRejectCheck(n, ids)
	rec, ok, err := readOne(ctx, c, loaderJobQuery)
	if err != nil {
		return in, fmt.Errorf("loader counts: %w", err)
	}
	props := map[string]any{}
	if ok {
		props, _ = rec.Values[0].(map[string]any)
	}
	in.Loader = LoaderCountsFromProps(props)
	return in, nil
}

// Run collects everything for profile ("baseline" includes the count
// comparison against exp) and returns the report.
func Run(ctx context.Context, c *graph.Client, profile string, exp *Expected, disc []Discrepancy) (Report, error) {
	in, err := CollectIntegrity(ctx, c)
	if err != nil {
		return Report{}, err
	}
	in.Profile, in.Expected, in.Discrepancy = profile, exp, disc
	if exp != nil {
		if in.Counts, err = CollectCounts(ctx, c); err != nil {
			return Report{}, err
		}
	}
	r := BuildReport(in)
	r.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	return r, nil
}
