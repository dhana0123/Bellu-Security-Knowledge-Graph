package validate

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/graph"
)

// A selector is a constant read-only Cypher statement that picks the
// parameters of one representative query from the graph. It returns at most
// one row, deterministically (ORDER BY with LIMIT 1). Where possible the
// ORDER BY follows a uniqueness or range index, so the scan stops at the
// first match.
type selector struct {
	query  string
	cypher string
	// params turns the selector row into query parameters; ok is false when
	// the row cannot yield a parameter (the query is then skipped).
	params func(row []any) (map[string]any, bool)
}

const (
	// The Vulnerability with the most relationships (one pass over the
	// degree counts of all Vulnerabilities, no relationship expansion).
	selLookupCVE = `MATCH (v:Vulnerability)
RETURN v.cveID AS cveID
ORDER BY COUNT { (v)--() } DESC, cveID
LIMIT 1`
	selWeakness = `MATCH (w:Weakness)
WHERE EXISTS { (w)<-[:EXAMPLE_OF]-(:Vulnerability) }
RETURN w.cweID AS cweID ORDER BY cweID LIMIT 1`
	selProduct = `MATCH (p:Product)
WHERE EXISTS { (p)<-[:AFFECTS]-(:Vulnerability) }
RETURN p.productName AS productName ORDER BY productName LIMIT 1`
	selVendor = `MATCH (v:Vendor)
WHERE EXISTS { (v)<-[:BELONGS_TO]-(:Product) }
RETURN v.vendorName AS vendorName ORDER BY vendorName LIMIT 1`
	selExploit = `MATCH (:Author)-[:WRITES]->(:Exploit)-[:EXPLOITS]->(v:Vulnerability)
RETURN v.cveID AS cveID ORDER BY cveID LIMIT 1`
	selDomain = `MATCH (v:Vulnerability)
WHERE EXISTS { (v)-[:REFERS_TO]->(:Domain) }
RETURN v.cveID AS cveID ORDER BY cveID LIMIT 1`
	// The description of the first non-rejected Vulnerability; Go picks a word.
	selFulltext = `MATCH (v:Vulnerability)
WHERE v.description IS NOT NULL AND NOT v.description STARTS WITH '** REJECT **'
RETURN v.description AS description ORDER BY v.cveID LIMIT 1`
	// The earliest published date, with a window of 15 days on each side.
	selPublished = `MATCH (v:Vulnerability)
WHERE v.publishedDate IS NOT NULL
WITH date(v.publishedDate) AS d ORDER BY d LIMIT 1
RETURN toString(d - duration('P15D')) AS from, toString(d + duration('P15D')) AS to`
	selV3 = `MATCH (v:Vulnerability)
WHERE v.v3version IS NOT NULL
RETURN v.v3version AS v3version ORDER BY v3version LIMIT 1`
)

func oneString(key string) func([]any) (map[string]any, bool) {
	return func(row []any) (map[string]any, bool) {
		s, _ := row[0].(string)
		return map[string]any{key: s}, s != ""
	}
}

var wordRe = regexp.MustCompile(`[A-Za-z]{6,}`)

// fulltextTerm returns the longest lower-case word of 6 or more letters among
// the first 50 words of a description, or "" when there is none. Letters
// only, so the term needs no Lucene escaping; the longest word is the least
// likely to be a stop word.
func fulltextTerm(desc string) string {
	best := ""
	for _, w := range wordRe.FindAllString(desc, 50) {
		if len(w) > len(best) {
			best = w
		}
	}
	return strings.ToLower(best)
}

var selectors = []selector{
	{"lookup_cve", selLookupCVE, oneString("cveID")},
	{"weakness_vulnerabilities", selWeakness, oneString("cweID")},
	{"product_vulnerabilities", selProduct, oneString("productName")},
	{"vendor_products", selVendor, oneString("vendorName")},
	{"vulnerability_exploits", selExploit, oneString("cveID")},
	{"vulnerability_domains", selDomain, oneString("cveID")},
	{"fulltext_description", selFulltext, func(row []any) (map[string]any, bool) {
		s, _ := row[0].(string)
		t := fulltextTerm(s)
		return map[string]any{"query": t}, t != ""
	}},
	{"published_range", selPublished, func(row []any) (map[string]any, bool) {
		f, _ := row[0].(string)
		t, _ := row[1].(string)
		return map[string]any{"from": f, "to": t}, f != "" && t != ""
	}},
	{"cvss_v3_version", selV3, func(row []any) (map[string]any, bool) {
		f, ok := row[0].(float64)
		return map[string]any{"v3version": f}, ok
	}},
}

// SelectorQueries returns the selector Cypher by query name (for tests).
func SelectorQueries() map[string]string {
	out := map[string]string{}
	for _, s := range selectors {
		out[s.query] = s.cypher
	}
	return out
}

// RunSelectedQueries picks the parameters of each of the nine queries from
// the graph and runs the query. A query passes when it runs without error and
// returns at least one row. When the selector finds no parameter the query is
// skipped, which is not a failure. Every query runs even when an earlier one
// fails. The client timeout must be at least QueryTimeout.
func RunSelectedQueries(ctx context.Context, c *graph.Client) ([]QueryResult, error) {
	if c.Timeout() < QueryTimeout {
		return nil, fmt.Errorf("validate: graph client timeout %s is below the %s query timeout", c.Timeout(), QueryTimeout)
	}
	qs, err := Queries()
	if err != nil {
		return nil, err
	}
	out := make([]QueryResult, 0, len(qs))
	for _, q := range qs {
		var sel *selector
		for i := range selectors {
			if selectors[i].query == q.Name {
				sel = &selectors[i]
			}
		}
		if sel == nil {
			return nil, fmt.Errorf("validate: no selector for query %s", q.Name)
		}
		row, found, serr := runSelector(ctx, c, sel.cypher)
		if serr != nil {
			out = append(out, QueryResult{Name: q.Name, Message: "selector failed: " + serr.Error()})
			continue
		}
		var params map[string]any
		ok := false
		if found {
			params, ok = sel.params(row)
		}
		if !ok {
			out = append(out, QueryResult{Name: q.Name, Passed: true, Skipped: true, Message: "no selector value in the graph"})
			continue
		}
		tbl, qerr := RunQuery(ctx, c, q, params)
		res := QueryResult{Name: q.Name, Rows: len(tbl.Rows)}
		switch {
		case qerr != nil:
			res.Message = "query failed: " + qerr.Error()
		case len(tbl.Rows) == 0:
			res.Message = fmt.Sprintf("query returned no rows for selector parameters %v", params)
		default:
			res.Passed = true
		}
		out = append(out, res)
	}
	return out, nil
}

func runSelector(ctx context.Context, c *graph.Client, cypher string) ([]any, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	v, err := c.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, nil)
		if err != nil {
			return nil, err
		}
		if res.Next(ctx) {
			return res.Record().Values, nil
		}
		return nil, res.Err()
	})
	if err != nil {
		return nil, false, err
	}
	row, _ := v.([]any)
	return row, row != nil, nil
}
