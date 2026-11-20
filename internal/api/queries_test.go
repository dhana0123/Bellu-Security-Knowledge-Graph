package api

import (
	"regexp"
	"strings"
	"testing"
)

var forbiddenTokens = regexp.MustCompile(`(?i)\b(CREATE|MERGE|SET|DELETE|REMOVE|DROP|DETACH|FOREACH|LOAD\s+CSV)\b`)
var callRe = regexp.MustCompile(`(?i)\bCALL\b\s*([A-Za-z0-9_.]*)`)
var inTransactions = regexp.MustCompile(`(?i)\bIN\s+(\w+\s+)?TRANSACTIONS\b`)

// lintQuery returns the reasons a query is not read-only.
func lintQuery(q string) []string {
	var out []string
	for _, m := range forbiddenTokens.FindAllString(q, -1) {
		out = append(out, "forbidden token "+strings.ToUpper(m))
	}
	if inTransactions.MatchString(q) {
		out = append(out, "CALL ... IN TRANSACTIONS")
	}
	for _, m := range callRe.FindAllStringSubmatch(q, -1) {
		if m[1] != "db.index.fulltext.queryNodes" {
			out = append(out, "forbidden CALL "+m[1])
		}
	}
	return out
}

func TestAllQueriesReadOnly(t *testing.T) {
	if len(allQueries) == 0 {
		t.Fatal("allQueries is empty")
	}
	for i, q := range allQueries {
		if strings.TrimSpace(q) == "" {
			t.Errorf("query %d is empty", i)
		}
		if bad := lintQuery(q); len(bad) > 0 {
			t.Errorf("query %d not read-only: %v\n%s", i, bad, q)
		}
	}
}

func TestLintRejectsWrites(t *testing.T) {
	bad := []string{
		"CREATE (n:X)", "match (n) merge (m)", "MATCH (n) SET n.a = 1", "MATCH (n) DETACH DELETE n",
		"MATCH (n) REMOVE n.a", "DROP INDEX x", "LOAD CSV FROM 'x' AS r RETURN r",
		"CALL { MATCH (n) RETURN n } IN TRANSACTIONS OF 5 ROWS", "CALL apoc.do.it()", "CALL db.labels()",
	}
	for _, q := range bad {
		if len(lintQuery(q)) == 0 {
			t.Errorf("lint accepted %q", q)
		}
	}
	if got := lintQuery("CALL db.index.fulltext.queryNodes('i', $q) YIELD node RETURN node"); len(got) != 0 {
		t.Errorf("lint rejected full-text call: %v", got)
	}
}

func TestQueriesUseParametersOnly(t *testing.T) {
	// Constant strings contain no string-concatenation markers for client input.
	for i, q := range allQueries {
		if strings.Contains(q, "%s") || strings.Contains(q, "%v") {
			t.Errorf("query %d contains a format verb", i)
		}
	}
}
