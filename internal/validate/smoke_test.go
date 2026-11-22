package validate

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

var smokeLabels = []string{"Vulnerability", "Weakness", "Exploit", "Product", "Vendor", "EXAMPLE_OF", "AFFECTS", "EXPLOITS"}

// Feature: bellu-security-knowledge-graph, Property 56: Smoke check
// **Validates: Requirements 13.9, 13.10**
func TestProperty56SmokeCheck(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		counts := map[string]int64{}
		for _, k := range smokeLabels {
			// Small values hit the 0 and 1 boundaries often.
			counts[k] = rapid.Int64Range(0, 6).Draw(t, k)
		}
		mode := rapid.SampledFrom([]string{"sample", "full"}).Draw(t, "mode")
		n := rapid.IntRange(1, 6).Draw(t, "limit")

		var want bool
		if mode == "sample" {
			// AFFECTS is a warning in sample mode (documented deviation).
			want = counts["Vulnerability"] >= 1 && counts["Vulnerability"] <= int64(n) &&
				counts["Weakness"] >= 1 && counts["EXAMPLE_OF"] >= 1
		} else {
			want = counts["Vulnerability"] >= 1 && counts["Weakness"] >= 1 && counts["EXAMPLE_OF"] >= 1 &&
				counts["AFFECTS"] >= 1 && counts["Exploit"] >= 1 && counts["EXPLOITS"] >= 1
		}
		got := DecideSmoke(mode, n, counts)
		if got.Passed != want {
			t.Fatalf("mode=%s n=%d counts=%v: passed=%v want %v (%v)", mode, n, counts, got.Passed, want, got.Failures)
		}
		if got.Passed != (len(got.Failures) == 0) {
			t.Fatalf("passed=%v with failures %v", got.Passed, got.Failures)
		}
		for _, k := range smokeLabels { // the report lists every count
			if got.Counts[k] != counts[k] {
				t.Fatalf("count %s = %d, want %d", k, got.Counts[k], counts[k])
			}
		}
		if mode == "sample" && (counts["AFFECTS"] == 0) != (len(got.Warnings) == 1) {
			t.Fatalf("AFFECTS=%d warnings=%v", counts["AFFECTS"], got.Warnings)
		}
		if mode == "full" && len(got.Warnings) != 0 {
			t.Fatalf("full mode warnings: %v", got.Warnings)
		}
	})
}

func TestSmokeUnknownModeFails(t *testing.T) {
	c := map[string]int64{"Vulnerability": 1, "Weakness": 1, "EXAMPLE_OF": 1, "AFFECTS": 1, "Exploit": 1, "EXPLOITS": 1}
	for _, m := range []string{"", "other"} {
		if r := DecideSmoke(m, 5, c); r.Passed {
			t.Errorf("mode %q passed", m)
		}
	}
}

func TestSmokeSampleLatestWithoutAffectsWarns(t *testing.T) {
	r := DecideSmoke("sample", 1000, map[string]int64{"Vulnerability": 1000, "Weakness": 40, "EXAMPLE_OF": 900})
	if !r.Passed || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "AFFECTS") {
		t.Fatalf("%+v", r)
	}
	if DecideSmoke("full", 0, map[string]int64{"Vulnerability": 1, "Weakness": 1, "EXAMPLE_OF": 1, "Exploit": 1, "EXPLOITS": 1}).Passed {
		t.Fatal("full mode needs AFFECTS")
	}
}

func TestSmokeCountNamesFollowPhase(t *testing.T) {
	has := func(l []string, s string) bool {
		for _, x := range l {
			if x == s {
				return true
			}
		}
		return false
	}
	p1, p3 := SmokeCountNames(1), SmokeCountNames(3)
	for _, n := range []string{"Vulnerability", "Exploit", "EXPLOITS", "AFFECTS", "Repository", "FIXES"} {
		if !has(p1, n) {
			t.Errorf("phase 1 lacks %s", n)
		}
	}
	for _, n := range []string{"Package", "AFFECTS_PACKAGE", "AttackPattern", "MAPS_TO_TECHNIQUE"} {
		if has(p1, n) || !has(p3, n) {
			t.Errorf("%s: phase1=%v phase3=%v", n, has(p1, n), has(p3, n))
		}
	}
	if has(p3, "BuildMeta") {
		t.Error("bookkeeping labels are not counted")
	}
	q, err := smokeCountQueries(3)
	if err != nil || len(q) != len(p3) {
		t.Fatalf("%d queries for %d names: %v", len(q), len(p3), err)
	}
}

var writeClause = regexp.MustCompile(`(?i)\b(CREATE|MERGE|SET|DELETE|REMOVE|DROP|LOAD\s+CSV|IN\s+TRANSACTIONS)\b`)

func TestNewCypherIsReadOnlyAndBounded(t *testing.T) {
	sample := []string{exploitDataSampleQuery, exploitabilityWithSample, exploitabilityWithoutSample, unsetSampleQuery}
	for _, q := range append([]string{exploitDataCountQuery, exploitabilityWithCount, exploitabilityWithoutCount, unsetCountQuery}, sample...) {
		if writeClause.MatchString(q) {
			t.Errorf("write clause in %s", q)
		}
	}
	for _, q := range sample {
		if !strings.Contains(q, "ORDER BY") || !strings.Contains(q, "LIMIT 100") {
			t.Errorf("sample query needs ORDER BY and LIMIT 100: %s", q)
		}
	}
	// One aggregation over the EXPLOITS relationships, not a query per node.
	if !strings.HasPrefix(exploitabilityWithBase, "MATCH (e:Exploit)-[r:EXPLOITS]->(v:Vulnerability)") {
		t.Error("exploitability scan must start from EXPLOITS")
	}
	if !strings.Contains(exploitDataCountQuery, "$allowed") || !strings.Contains(exploitDataCountQuery, "$provRe") {
		t.Error("exploit property allow-list must be parameterized")
	}
	re := regexp.MustCompile("^" + provenanceKeyRe + "$")
	for _, k := range []string{"p_nvd_run", "p_exploitdb_at", "p_osv_ref", "p_nvd_removed"} {
		if !re.MatchString(k) {
			t.Errorf("%s not provenance", k)
		}
	}
	for _, k := range []string{"code", "p_nvd", "p_NVD_run", "exploitCode", "p_nvd_run_x"} {
		if re.MatchString(k) {
			t.Errorf("%s matched as provenance", k)
		}
	}
}

func TestExploitabilityCheckMergesAndCaps(t *testing.T) {
	var a, b []string
	for i := 0; i < 80; i++ {
		a = append(a, "CVE-A-"+string(rune('a'+i%26))+string(rune('a'+i/26)))
		b = append(b, "CVE-B-"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	c := NewExploitabilityCheck(80, 80, a, b)
	if c.Passed || c.Count != 160 || len(c.Examples) != MaxExamples {
		t.Fatalf("%+v", c)
	}
	if c2 := NewExploitabilityCheck(0, 0, nil, nil); !c2.Passed || c2.Count != 0 {
		t.Fatalf("%+v", c2)
	}
	if c3 := NewExploitabilityCheck(1, 1, []string{"x"}, []string{"x"}); len(c3.Examples) != 1 {
		t.Fatalf("%+v", c3)
	}
	if len(NewExploitDataCheck(300, make([]ExploitDataExample, 300)).Examples) != MaxExamples {
		t.Fatal("exploit data examples not capped")
	}
	if len(NewUnsetPropsCheck(300, 300, 0, make([]string, 300)).Examples) != MaxExamples {
		t.Fatal("unset examples not capped")
	}
}

func TestReportWithNewChecks(t *testing.T) {
	in := goodInputs()
	ed := NewExploitDataCheck(1, []ExploitDataExample{{EID: "1", Props: []string{"code"}}})
	ex := NewExploitabilityCheck(1, 0, []string{"CVE-1"}, nil)
	us := NewUnsetPropsCheck(1, 1, 0, []string{"CVE-2"})
	sm := DecideSmoke("sample", 10, map[string]int64{"Vulnerability": 3, "Weakness": 1, "EXAMPLE_OF": 1})
	in.ExploitData, in.Exploitability, in.Unset, in.Smoke = &ed, &ex, &us, &sm
	in.BuildMode, in.SampleLimit = "sample", 10
	r := BuildReport(in)
	if got := strings.Join(r.Failed, ","); got != "exploit_data,exploitability,unset_properties" {
		t.Fatalf("failed=%s", got)
	}
	if len(r.Warnings) != 1 || strings.Join(r.FailedChecks, ",") != strings.Join(r.Failed, ",") {
		t.Fatalf("warnings=%v failedChecks=%v", r.Warnings, r.FailedChecks)
	}
	b, _ := json.Marshal(r)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"status", "buildMode", "failedChecks", "warnings", "exploitData", "exploitability", "unsetProperties", "smoke"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %s", k)
		}
	}

	bad := DecideSmoke("full", 0, map[string]int64{})
	in.ExploitData, in.Exploitability, in.Unset = nil, nil, nil
	in.Smoke = &bad
	if r := BuildReport(in); r.Passed() || strings.Join(r.Failed, ",") != "smoke" {
		t.Fatalf("%v", r.Failed)
	}
}

func TestAttachQueriesSkippedIsWarningNotFailure(t *testing.T) {
	r := BuildReport(goodInputs())
	AttachQueries(&r, []QueryResult{{Name: "a", Passed: true, Rows: 1}, {Name: "vulnerability_exploits", Passed: true, Skipped: true, Message: "no selector value in the graph"}})
	if !r.Passed() || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "vulnerability_exploits") {
		t.Fatalf("%+v %v", r.Failed, r.Warnings)
	}
	AttachQueries(&r, []QueryResult{{Name: "b"}})
	if r.Passed() || len(r.FailedChecks) != 1 || r.FailedChecks[0] != "query:b" {
		t.Fatalf("%+v", r)
	}
}

func TestSelectorsCoverNineQueriesAndAreReadOnly(t *testing.T) {
	qs, err := Queries()
	if err != nil {
		t.Fatal(err)
	}
	if len(selectors) != len(qs) {
		t.Fatalf("%d selectors for %d queries", len(selectors), len(qs))
	}
	for i, q := range qs {
		s := selectors[i]
		if s.query != q.Name {
			t.Errorf("selector %d is for %s, want %s", i, s.query, q.Name)
		}
		if writeClause.MatchString(s.cypher) || !strings.Contains(s.cypher, "LIMIT 1") {
			t.Errorf("%s selector must be read-only with LIMIT 1", s.query)
		}
	}
}

func TestSelectorParams(t *testing.T) {
	by := map[string]selector{}
	for _, s := range selectors {
		by[s.query] = s
	}
	if p, ok := by["lookup_cve"].params([]any{"CVE-2020-1"}); !ok || p["cveID"] != "CVE-2020-1" {
		t.Errorf("lookup: %v %v", p, ok)
	}
	if _, ok := by["vendor_products"].params([]any{""}); ok {
		t.Error("empty vendor must skip")
	}
	if p, ok := by["published_range"].params([]any{"2020-01-01", "2020-01-31"}); !ok || p["from"] != "2020-01-01" || p["to"] != "2020-01-31" {
		t.Errorf("range: %v %v", p, ok)
	}
	if p, ok := by["cvss_v3_version"].params([]any{3.1}); !ok || p["v3version"] != 3.1 {
		t.Errorf("v3: %v %v", p, ok)
	}
	if _, ok := by["cvss_v3_version"].params([]any{int64(3)}); ok {
		t.Error("non-float v3version must skip")
	}
	if p, ok := by["fulltext_description"].params([]any{"A buffer overflow in the parser allows attackers"}); !ok || p["query"] != "overflow" && p["query"] != "attackers" {
		t.Errorf("fulltext: %v %v", p, ok)
	}
	if _, ok := by["fulltext_description"].params([]any{"a b c 12 34"}); ok {
		t.Error("no word of 6 letters must skip")
	}
}
