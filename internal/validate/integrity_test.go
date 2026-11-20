package validate

import (
	"encoding/json"
	"strings"
	"testing"
)

func goodConstraints() []CatalogConstraint {
	var out []CatalogConstraint
	for _, r := range RequiredConstraints {
		out = append(out, CatalogConstraint{r.Name, "UNIQUENESS", r.Label, r.Prop})
	}
	return out
}

func goodIndexes() []CatalogIndex {
	var out []CatalogIndex
	for _, r := range RequiredIndexes {
		out = append(out, CatalogIndex{r.Name, r.Type, "ONLINE"})
	}
	return out
}

func goodInputs() Inputs {
	in := Inputs{Profile: "integrity", Constraints: goodConstraints(), Indexes: goodIndexes(), Reject: NewRejectCheck(0, nil)}
	for _, r := range RequiredConstraints {
		in.Duplicates = append(in.Duplicates, NewDuplicateCheck(r.Label, r.Prop, nil))
	}
	for _, r := range EndpointRules {
		in.Endpoints = append(in.Endpoints, NewEndpointCheck(r, 0, nil))
	}
	return in
}

func TestReportPasses(t *testing.T) {
	r := BuildReport(goodInputs())
	if !r.Passed() || len(r.Failed) != 0 {
		t.Fatalf("%+v", r.Failed)
	}
}

func TestSchemaFailures(t *testing.T) {
	in := goodInputs()
	in.Constraints = in.Constraints[1:]
	in.Indexes[0].State = "POPULATING"
	in.Indexes[4].Type = "RANGE"
	r := BuildReport(in)
	want := []string{"constraint:UniqueCveID", "index:VulnerabilityDescriptionFullTextSchema", "index:VulnerabilityV2Version"}
	if r.Passed() || strings.Join(r.Failed, ",") != strings.Join(want, ",") {
		t.Fatalf("failed=%v", r.Failed)
	}
}

func TestDuplicatesEndpointsRejectFail(t *testing.T) {
	in := goodInputs()
	in.Duplicates[0] = NewDuplicateCheck("Vulnerability", "cveID", []DuplicateGroup{{"CVE-1", 2}})
	in.Endpoints[1] = NewEndpointCheck(EndpointRules[1], 3, []EndpointExample{{"1", []string{"Author"}, []string{"Vulnerability"}}})
	in.Reject = NewRejectCheck(1, []string{"CVE-2"})
	r := BuildReport(in)
	want := "duplicates:Vulnerability,endpoints:EXPLOITS,reject"
	if strings.Join(r.Failed, ",") != want {
		t.Fatalf("failed=%v", r.Failed)
	}
}

func TestCapsAtMaxExamples(t *testing.T) {
	g := make([]DuplicateGroup, 150)
	e := make([]EndpointExample, 150)
	s := make([]string, 150)
	if len(NewDuplicateCheck("L", "p", g).Groups) != 100 ||
		len(NewEndpointCheck(EndpointRules[0], 150, e).Examples) != 100 ||
		len(NewRejectCheck(150, s).Examples) != 100 {
		t.Fatal("not capped")
	}
}

func TestCountsFeedStatus(t *testing.T) {
	in := goodInputs()
	exp, _ := LoadExpected(ProfileBaseline)
	disc, _ := LoadDiscrepancies()
	in.Expected, in.Discrepancy = &exp, disc
	in.Counts = map[string]int64{}
	for k, v := range exp.Metrics {
		in.Counts[k] = v
	}
	in.Counts["AFFECTS"] = 212656 // known discrepancy
	if r := BuildReport(in); !r.Passed() {
		t.Fatalf("%v", r.Failed)
	}
	in.Counts["Author"]++
	r := BuildReport(in)
	if r.Passed() || r.Failed[0] != "count:Author" {
		t.Fatalf("%v", r.Failed)
	}
}

func TestLoaderCountsFromProps(t *testing.T) {
	lc := LoaderCountsFromProps(map[string]any{
		"name": "baseline-load", "missing_exploits_rel": int64(3), "missing_product_affects": int64(2),
		"rejectDeleted": int64(5), "bareNodes": int64(1), "rowsDone": int64(9),
	})
	if lc.MissingEndpoints["exploits_rel"] != 3 || lc.MissingEndpoints["product_affects"] != 2 ||
		len(lc.MissingEndpoints) != 2 || *lc.RejectDeleted != 5 || *lc.BareNodes != 1 {
		t.Fatalf("%+v", lc)
	}
	if e := LoaderCountsFromProps(nil); e.RejectDeleted != nil || e.BareNodes != nil {
		t.Fatal("absent should be nil")
	}
}

func TestReportJSON(t *testing.T) {
	in := goodInputs()
	in.Loader = LoaderCountsFromProps(map[string]any{"rejectDeleted": int64(4)})
	b, err := json.Marshal(BuildReport(in))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"profile", "status", "failed", "schema", "duplicates", "endpoints", "reject", "loader"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %s", k)
		}
	}
	if m["status"] != "passed" || m["loader"].(map[string]any)["rejectDeleted"].(float64) != 4 {
		t.Fatalf("%s", b)
	}
}
