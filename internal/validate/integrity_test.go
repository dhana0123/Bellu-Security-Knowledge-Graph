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
	in := Inputs{Constraints: goodConstraints(), Indexes: goodIndexes(), Reject: NewRejectCheck(0, nil)}
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

func TestReportJSON(t *testing.T) {
	in := goodInputs()
	b, err := json.Marshal(BuildReport(in))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"status", "failed", "schema", "duplicates", "endpoints", "reject"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %s", k)
		}
	}
	if m["status"] != "passed" {
		t.Fatalf("%s", b)
	}
}

func TestNeo4j2025ConstraintType(t *testing.T) {
	in := goodInputs()
	for i := range in.Constraints {
		in.Constraints[i].Type = "NODE_PROPERTY_UNIQUENESS"
	}
	if r := BuildReport(in); !r.Passed() {
		t.Fatalf("failed=%v", r.Failed)
	}
	in.Constraints[0].Type = "NODE_KEY"
	if r := BuildReport(in); r.Passed() {
		t.Fatal("a non-uniqueness constraint must fail")
	}
}
