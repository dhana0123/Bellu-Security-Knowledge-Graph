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

func TestPhaseChecks(t *testing.T) {
	if got := len(RequiredConstraintsFor(1)); got != len(RequiredConstraints) {
		t.Errorf("phase 1 constraints = %d", got)
	}
	if got := len(RequiredConstraintsFor(2)); got != len(RequiredConstraints)+1 {
		t.Errorf("phase 2 constraints = %d", got)
	}
	if got := len(RequiredConstraintsFor(3)); got != len(RequiredConstraints)+4 {
		t.Errorf("phase 3 constraints = %d", got)
	}
	// A phase 3 graph without the V201 constraints fails; phase 1 ignores them.
	var cat []CatalogConstraint
	for _, r := range RequiredConstraintsFor(2) {
		cat = append(cat, CatalogConstraint{Name: r.Name, Type: "UNIQUENESS", Label: r.Label, Prop: r.Prop})
	}
	failed := 0
	for _, c := range CheckConstraintsFor(cat, 3) {
		if !c.Passed {
			failed++
		}
	}
	if failed != 3 {
		t.Errorf("failed = %d, want the 3 V201 constraints", failed)
	}
	if n := len(phaseDupQueries(3)); n != 4 {
		t.Errorf("phase 3 duplicate queries = %d, want 4", n)
	}
	if n := len(phaseDupQueries(1)); n != 0 {
		t.Errorf("phase 1 duplicate queries = %d", n)
	}
	if n := len(phaseEndpointQueries(3)); n != 5 {
		t.Errorf("phase 3 endpoint queries = %d, want 5", n)
	}
}
