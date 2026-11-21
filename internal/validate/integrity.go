package validate

import (
	"fmt"
	"sort"
	"strings"
)

// MaxExamples caps duplicate groups per label and endpoint examples per type.
const MaxExamples = 100

// RejectPrefix starts the description of a rejected CVE record.
const RejectPrefix = "** REJECT **"

// RequiredConstraint is one uniqueness constraint (migrations V001, V003).
type RequiredConstraint struct{ Name, Label, Prop string }

// RequiredIndex is one VulKG index (migration V001). Type is the Neo4j
// index type: "RANGE" or "FULLTEXT".
type RequiredIndex struct{ Name, Type string }

// RequiredConstraints lists the seven VulKG uniqueness constraints and the two git-link ones.
var RequiredConstraints = []RequiredConstraint{
	{"UniqueCveID", "Vulnerability", "cveID"},
	{"UniqueEID", "Exploit", "eid"},
	{"UniqueAuthorName", "Author", "authorName"},
	{"UniquecweID", "Weakness", "cweID"},
	{"UniqueDomainName", "Domain", "domainName"},
	{"UniqueProductName", "Product", "productName"},
	{"UniqueVendorName", "Vendor", "vendorName"},
	{"UniqueRepositoryUrl", "Repository", "url"},
	{"UniqueFixCommitKey", "FixCommit", "fcKey"},
}

// RequiredIndexes lists the four range indexes and the full-text index.
var RequiredIndexes = []RequiredIndex{
	{"VulnerabilityV2Version", "RANGE"},
	{"VulnerabilityV3Version", "RANGE"},
	{"VulnerabilityPublishedDate", "RANGE"},
	{"ExploitPublishDate", "RANGE"},
	{"VulnerabilityDescriptionFullTextSchema", "FULLTEXT"},
}

// EndpointRule gives the required endpoint labels of a relationship type.
type EndpointRule struct{ Type, From, To string }

// EndpointRules covers the six VulKG relationship types and the three git-link types.
var EndpointRules = []EndpointRule{
	{"WRITES", "Author", "Exploit"},
	{"EXPLOITS", "Exploit", "Vulnerability"},
	{"EXAMPLE_OF", "Vulnerability", "Weakness"},
	{"REFERS_TO", "Vulnerability", "Domain"},
	{"AFFECTS", "Vulnerability", "Product"},
	{"BELONGS_TO", "Product", "Vendor"},
	{"REFERS_TO_REPOSITORY", "Vulnerability", "Repository"},
	{"HAS_FIX_COMMIT", "Repository", "FixCommit"},
	{"FIXES", "FixCommit", "Vulnerability"},
}

// CatalogConstraint is a row of SHOW CONSTRAINTS.
type CatalogConstraint struct {
	Name, Type, Label, Prop string
}

// CatalogIndex is a row of SHOW INDEXES.
type CatalogIndex struct {
	Name, Type, State string
}

// SchemaCheck is the outcome for one required constraint or index.
type SchemaCheck struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"` // "constraint" or "index"
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

// CheckConstraints compares the catalog with RequiredConstraints.
func CheckConstraints(cat []CatalogConstraint) []SchemaCheck {
	return CheckConstraintsFor(cat, 1)
}

// CheckConstraintsFor compares the catalog with RequiredConstraintsFor(phase).
func CheckConstraintsFor(cat []CatalogConstraint, phase int) []SchemaCheck {
	by := map[string]CatalogConstraint{}
	for _, c := range cat {
		by[c.Name] = c
	}
	req := RequiredConstraintsFor(phase)
	out := make([]SchemaCheck, 0, len(req))
	for _, r := range req {
		s := SchemaCheck{Name: r.Name, Kind: "constraint"}
		got, ok := by[r.Name]
		switch {
		case !ok:
			s.Message = "missing"
		case !isUniqueness(got.Type) || got.Label != r.Label || got.Prop != r.Prop:
			s.Message = fmt.Sprintf("expected UNIQUENESS on %s.%s, found %s on %s.%s",
				r.Label, r.Prop, got.Type, got.Label, got.Prop)
		default:
			s.Passed = true
		}
		out = append(out, s)
	}
	return out
}

// CheckIndexes compares the catalog with RequiredIndexes; each must be ONLINE.
func CheckIndexes(cat []CatalogIndex) []SchemaCheck {
	by := map[string]CatalogIndex{}
	for _, c := range cat {
		by[c.Name] = c
	}
	out := make([]SchemaCheck, 0, len(RequiredIndexes))
	for _, r := range RequiredIndexes {
		s := SchemaCheck{Name: r.Name, Kind: "index"}
		got, ok := by[r.Name]
		switch {
		case !ok:
			s.Message = "missing"
		case !strings.EqualFold(got.Type, r.Type):
			s.Message = fmt.Sprintf("expected type %s, found %s", r.Type, got.Type)
		case !strings.EqualFold(got.State, "ONLINE"):
			s.Message = "state " + got.State + ", expected ONLINE"
		default:
			s.Passed = true
		}
		out = append(out, s)
	}
	return out
}

// DuplicateGroup is one key value shared by several nodes.
type DuplicateGroup struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// DuplicateCheck is the duplicate-key result for one label.
type DuplicateCheck struct {
	Label  string           `json:"label"`
	Prop   string           `json:"prop"`
	Passed bool             `json:"passed"`
	Groups []DuplicateGroup `json:"groups,omitempty"` // at most MaxExamples
}

// NewDuplicateCheck builds the result, capping groups at MaxExamples.
func NewDuplicateCheck(label, prop string, groups []DuplicateGroup) DuplicateCheck {
	if len(groups) > MaxExamples {
		groups = groups[:MaxExamples]
	}
	return DuplicateCheck{Label: label, Prop: prop, Passed: len(groups) == 0, Groups: groups}
}

// EndpointExample is one relationship with wrong endpoint labels.
type EndpointExample struct {
	ID         string   `json:"id"`
	FromLabels []string `json:"fromLabels"`
	ToLabels   []string `json:"toLabels"`
}

// EndpointCheck is the endpoint-label result for one relationship type.
type EndpointCheck struct {
	Type     string            `json:"type"`
	Expected string            `json:"expected"` // "From->To"
	Passed   bool              `json:"passed"`
	Bad      int64             `json:"bad"`
	Examples []EndpointExample `json:"examples,omitempty"` // at most MaxExamples
}

// NewEndpointCheck builds the result, capping examples at MaxExamples.
func NewEndpointCheck(r EndpointRule, bad int64, ex []EndpointExample) EndpointCheck {
	if len(ex) > MaxExamples {
		ex = ex[:MaxExamples]
	}
	return EndpointCheck{Type: r.Type, Expected: r.From + "->" + r.To, Passed: bad == 0, Bad: bad, Examples: ex}
}

// RejectCheck reports Vulnerabilities whose description starts with the
// REJECT marker although they are not flagged rejected=true.
type RejectCheck struct {
	Passed   bool     `json:"passed"`
	Count    int64    `json:"count"`
	Examples []string `json:"examples,omitempty"` // CVE ids, at most MaxExamples
}

// NewRejectCheck builds the result.
func NewRejectCheck(count int64, ex []string) RejectCheck {
	if len(ex) > MaxExamples {
		ex = ex[:MaxExamples]
	}
	return RejectCheck{Passed: count == 0, Count: count, Examples: ex}
}

// Inputs are everything gathered from the graph.
type Inputs struct {
	Constraints []CatalogConstraint
	Indexes     []CatalogIndex
	Duplicates  []DuplicateCheck
	Endpoints   []EndpointCheck
	Reject      RejectCheck
	// Phase is the highest schema phase applied (0 means 1).
	Phase int
}

// Report is the Validation_Report JSON document.
type Report struct {
	GeneratedAt string   `json:"generatedAt,omitempty"`
	Status      string   `json:"status"` // "passed" or "failed"
	Failed      []string `json:"failed"` // names of failed checks
	// Counts holds the node and relationship counts collected for the smoke check.
	Counts     map[string]int64 `json:"counts,omitempty"`
	Schema     []SchemaCheck    `json:"schema"`
	Duplicates []DuplicateCheck `json:"duplicates"`
	Endpoints  []EndpointCheck  `json:"endpoints"`
	Reject     RejectCheck      `json:"reject"`
	// Queries is filled by the representative-query runner.
	Queries any `json:"queries,omitempty"`
}

// BuildReport runs every pure comparison and assembles the report. All checks
// are evaluated even when an earlier one fails.
func BuildReport(in Inputs) Report {
	r := Report{
		Schema:     append(CheckConstraintsFor(in.Constraints, in.Phase), CheckIndexes(in.Indexes)...),
		Duplicates: nonNilDup(in.Duplicates),
		Endpoints:  nonNilEnd(in.Endpoints),
		Reject:     in.Reject,
		Failed:     []string{},
	}
	for _, s := range r.Schema {
		if !s.Passed {
			r.Failed = append(r.Failed, s.Kind+":"+s.Name)
		}
	}
	for _, d := range r.Duplicates {
		if !d.Passed {
			r.Failed = append(r.Failed, "duplicates:"+d.Label)
		}
	}
	for _, e := range r.Endpoints {
		if !e.Passed {
			r.Failed = append(r.Failed, "endpoints:"+e.Type)
		}
	}
	if !r.Reject.Passed {
		r.Failed = append(r.Failed, "reject")
	}
	sort.Strings(r.Failed)
	r.Status = "passed"
	if len(r.Failed) > 0 {
		r.Status = "failed"
	}
	return r
}

// Passed reports whether the report status is "passed".
func (r Report) Passed() bool { return r.Status == "passed" }

func nonNilDup(d []DuplicateCheck) []DuplicateCheck {
	if d == nil {
		return []DuplicateCheck{}
	}
	return d
}

func nonNilEnd(e []EndpointCheck) []EndpointCheck {
	if e == nil {
		return []EndpointCheck{}
	}
	return e
}

// isUniqueness accepts the uniqueness constraint type as Neo4j 5
// ("UNIQUENESS") and Neo4j 2025+ ("NODE_PROPERTY_UNIQUENESS") report it.
func isUniqueness(t string) bool {
	return t == "UNIQUENESS" || t == "NODE_PROPERTY_UNIQUENESS"
}
