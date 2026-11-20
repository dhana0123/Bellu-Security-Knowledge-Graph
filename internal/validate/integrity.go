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

// RequiredConstraint is one VulKG uniqueness constraint (migration V001).
type RequiredConstraint struct{ Name, Label, Prop string }

// RequiredIndex is one VulKG index (migration V001). Type is the Neo4j
// index type: "RANGE" or "FULLTEXT".
type RequiredIndex struct{ Name, Type string }

// RequiredConstraints lists the seven VulKG uniqueness constraints.
var RequiredConstraints = []RequiredConstraint{
	{"UniqueCveID", "Vulnerability", "cveID"},
	{"UniqueEID", "Exploit", "eid"},
	{"UniqueAuthorName", "Author", "authorName"},
	{"UniquecweID", "Weakness", "cweID"},
	{"UniqueDomainName", "Domain", "domainName"},
	{"UniqueProductName", "Product", "productName"},
	{"UniqueVendorName", "Vendor", "vendorName"},
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

// EndpointRules covers the six VulKG relationship types.
var EndpointRules = []EndpointRule{
	{"WRITES", "Author", "Exploit"},
	{"EXPLOITS", "Exploit", "Vulnerability"},
	{"EXAMPLE_OF", "Vulnerability", "Weakness"},
	{"REFERS_TO", "Vulnerability", "Domain"},
	{"AFFECTS", "Vulnerability", "Product"},
	{"BELONGS_TO", "Product", "Vendor"},
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
	by := map[string]CatalogConstraint{}
	for _, c := range cat {
		by[c.Name] = c
	}
	out := make([]SchemaCheck, 0, len(RequiredConstraints))
	for _, r := range RequiredConstraints {
		s := SchemaCheck{Name: r.Name, Kind: "constraint"}
		got, ok := by[r.Name]
		switch {
		case !ok:
			s.Message = "missing"
		case got.Type != "UNIQUENESS" || got.Label != r.Label || got.Prop != r.Prop:
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

// LoaderCounts is what the baseline loader recorded on (:Job {name:"baseline-load"}).
//
// Storage contract (the loader must write these properties on that node):
//
//	missing_<step>  integer  rows of that step whose relationship endpoint
//	                         was missing (steps: exploits_rel, example_of,
//	                         domain_refers, product_affects, vendor_belongs,
//	                         writes, affected_version); absent = not recorded
//	rejectDeleted   integer  Vulnerability nodes deleted by step reject_delete
//	bareNodes       integer  bare Vulnerability nodes created by step 8
type LoaderCounts struct {
	MissingEndpoints map[string]int64 `json:"missingEndpoints"`
	RejectDeleted    *int64           `json:"rejectDeleted"`
	BareNodes        *int64           `json:"bareNodes"`
}

// MissingPrefix is the Job property prefix for per-step missing endpoints.
const MissingPrefix = "missing_"

// LoaderCountsFromProps extracts LoaderCounts from Job node properties.
func LoaderCountsFromProps(props map[string]any) LoaderCounts {
	lc := LoaderCounts{MissingEndpoints: map[string]int64{}}
	for k, v := range props {
		n, ok := v.(int64)
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(k, MissingPrefix):
			lc.MissingEndpoints[strings.TrimPrefix(k, MissingPrefix)] = n
		case k == "rejectDeleted":
			x := n
			lc.RejectDeleted = &x
		case k == "bareNodes":
			x := n
			lc.BareNodes = &x
		}
	}
	return lc
}

// Inputs are everything gathered from the graph. Nil/empty sections are
// omitted from the report (the "integrity" profile has no Counts).
type Inputs struct {
	Profile     string
	Expected    *Expected
	Discrepancy []Discrepancy
	Counts      map[string]int64 // nil: skip count comparison
	Constraints []CatalogConstraint
	Indexes     []CatalogIndex
	Duplicates  []DuplicateCheck
	Endpoints   []EndpointCheck
	Reject      RejectCheck
	Loader      LoaderCounts
}

// Report is the Validation_Report JSON document.
type Report struct {
	Profile     string           `json:"profile"`
	GeneratedAt string           `json:"generatedAt,omitempty"`
	Status      string           `json:"status"` // "passed" or "failed"
	Failed      []string         `json:"failed"` // names of failed checks
	Counts      []Result         `json:"counts,omitempty"`
	Schema      []SchemaCheck    `json:"schema"`
	Duplicates  []DuplicateCheck `json:"duplicates"`
	Endpoints   []EndpointCheck  `json:"endpoints"`
	Reject      RejectCheck      `json:"reject"`
	Loader      LoaderCounts     `json:"loader"`
	// Queries is filled by the representative-query runner (task 6.3).
	Queries any `json:"queries,omitempty"`
}

// BuildReport runs every pure comparison and assembles the report. All checks
// are evaluated even when an earlier one fails.
func BuildReport(in Inputs) Report {
	r := Report{
		Profile:    in.Profile,
		Schema:     append(CheckConstraints(in.Constraints), CheckIndexes(in.Indexes)...),
		Duplicates: nonNilDup(in.Duplicates),
		Endpoints:  nonNilEnd(in.Endpoints),
		Reject:     in.Reject,
		Loader:     in.Loader,
		Failed:     []string{},
	}
	if r.Loader.MissingEndpoints == nil {
		r.Loader.MissingEndpoints = map[string]int64{}
	}
	if in.Counts != nil && in.Expected != nil {
		r.Counts = CompareCounts(*in.Expected, in.Discrepancy, in.Counts)
		for _, c := range r.Counts {
			if !c.Passed {
				r.Failed = append(r.Failed, "count:"+c.Metric)
			}
		}
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
