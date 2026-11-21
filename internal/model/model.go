// Package model is the schema registry: every node label and relationship
// type of the graph, with key property and phase. It drives reset, the
// Integrity_Validator, the API allow-lists, and the statistics queries.
package model

import "sort"

// Kind separates domain labels from bookkeeping labels.
type Kind int

const (
	// Domain labels hold security data.
	Domain Kind = iota
	// Bookkeeping labels hold pipeline state.
	Bookkeeping
)

// Label describes one node label.
type Label struct {
	Name  string
	Key   string // key property; unique per label
	Phase int    // 1, 2, or 3
	Kind  Kind
}

// RelType describes one relationship type.
type RelType struct {
	Name     string
	From, To string
	// Identity lists the properties that make two relationships between the
	// same pair distinct (CHILD_OF has viewID).
	Identity []string
	Phase    int
}

// Labels lists every label. Domain labels first, in schema order.
var Labels = []Label{
	{"Vulnerability", "cveID", 1, Domain},
	{"Exploit", "eid", 1, Domain},
	{"Author", "authorName", 1, Domain},
	{"Weakness", "cweID", 1, Domain},
	{"Domain", "domainName", 1, Domain},
	{"Product", "productName", 1, Domain},
	{"Vendor", "vendorName", 1, Domain},
	{"Package", "purl", 2, Domain},
	{"Repository", "url", 1, Domain},
	{"FixCommit", "fcKey", 1, Domain},
	{"AttackPattern", "capecID", 3, Domain},
	{"Technique", "attackID", 3, Domain},
	{"AtlasTechnique", "atlasID", 3, Domain},
	{"Checkpoint", "source", 1, Bookkeeping},
	{"Lock", "source", 1, Bookkeeping},
	{"SyncRun", "id", 1, Bookkeeping},
	{"Job", "name", 1, Bookkeeping},
	{"BuildMeta", "id", 1, Bookkeeping},
	{"DeadLetter", "id", 1, Bookkeeping},
	{"Change", "id", 1, Bookkeeping},
	{"ApiKey", "id", 1, Bookkeeping},
	{"Migration", "version", 1, Bookkeeping},
}

// Rels lists every relationship type.
var Rels = []RelType{
	{"WRITES", "Author", "Exploit", nil, 1},
	{"EXPLOITS", "Exploit", "Vulnerability", nil, 1},
	{"EXAMPLE_OF", "Vulnerability", "Weakness", nil, 1},
	{"REFERS_TO", "Vulnerability", "Domain", nil, 1},
	{"AFFECTS", "Vulnerability", "Product", nil, 1},
	{"BELONGS_TO", "Product", "Vendor", nil, 1},
	{"CHILD_OF", "Weakness", "Weakness", []string{"viewID"}, 1},
	{"AFFECTS_PACKAGE", "Vulnerability", "Package", nil, 2},
	{"HOSTED_IN", "Package", "Repository", nil, 2},
	{"REFERS_TO_REPOSITORY", "Vulnerability", "Repository", nil, 1},
	{"HAS_FIX_COMMIT", "Repository", "FixCommit", nil, 1},
	{"FIXES", "FixCommit", "Vulnerability", nil, 1},
	{"RELATED_ATTACK_PATTERN", "Weakness", "AttackPattern", nil, 3},
	{"MAPS_TO_TECHNIQUE", "AttackPattern", "Technique", nil, 3},
}

// ExploitProps are the only properties stored on an Exploit node besides the
// key (Requirements 7.5, 29.2): publish date, type, platform. The author is
// the Author node. Exploit code is never stored.
var ExploitProps = []string{"exploitPublishDate", "exploitType", "platform"}

// LabelByName returns the label with the given name.
func LabelByName(name string) (Label, bool) {
	for _, l := range Labels {
		if l.Name == name {
			return l, true
		}
	}
	return Label{}, false
}

// RelByName returns the relationship type with the given name.
func RelByName(name string) (RelType, bool) {
	for _, r := range Rels {
		if r.Name == name {
			return r, true
		}
	}
	return RelType{}, false
}

// DomainLabels returns the names of the domain labels up to maxPhase.
func DomainLabels(maxPhase int) []string {
	var out []string
	for _, l := range Labels {
		if l.Kind == Domain && l.Phase <= maxPhase {
			out = append(out, l.Name)
		}
	}
	return out
}

// ResetLabels returns the labels `bskg reset` empties: every label except
// Migration and ApiKey, sorted by name.
func ResetLabels() []string {
	var out []string
	for _, l := range Labels {
		if l.Name != "Migration" && l.Name != "ApiKey" {
			out = append(out, l.Name)
		}
	}
	sort.Strings(out)
	return out
}
