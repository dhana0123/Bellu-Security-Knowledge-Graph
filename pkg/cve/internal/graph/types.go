// Package graph defines the graph projection types, level policy, stable ids
// and the Sink interface used by the Projector.
package graph

import (
	"context"
	"errors"
	"fmt"
)

// Level is a distribution level.
type Level string

const (
	LevelCore      Level = "core"
	LevelEcosystem Level = "ecosystem"
	LevelComplete  Level = "complete"
)

// ErrUnknownLevel is returned by Policy.Validate for an unsupported level.
var ErrUnknownLevel = errors.New("graph: unknown level")

// Node type names (exactly twelve).
const (
	NodeVulnerability      = "Vulnerability"
	NodeSourceRecord       = "SourceRecord"
	NodeProduct            = "Product"
	NodeVendor             = "Vendor"
	NodePackage            = "Package"
	NodeVersion            = "Version"
	NodeWeakness           = "Weakness"
	NodeSeverityAssessment = "SeverityAssessment"
	NodeExploit            = "Exploit"
	NodePatch              = "Patch"
	NodeEPSSAssessment     = "EPSSAssessment"
	NodeKEVEntry           = "KEVEntry"
)

// Edge type names (exactly twelve).
const (
	EdgeHasSourceRecord = "HAS_SOURCE_RECORD"
	EdgeAliasOf         = "ALIAS_OF"
	EdgeAffects         = "AFFECTS"
	EdgeAffectsVersion  = "AFFECTS_VERSION"
	EdgeBelongsToVendor = "BELONGS_TO_VENDOR"
	EdgeClassifiedAs    = "CLASSIFIED_AS"
	EdgeHasAssessment   = "HAS_ASSESSMENT"
	EdgeHasEPSS         = "HAS_EPSS"
	EdgeListedInKEV     = "LISTED_IN_KEV"
	EdgeHasExploit      = "HAS_EXPLOIT"
	EdgeFixedBy         = "FIXED_BY"
	EdgeFixesVersion    = "FIXES_VERSION"
)

// AllNodeTypes lists the D1 node vocabulary.
var AllNodeTypes = []string{
	NodeVulnerability, NodeSourceRecord, NodeProduct, NodeVendor, NodePackage, NodeVersion,
	NodeWeakness, NodeSeverityAssessment, NodeExploit, NodePatch, NodeEPSSAssessment, NodeKEVEntry,
}

// AllEdgeTypes lists the D1 edge vocabulary.
var AllEdgeTypes = []string{
	EdgeHasSourceRecord, EdgeAliasOf, EdgeAffects, EdgeAffectsVersion, EdgeBelongsToVendor,
	EdgeClassifiedAs, EdgeHasAssessment, EdgeHasEPSS, EdgeListedInKEV, EdgeHasExploit,
	EdgeFixedBy, EdgeFixesVersion,
}

// EdgeEndpoints gives the allowed source and destination node types per edge type.
var EdgeEndpoints = map[string]struct{ Src, Dst []string }{
	EdgeHasSourceRecord: {[]string{NodeVulnerability}, []string{NodeSourceRecord}},
	EdgeAliasOf:         {[]string{NodeSourceRecord}, []string{NodeVulnerability}},
	EdgeAffects:         {[]string{NodeVulnerability}, []string{NodePackage, NodeProduct}},
	EdgeAffectsVersion:  {[]string{NodeVulnerability}, []string{NodeVersion}},
	EdgeBelongsToVendor: {[]string{NodeProduct}, []string{NodeVendor}},
	EdgeClassifiedAs:    {[]string{NodeVulnerability}, []string{NodeWeakness}},
	EdgeHasAssessment:   {[]string{NodeVulnerability}, []string{NodeSeverityAssessment}},
	EdgeHasEPSS:         {[]string{NodeVulnerability}, []string{NodeEPSSAssessment}},
	EdgeListedInKEV:     {[]string{NodeVulnerability}, []string{NodeKEVEntry}},
	EdgeHasExploit:      {[]string{NodeVulnerability}, []string{NodeExploit}},
	EdgeFixedBy:         {[]string{NodeVulnerability}, []string{NodePatch}},
	EdgeFixesVersion:    {[]string{NodePatch}, []string{NodeVersion}},
}

var coreNodes = []string{NodeVulnerability, NodeSourceRecord, NodeWeakness, NodeSeverityAssessment, NodeKEVEntry, NodeEPSSAssessment}
var coreEdges = []string{EdgeHasSourceRecord, EdgeAliasOf, EdgeClassifiedAs, EdgeHasAssessment, EdgeHasEPSS, EdgeListedInKEV}

func concat(a []string, b ...string) []string {
	out := append([]string{}, a...)
	return append(out, b...)
}

var (
	ecosystemNodes = concat(coreNodes, NodePackage, NodeProduct, NodeVendor, NodeVersion, NodePatch)
	ecosystemEdges = concat(coreEdges, EdgeAffects, EdgeAffectsVersion, EdgeBelongsToVendor, EdgeFixedBy, EdgeFixesVersion)
	completeNodes  = concat(ecosystemNodes, NodeExploit)
	completeEdges  = concat(ecosystemEdges, EdgeHasExploit)
)

func toSet(s []string) map[string]struct{} {
	m := make(map[string]struct{}, len(s))
	for _, v := range s {
		m[v] = struct{}{}
	}
	return m
}

var levelNodes = map[Level]map[string]struct{}{
	LevelCore:      toSet(coreNodes),
	LevelEcosystem: toSet(ecosystemNodes),
	LevelComplete:  toSet(completeNodes),
	"":             toSet(AllNodeTypes),
}

var levelEdges = map[Level]map[string]struct{}{
	LevelCore:      toSet(coreEdges),
	LevelEcosystem: toSet(ecosystemEdges),
	LevelComplete:  toSet(completeEdges),
	"":             toSet(AllEdgeTypes),
}

// NodeTypesFor returns the node types of a level (copy). Empty level means all.
func NodeTypesFor(l Level) []string { return orderedSubset(AllNodeTypes, levelNodes[l]) }

// EdgeTypesFor returns the edge types of a level (copy). Empty level means all.
func EdgeTypesFor(l Level) []string { return orderedSubset(AllEdgeTypes, levelEdges[l]) }

func orderedSubset(all []string, set map[string]struct{}) []string {
	var out []string
	for _, t := range all {
		if _, ok := set[t]; ok {
			out = append(out, t)
		}
	}
	return out
}

// Policy selects which part of the projection is emitted.
type Policy struct {
	Level      Level    // "" = full D1 vocabulary
	Ecosystems []string // empty = all
}

// Validate rejects unknown levels.
func (p Policy) Validate() error {
	if _, ok := levelNodes[p.Level]; !ok {
		return fmt.Errorf("%w: %q", ErrUnknownLevel, string(p.Level))
	}
	return nil
}

// AllowsNode reports whether the node type is part of the policy level.
func (p Policy) AllowsNode(t string) bool {
	set, ok := levelNodes[p.Level]
	if !ok {
		return false
	}
	_, ok = set[t]
	return ok
}

// AllowsEdge reports whether the edge type is part of the policy level.
func (p Policy) AllowsEdge(t string) bool {
	set, ok := levelEdges[p.Level]
	if !ok {
		return false
	}
	_, ok = set[t]
	return ok
}

// Node is a graph node.
type Node struct {
	ID    string
	Type  string
	Props map[string]any
}

// Edge is a graph edge.
type Edge struct {
	ID    string
	Type  string
	Src   string
	Dst   string
	Props map[string]any
}

// SinkMeta carries projection metadata to sinks at Begin.
type SinkMeta struct {
	Level         Level
	Ecosystems    []string
	SchemaVersion string
	Engine        string
	EngineVersion string
	HasHistory    bool
	CreatedAt     string
	// Token, when set, is stored in meta.projection_token. Incremental projection uses it to
	// pair a graph.db with its state file.
	Token string
}

// Sink is an output target of the Projector.
type Sink interface {
	Begin(ctx context.Context, meta SinkMeta) error
	WriteNode(n Node) error
	WriteEdge(e Edge) error
	Commit() error // makes output visible atomically
	Abort() error  // removes partial output
}
