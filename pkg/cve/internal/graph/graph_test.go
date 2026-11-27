package graph

import (
	"errors"
	"testing"
)

func TestPolicyValidate(t *testing.T) {
	for _, l := range []Level{"", LevelCore, LevelEcosystem, LevelComplete} {
		if err := (Policy{Level: l}).Validate(); err != nil {
			t.Errorf("level %q: %v", l, err)
		}
	}
	if err := (Policy{Level: "bogus"}).Validate(); !errors.Is(err, ErrUnknownLevel) {
		t.Fatalf("want ErrUnknownLevel, got %v", err)
	}
	if (Policy{Level: "bogus"}).AllowsNode(NodeVulnerability) {
		t.Error("unknown level must allow nothing")
	}
}

func TestLevelTables(t *testing.T) {
	if len(AllNodeTypes) != 12 || len(AllEdgeTypes) != 12 {
		t.Fatal("vocabulary must be 12 nodes and 12 edges")
	}
	cases := []struct {
		l       Level
		nodes   int
		edges   int
		exploit bool
		pkg     bool
	}{
		{LevelCore, 6, 6, false, false},
		{LevelEcosystem, 11, 11, false, true},
		{LevelComplete, 12, 12, true, true},
		{"", 12, 12, true, true},
	}
	for _, c := range cases {
		p := Policy{Level: c.l}
		if n := len(NodeTypesFor(c.l)); n != c.nodes {
			t.Errorf("%q nodes=%d", c.l, n)
		}
		if n := len(EdgeTypesFor(c.l)); n != c.edges {
			t.Errorf("%q edges=%d", c.l, n)
		}
		if p.AllowsNode(NodeExploit) != c.exploit || p.AllowsEdge(EdgeHasExploit) != c.exploit {
			t.Errorf("%q exploit mismatch", c.l)
		}
		if p.AllowsNode(NodePackage) != c.pkg || p.AllowsEdge(EdgeAffects) != c.pkg {
			t.Errorf("%q package mismatch", c.l)
		}
		if !p.AllowsNode(NodeKEVEntry) || !p.AllowsEdge(EdgeAliasOf) {
			t.Errorf("%q must include core", c.l)
		}
	}
}

func TestEdgeEndpoints(t *testing.T) {
	if len(EdgeEndpoints) != 12 {
		t.Fatalf("endpoints=%d", len(EdgeEndpoints))
	}
	nodes := toSet(AllNodeTypes)
	for _, et := range AllEdgeTypes {
		ep, ok := EdgeEndpoints[et]
		if !ok {
			t.Fatalf("missing endpoints for %s", et)
		}
		for _, n := range append(append([]string{}, ep.Src...), ep.Dst...) {
			if _, ok := nodes[n]; !ok {
				t.Errorf("%s references unknown node type %s", et, n)
			}
		}
	}
	if ep := EdgeEndpoints[EdgeAliasOf]; ep.Src[0] != NodeSourceRecord || ep.Dst[0] != NodeVulnerability {
		t.Error("ALIAS_OF must be SourceRecord -> Vulnerability")
	}
}

func TestStableIDs(t *testing.T) {
	if got := PackageID("PyPI", "Foo_Bar"); got != "pkg:pypi/foo-bar" {
		t.Errorf("package id %q", got)
	}
	if got := ProductID("Apache", "HTTPD"); got != "cpe:apache:httpd" {
		t.Errorf("product id %q", got)
	}
	if VulnerabilityID("CVE-1") != "vuln:CVE-1" || KEVID("CVE-1") != "kev:CVE-1" ||
		EPSSID("CVE-1", "2024-01-01") != "epss:CVE-1:2024-01-01" ||
		VersionID("semver", "pkg:npm/x", "1.0.0") != "ver:semver:pkg:npm/x@1.0.0" {
		t.Error("id format mismatch")
	}
	if ExploitID("v", "u", "s") != ExploitID("v", "u", "s") || ExploitID("v", "u", "s") == PatchID("v", "u", "s") {
		t.Error("exploit/patch ids")
	}
	if len(ExploitID("v", "u", "s")) != len("exp:")+16 {
		t.Error("exploit id length")
	}
	if s := SeverityID("nvd", "r1", "cvss3", "AV:N"); s != SeverityID("nvd", "r1", "cvss3", "AV:N") || len(s) != len("sev:nvd:r1:cvss3:")+12 {
		t.Errorf("severity id %q", s)
	}
	e1 := EdgeID(EdgeAffects, "a", "b")
	if e1 != EdgeID(EdgeAffects, "a", "b") || e1 == EdgeID(EdgeAffects, "b", "a") || len(e1) != 64 {
		t.Error("edge id")
	}
}

func TestCanonicalJSONAndHash(t *testing.T) {
	a := map[string]any{"b": 1, "a": map[string]any{"z": true, "y": nil}, "c": "<x>"}
	b := map[string]any{"c": "<x>", "a": map[string]any{"y": nil, "z": true}, "b": 1}
	ja, err := CanonicalJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	jb, _ := CanonicalJSON(b)
	if string(ja) != string(jb) || string(ja) != `{"a":{"y":null,"z":true},"b":1,"c":"<x>"}` {
		t.Errorf("canonical json %s", ja)
	}
	if p, _ := CanonicalProps(nil); string(p) != "{}" {
		t.Errorf("nil props %s", p)
	}
	n1 := Node{ID: "vuln:1", Type: NodeVulnerability, Props: a}
	n2 := Node{ID: "vuln:1", Type: NodeVulnerability, Props: b}
	h1, _ := NodeHash(n1)
	h2, _ := NodeHash(n2)
	if h1 != h2 || len(h1) != 64 {
		t.Error("node hash not deterministic")
	}
	n2.Props = map[string]any{"b": 2}
	if h3, _ := NodeHash(n2); h3 == h1 {
		t.Error("hash must change with props")
	}
	e := NewEdge(EdgeAffects, "x", "y", nil)
	eh1, _ := EdgeHash(e)
	e.Dst = "z"
	if eh2, _ := EdgeHash(e); eh1 == eh2 {
		t.Error("edge hash must cover dst")
	}
}

func TestIDSet(t *testing.T) {
	s := NewIDSet()
	if err := s.Add(""); !errors.Is(err, ErrEmptyID) {
		t.Errorf("empty: %v", err)
	}
	if err := s.Add("a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("a"); !errors.Is(err, ErrDuplicateID) {
		t.Errorf("dup: %v", err)
	}
	if !s.Seen("a") || s.Seen("b") || s.Len() != 1 {
		t.Error("seen/len")
	}
}
