package baseline_test

// Reference model of the VulKG MERGE semantics (design: Baseline, "Property 23"
// and "Property 24"). It is pure Go: input is the eight CSV tables, output is a
// set of nodes and relationships (with canonical property strings) and the
// loader's counters. The model deliberately does not call the loader code.
//
// Canonical property strings carry the stored type as a prefix so that integer
// versus decimal and list versus string differences are visible:
// "s:", "i:", "f:", "b:", "d:" (date) and "l:[a<US>b]" (list of strings or dates).

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/bellu/bskg/internal/baseline"
)

// ---- tables ----------------------------------------------------------------

type mtable struct {
	cols []string
	rows []map[string]string
}

type mtables map[string]*mtable

func (ts mtables) rows(logical string) []map[string]string {
	if t := ts[logical]; t != nil {
		return t.rows
	}
	return nil
}

// cell returns the trimmed value; empty means absent (as in baseline.Row.Get).
func cell(r map[string]string, col string) (string, bool) {
	v := strings.TrimSpace(r[col])
	return v, v != ""
}

var modelScriptNames = map[string]string{
	baseline.LogicalVulnerabilityNodes:         "VulnerabilityNodes.csv",
	baseline.LogicalVulnerabilityAddProperties: "VulnerabilityNodesAddProperties.csv",
	baseline.LogicalExploitNodes:               "ExploitNodes.csv",
	baseline.LogicalHasExploit:                 "Vulnerability_HAS_EXPLOIT_Exploit_relationship.csv",
	baseline.LogicalWeaknessNodes:              "WeaknessNodes.csv",
	baseline.LogicalDomainRelationship:         "DomainNodes_Vulnerability_HAS_REFERENCE_Domain_relationship.csv",
	baseline.LogicalProductVendorAffects:       "ProductNodes_VendorNodes_Vulnerability_AFFECTS_Product_BELONGS_TO_Vendor.csv",
	baseline.LogicalAffectsAddProperty:         "AffectsAddProperty.csv",
}

func readModelTable(path string) (*mtable, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	hdr, err := r.Read()
	if err != nil {
		return nil, err
	}
	t := &mtable{}
	for _, c := range hdr {
		t.cols = append(t.cols, strings.TrimPrefix(strings.TrimSpace(c), "\ufeff"))
	}
	for {
		rec, err := r.Read()
		if err != nil {
			break // io.EOF; a malformed file fails the comparisons later
		}
		row := map[string]string{}
		for i, c := range t.cols {
			if _, dup := row[c]; !dup && i < len(rec) {
				row[c] = rec[i]
			}
		}
		t.rows = append(t.rows, row)
	}
	return t, nil
}

func readModelTables(dir string) (mtables, error) {
	ts := mtables{}
	for logical, name := range modelScriptNames {
		t, err := readModelTable(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		ts[logical] = t
	}
	return ts, nil
}

// ---- canonical values ------------------------------------------------------

type mtype int

const (
	mString mtype = iota
	mInt
	mFloat
	mBool
	mDate
	mList
)

type mfield struct {
	col, prop string
	t         mtype
}

func canonList(items []string) string { return "l:[" + strings.Join(items, "\x1f") + "]" }

func canonField(t mtype, s string) (string, error) {
	switch t {
	case mString:
		return "s:" + s, nil
	case mInt:
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return "i:" + strconv.FormatInt(n, 10), nil
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || f != math.Trunc(f) {
			return "", fmt.Errorf("model: invalid integer %q", s)
		}
		return "i:" + strconv.FormatInt(int64(f), 10), nil
	case mFloat:
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return "", fmt.Errorf("model: invalid decimal %q", s)
		}
		return "f:" + strconv.FormatFloat(f, 'g', -1, 64), nil
	case mBool:
		switch strings.ToLower(s) {
		case "true":
			return "b:true", nil
		case "false":
			return "b:false", nil
		}
		return "", fmt.Errorf("model: invalid boolean %q", s)
	case mDate:
		d, err := time.Parse("2006-01-02", s)
		if err != nil {
			return "", fmt.Errorf("model: invalid date %q", s)
		}
		return "d:" + d.Format("2006-01-02"), nil
	case mList:
		items := []string{}
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				items = append(items, p)
			}
		}
		return canonList(items), nil
	}
	return "", fmt.Errorf("model: unknown type %d", t)
}

func fieldProps(row map[string]string, fields []mfield) (map[string]string, error) {
	out := map[string]string{}
	for _, f := range fields {
		s, ok := cell(row, f.col)
		if !ok {
			continue
		}
		v, err := canonField(f.t, s)
		if err != nil {
			return nil, err
		}
		out[f.prop] = v
	}
	return out, nil
}

// Column mapping of the VulKG script (CVSS scores are decimals, Requirement 4.9).
var (
	modelVulnFields = []mfield{
		{"publishedDate", "publishedDate", mDate},
		{"description_value", "description", mString},
		{"num_reference", "numOfReference", mInt},
		{"v2version", "v2version", mInt},
		{"v2baseScore", "v2baseScore", mFloat},
		{"v2accessVector", "v2accessVector", mString},
		{"v2accessComplexity", "v2accessComplexity", mString},
		{"v2authentication", "v2authentication", mString},
		{"v2confidentialityImpact", "v2confidentialityImpact", mString},
		{"v2integrityImpact", "v2integrityImpact", mString},
		{"v2availabilityImpact", "v2availabilityImpact", mString},
		{"v2vectorString", "v2vectorString", mString},
		{"v2impactScore", "v2impactScore", mFloat},
		{"v2exploitabilityScore", "v2exploitabilityScore", mFloat},
		{"v2userInteractionRequired", "v2userInteractionRequired", mBool},
		{"v2severity", "v2severity", mString},
		{"v2obtainUserPrivilege", "v2obtainUserPrivilege", mBool},
		{"v2obtainAllPrivilege", "v2obtainAllPrivilege", mBool},
		{"v2acInsufInfo", "v2acInsufInfo", mBool},
		{"v2obtainOtherPrivilege", "v2obtainOtherPrivilege", mBool},
		{"v3version", "v3version", mFloat},
		{"v3baseScore", "v3baseScore", mFloat},
		{"v3attackVector", "v3attackVector", mString},
		{"v3attackComplexity", "v3attackComplexity", mString},
		{"v3privilegesRequired", "v3privilegesRequired", mString},
		{"v3userInteraction", "v3userInteraction", mString},
		{"v3scope", "v3scope", mString},
		{"v3confidentialityImpact", "v3confidentialityImpact", mString},
		{"v3integrityImpact", "v3integrityImpact", mString},
		{"v3availabilityImpact", "v3availabilityImpact", mString},
		{"v3vectorString", "v3vectorString", mString},
		{"v3impactScore", "v3impactScore", mFloat},
		{"v3exploitabilityScore", "v3exploitabilityScore", mFloat},
		{"v3baseSeverity", "v3baseSeverity", mString},
	}
	modelExploitFields = []mfield{
		{"Exploit_Date", "exploitPublishDate", mDate},
		{"Exploit_Type", "exploitType", mString},
		{"Platform", "platform", mString},
	}
	modelWeaknessFields = []mfield{
		{"cweView", "cweView", mList},
		{"cweName", "cweName", mString},
		{"weaknessAbstraction", "weaknessAbstraction", mString},
		{"status", "status", mString},
		{"description", "description", mString},
		{"extendedDescription", "extendedDescription", mString},
	}
)

// ---- graph -----------------------------------------------------------------

const sep = "\x00"

type mrel struct {
	typ, fl, fk, tl, tk string
	props               map[string]string
}

type mgraph struct {
	nodes map[string]map[string]string // label+sep+key -> props
	rels  map[string]*mrel             // typ+sep+fl+sep+fk+sep+tl+sep+tk
}

func newMGraph() *mgraph {
	return &mgraph{nodes: map[string]map[string]string{}, rels: map[string]*mrel{}}
}

func copyProps(p map[string]string) map[string]string {
	out := make(map[string]string, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

func (g *mgraph) clone() *mgraph {
	c := newMGraph()
	for k, p := range g.nodes {
		c.nodes[k] = copyProps(p)
	}
	for k, r := range g.rels {
		cr := *r
		cr.props = copyProps(r.props)
		c.rels[k] = &cr
	}
	return c
}

func nkey(label, key string) string { return label + sep + key }

func (g *mgraph) has(label, key string) bool { _, ok := g.nodes[nkey(label, key)]; return ok }

// mergeNode is MERGE ... ON CREATE SET props. It reports whether it created the node.
func (g *mgraph) mergeNode(label, key string, onCreate map[string]string) bool {
	k := nkey(label, key)
	if _, ok := g.nodes[k]; ok {
		return false
	}
	g.nodes[k] = copyProps(onCreate)
	return true
}

func (g *mgraph) mergeRel(typ, fl, fk, tl, tk string, onCreate map[string]string) {
	k := strings.Join([]string{typ, fl, fk, tl, tk}, sep)
	if _, ok := g.rels[k]; ok {
		return
	}
	g.rels[k] = &mrel{typ, fl, fk, tl, tk, copyProps(onCreate)}
}

func (g *mgraph) countNodes(label string) int64 {
	var n int64
	for k := range g.nodes {
		if strings.HasPrefix(k, label+sep) {
			n++
		}
	}
	return n
}

func (g *mgraph) countRels(typ string) int64 {
	var n int64
	for _, r := range g.rels {
		if r.typ == typ {
			n++
		}
	}
	return n
}

// modelCounters are the loader's reported numbers for one load.
type modelCounters struct {
	bare        int64            // Job.bareNodes
	rejectNodes int64            // Job.rejectDeleted
	rejectRels  int64            // Job.rejectRelsDeleted
	missing     map[string]int64 // step name -> Job.missing_<step>
	preReject   map[string]int64 // counts just before step 13 (labels and types)
}

var (
	modelLabels = []string{"Vulnerability", "Exploit", "Author", "Weakness", "Domain", "Product", "Vendor"}
	modelTypes  = []string{"WRITES", "EXPLOITS", "EXAMPLE_OF", "REFERS_TO", "AFFECTS", "BELONGS_TO"}
)

// applyLoad performs the 14 VulKG steps on g (which may already hold the graph
// of an earlier load) and returns the counters of this load.
func (g *mgraph) applyLoad(ts mtables) (modelCounters, error) {
	cn := modelCounters{missing: map[string]int64{}, preReject: map[string]int64{}}

	// 1 vuln_nodes: MERGE ... ON CREATE SET all properties.
	for _, row := range ts.rows(baseline.LogicalVulnerabilityNodes) {
		cve, ok := cell(row, "cveID")
		if !ok {
			continue
		}
		p, err := fieldProps(row, modelVulnFields)
		if err != nil {
			return cn, err
		}
		g.mergeNode("Vulnerability", cve, p)
	}
	// 2 exploit_nodes, 3 author_nodes.
	for _, row := range ts.rows(baseline.LogicalExploitNodes) {
		eid, ok := cell(row, "ExploitID")
		if !ok {
			continue
		}
		p, err := fieldProps(row, modelExploitFields)
		if err != nil {
			return cn, err
		}
		g.mergeNode("Exploit", eid, p)
	}
	for _, row := range ts.rows(baseline.LogicalExploitNodes) {
		if a, ok := cell(row, "Author"); ok {
			g.mergeNode("Author", a, nil)
		}
	}
	// 4 writes.
	var sent, matched int64
	for _, row := range ts.rows(baseline.LogicalExploitNodes) {
		a, okA := cell(row, "Author")
		e, okE := cell(row, "ExploitID")
		if !okA || !okE {
			continue
		}
		sent++
		if g.has("Exploit", e) && g.has("Author", a) {
			matched++
			g.mergeRel("WRITES", "Author", a, "Exploit", e, nil)
		}
	}
	cn.missing[baseline.StepWrites] = sent - matched
	// 5 exploits_rel.
	sent, matched = 0, 0
	for _, row := range ts.rows(baseline.LogicalHasExploit) {
		e, okE := cell(row, "eid")
		c, okC := cell(row, "cveID")
		if !okE || !okC {
			continue
		}
		sent++
		if g.has("Exploit", e) && g.has("Vulnerability", c) {
			matched++
			g.mergeRel("EXPLOITS", "Exploit", e, "Vulnerability", c, nil)
		}
	}
	cn.missing[baseline.StepExploitsRel] = sent - matched
	// 6 weakness_nodes.
	for _, row := range ts.rows(baseline.LogicalWeaknessNodes) {
		w, ok := cell(row, "cweID")
		if !ok {
			continue
		}
		p, err := fieldProps(row, modelWeaknessFields)
		if err != nil {
			return cn, err
		}
		g.mergeNode("Weakness", w, p)
	}
	// 7 example_of.
	sent, matched = 0, 0
	for _, row := range ts.rows(baseline.LogicalVulnerabilityAddProperties) {
		c, okC := cell(row, "cveID")
		w, okW := cell(row, "CWEID")
		if !okC || !okW {
			continue
		}
		sent++
		if g.has("Vulnerability", c) && g.has("Weakness", w) {
			matched++
			g.mergeRel("EXAMPLE_OF", "Vulnerability", c, "Weakness", w, nil)
		}
	}
	cn.missing[baseline.StepExampleOf] = sent - matched
	// 8 vuln_addprops: ON MATCH SET only; a created node is bare.
	for _, row := range ts.rows(baseline.LogicalVulnerabilityAddProperties) {
		c, ok := cell(row, "cveID")
		if !ok {
			continue
		}
		if g.mergeNode("Vulnerability", c, nil) {
			cn.bare++
			continue
		}
		p := g.nodes[nkey("Vulnerability", c)]
		if v, ok := cell(row, "GainedAccess"); ok {
			p["gainedAccess"] = "s:" + v
		} else {
			delete(p, "gainedAccess")
		}
		if v, ok := cell(row, "VulnerabilityType"); ok {
			l, err := canonField(mList, v)
			if err != nil {
				return cn, err
			}
			p["vulnerabilityType"] = l
		} else {
			delete(p, "vulnerabilityType")
		}
	}
	// 9 domain_refers: a Domain for every row, the relationship needs the Vulnerability.
	sent, matched = 0, 0
	for _, row := range ts.rows(baseline.LogicalDomainRelationship) {
		c, okC := cell(row, "cveID")
		d, okD := cell(row, "domainName")
		if !okC || !okD {
			continue
		}
		sent++
		g.mergeNode("Domain", d, nil)
		if g.has("Vulnerability", c) {
			matched++
			g.mergeRel("REFERS_TO", "Vulnerability", c, "Domain", d, nil)
		}
	}
	cn.missing[baseline.StepDomainRefers] = sent - matched
	// 10 product_affects: first row wins for productType and numOfVersion.
	sent, matched = 0, 0
	for _, row := range ts.rows(baseline.LogicalProductVendorAffects) {
		c, okC := cell(row, "cveID")
		p, okP := cell(row, "Product")
		if !okC || !okP {
			continue
		}
		sent++
		pp := map[string]string{}
		if t, ok := cell(row, "ProductType"); ok {
			pp["productType"] = "s:" + t
		}
		g.mergeNode("Product", p, pp)
		if g.has("Vulnerability", c) {
			matched++
			rp := map[string]string{}
			if n, ok := cell(row, "Nversions"); ok {
				v, err := canonField(mInt, n)
				if err != nil {
					return cn, err
				}
				rp["numOfVersion"] = v
			}
			g.mergeRel("AFFECTS", "Vulnerability", c, "Product", p, rp)
		}
	}
	cn.missing[baseline.StepProductAffects] = sent - matched
	// 11 vendor_belongs.
	sent, matched = 0, 0
	for _, row := range ts.rows(baseline.LogicalProductVendorAffects) {
		p, okP := cell(row, "Product")
		v, okV := cell(row, "Vendor")
		if !okP || !okV {
			continue
		}
		sent++
		g.mergeNode("Vendor", v, nil)
		if g.has("Product", p) {
			matched++
			g.mergeRel("BELONGS_TO", "Product", p, "Vendor", v, nil)
		}
	}
	cn.missing[baseline.StepVendorBelongs] = sent - matched
	// 12 affected_version: replace per load with the file-order list per pair.
	versions := map[string][]string{}
	sent, matched = 0, 0
	for _, row := range ts.rows(baseline.LogicalAffectsAddProperty) {
		c, okC := cell(row, "cveID")
		p, okP := cell(row, "Product")
		v, okV := cell(row, "Version")
		if !okC || !okP || !okV {
			continue
		}
		sent++
		k := strings.Join([]string{"AFFECTS", "Vulnerability", c, "Product", p}, sep)
		if _, ok := g.rels[k]; ok {
			matched++
			versions[k] = append(versions[k], v)
		}
	}
	cn.missing[baseline.StepAffectedVer] = sent - matched
	for k, r := range g.rels {
		if r.typ == "AFFECTS" {
			r.props["affectedVersion"] = canonList(append([]string{}, versions[k]...))
		}
	}
	// 13 reject_delete.
	for _, l := range modelLabels {
		cn.preReject[l] = g.countNodes(l)
	}
	for _, t := range modelTypes {
		cn.preReject[t] = g.countRels(t)
	}
	doomed := map[string]bool{}
	for k, p := range g.nodes {
		if strings.HasPrefix(k, "Vulnerability"+sep) && strings.HasPrefix(p["description"], "s:** REJECT **") {
			doomed[k] = true
		}
	}
	for k, r := range g.rels {
		if doomed[nkey(r.fl, r.fk)] || doomed[nkey(r.tl, r.tk)] {
			cn.rejectRels++
			delete(g.rels, k)
		}
	}
	cn.rejectNodes = int64(len(doomed))
	for k := range doomed {
		delete(g.nodes, k)
	}
	// 14 exploitability: recomputed for every Vulnerability.
	dates := map[string][]string{}
	has := map[string]bool{}
	for _, r := range g.rels {
		if r.typ != "EXPLOITS" {
			continue
		}
		vk := nkey(r.tl, r.tk)
		has[vk] = true
		if d, ok := g.nodes[nkey(r.fl, r.fk)]["exploitPublishDate"]; ok {
			dates[vk] = append(dates[vk], strings.TrimPrefix(d, "d:"))
		}
	}
	for k, p := range g.nodes {
		if !strings.HasPrefix(k, "Vulnerability"+sep) {
			continue
		}
		ds := append([]string{}, dates[k]...)
		sort.Strings(ds)
		if has[k] {
			p["exploitability"] = "i:1"
		} else {
			p["exploitability"] = "i:0"
		}
		p["exploitDate"] = canonList(ds)
	}
	return cn, nil
}

// diffGraphs describes up to 12 differences between want and got ("" when equal).
func diffGraphs(want, got *mgraph) string {
	var out []string
	add := func(format string, a ...any) {
		if len(out) < 12 {
			out = append(out, fmt.Sprintf(format, a...))
		}
	}
	show := func(k string) string { return strings.ReplaceAll(k, sep, "/") }
	keys := func(m map[string]map[string]string) []string {
		var ks []string
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return ks
	}
	flat := func(g *mgraph) (map[string]map[string]string, map[string]map[string]string) {
		rels := map[string]map[string]string{}
		for k, r := range g.rels {
			rels[k] = r.props
		}
		return g.nodes, rels
	}
	wn, wr := flat(want)
	gn, gr := flat(got)
	for _, pair := range []struct {
		what string
		w, g map[string]map[string]string
	}{{"node", wn, gn}, {"relationship", wr, gr}} {
		for _, k := range keys(pair.w) {
			gp, ok := pair.g[k]
			switch {
			case !ok:
				add("missing %s %s", pair.what, show(k))
			case !reflect.DeepEqual(pair.w[k], gp):
				add("%s %s: want %q got %q", pair.what, show(k), pair.w[k], gp)
			}
		}
		for _, k := range keys(pair.g) {
			if _, ok := pair.w[k]; !ok {
				add("unexpected %s %s %q", pair.what, show(k), pair.g[k])
			}
		}
	}
	return strings.Join(out, "\n")
}

// ---- generators ------------------------------------------------------------

var (
	genCVEs = func() []string {
		var o []string
		for i := 1; i <= 8; i++ { // 1..6 usually in the vulnerability file, 7..8 never
			o = append(o, fmt.Sprintf("CVE-2019-%04d", i))
		}
		return o
	}()
	genKnownCVEs = genCVEs[:6]
)

var (
	vulnHeader = append([]string{"cveID"}, func() []string {
		var c []string
		for _, f := range modelVulnFields {
			c = append(c, f.col)
		}
		return c
	}()...)
	addPropsHeader  = []string{"cveID", "CWEID", "GainedAccess", "VulnerabilityType"}
	exploitHeader   = []string{"ExploitID", "Exploit_Date", "Author", "Exploit_Type", "Platform"}
	hasExploitHdr   = []string{"eid", "cveID"}
	weaknessHeader  = []string{"cweID", "cweView", "cweName", "weaknessAbstraction", "status", "description", "extendedDescription"}
	domainHeader    = []string{"cveID", "domainName"}
	productHeader   = []string{"cveID", "Product", "ProductType", "Nversions", "Vendor"}
	affectsAddHdr   = []string{"cveID", "Product", "Version"}
	headerByLogical = map[string][]string{
		baseline.LogicalVulnerabilityNodes:         vulnHeader,
		baseline.LogicalVulnerabilityAddProperties: addPropsHeader,
		baseline.LogicalExploitNodes:               exploitHeader,
		baseline.LogicalHasExploit:                 hasExploitHdr,
		baseline.LogicalWeaknessNodes:              weaknessHeader,
		baseline.LogicalDomainRelationship:         domainHeader,
		baseline.LogicalProductVendorAffects:       productHeader,
		baseline.LogicalAffectsAddProperty:         affectsAddHdr,
	}
)

func genValue(t *rapid.T, label string, typ mtype) string {
	switch typ {
	case mInt:
		return strconv.Itoa(rapid.IntRange(0, 9).Draw(t, label))
	case mFloat:
		if rapid.IntRange(0, 3).Draw(t, label+"-shape") == 0 {
			return strconv.Itoa(rapid.IntRange(0, 10).Draw(t, label)) // integer-looking decimal
		}
		return fmt.Sprintf("%d.%d", rapid.IntRange(0, 10).Draw(t, label), rapid.IntRange(0, 9).Draw(t, label+"-frac"))
	case mBool:
		return rapid.SampledFrom([]string{"true", "false", "TRUE"}).Draw(t, label)
	case mDate:
		return fmt.Sprintf("%04d-%02d-%02d", rapid.IntRange(2015, 2020).Draw(t, label+"-y"),
			rapid.IntRange(1, 12).Draw(t, label+"-m"), rapid.IntRange(1, 28).Draw(t, label+"-d"))
	case mList:
		return rapid.SampledFrom([]string{"A", "A,B", "Execute Code, Overflow", "B,"}).Draw(t, label)
	}
	return rapid.SampledFrom([]string{"NETWORK", "LOW", "a, b", `say "hi"`, "MEDIUM"}).Draw(t, label)
}

// optional returns a generated value, or an empty/blank field about a third of the time.
func optional(t *rapid.T, label string, typ mtype) string {
	if rapid.IntRange(0, 2).Draw(t, label+"-present") == 0 {
		return rapid.SampledFrom([]string{"", " "}).Draw(t, label+"-blank")
	}
	return genValue(t, label, typ)
}

func fieldRow(t *rapid.T, fields []mfield) map[string]string {
	row := map[string]string{}
	for _, f := range fields {
		row[f.col] = optional(t, f.col, f.t)
	}
	return row
}

// genTables generates the eight tables. With allowBare false, every cveID in the
// add-properties file also appears in the vulnerability file (no bare nodes).
func genTables(t *rapid.T, allowBare bool) mtables {
	ts := mtables{}
	for l, h := range headerByLogical {
		ts[l] = &mtable{cols: h}
	}
	n := func(label string, max int) int { return rapid.IntRange(0, max).Draw(t, label) }
	pick := func(label string, pool []string) string { return rapid.SampledFrom(pool).Draw(t, label) }
	add := func(logical string, row map[string]string) { ts[logical].rows = append(ts[logical].rows, row) }

	known := map[string]bool{}
	for i, c := 0, n("nVuln", 8); i < c; i++ {
		row := fieldRow(t, modelVulnFields)
		cve := pick("vulnCVE", genKnownCVEs)
		row["cveID"] = cve
		known[cve] = true
		row["description_value"] = pick("desc", []string{"", "Plain flaw", "Another, flaw", "** REJECT ** DO NOT USE", "** REJECT ** x", "Not ** REJECT ** here"})
		add(baseline.LogicalVulnerabilityNodes, row)
	}
	for i, c := 0, n("nExploit", 6); i < c; i++ {
		add(baseline.LogicalExploitNodes, map[string]string{
			"ExploitID":    pick("exploitID", []string{"40001", "40002", "40003", "40004"}),
			"Exploit_Date": optional(t, "exploitDate", mDate),
			"Author":       pick("author", []string{"alice", "bob", "carol", "", " "}),
			"Exploit_Type": optional(t, "exploitType", mString),
			"Platform":     optional(t, "platform", mString),
		})
	}
	for i, c := 0, n("nHasExploit", 8); i < c; i++ {
		add(baseline.LogicalHasExploit, map[string]string{
			"eid":   pick("heEid", []string{"40001", "40002", "40003", "40004", "40005", "40006"}),
			"cveID": pick("heCVE", genCVEs),
		})
	}
	for i, c := 0, n("nWeakness", 5); i < c; i++ {
		row := fieldRow(t, modelWeaknessFields)
		row["cweID"] = pick("cweID", []string{"CWE-1", "CWE-2", "CWE-3", "CWE-4"})
		add(baseline.LogicalWeaknessNodes, row)
	}
	cvePool := genCVEs
	if !allowBare {
		cvePool = nil
		for _, c := range genKnownCVEs {
			if known[c] {
				cvePool = append(cvePool, c)
			}
		}
	}
	nAdd := n("nAddProps", 8)
	if len(cvePool) == 0 {
		nAdd = 0
	}
	for i := 0; i < nAdd; i++ {
		add(baseline.LogicalVulnerabilityAddProperties, map[string]string{
			"cveID":             pick("apCVE", cvePool),
			"CWEID":             pick("apCWE", []string{"CWE-1", "CWE-2", "CWE-3", "CWE-4", "CWE-5", "CWE-6", ""}),
			"GainedAccess":      optional(t, "gained", mString),
			"VulnerabilityType": optional(t, "vtype", mList),
		})
	}
	for i, c := 0, n("nDomain", 8); i < c; i++ {
		add(baseline.LogicalDomainRelationship, map[string]string{
			"cveID":      pick("dCVE", genCVEs),
			"domainName": pick("domain", []string{"d1.example.com", "d2.example.com", "d3.example.com", "d4.example.com"}),
		})
	}
	products := []string{"p1", "p2", "p3", "p4"}
	for i, c := 0, n("nProduct", 10); i < c; i++ {
		add(baseline.LogicalProductVendorAffects, map[string]string{
			"cveID":       pick("pCVE", append([]string{""}, genCVEs...)),
			"Product":     pick("product", products),
			"ProductType": pick("ptype", []string{"Application", "Operating System", "Hardware", ""}),
			"Nversions":   optional(t, "nver", mInt),
			"Vendor":      pick("vendor", []string{"v1", "v2", "v3", ""}),
		})
	}
	for i, c := 0, n("nAffects", 12); i < c; i++ {
		add(baseline.LogicalAffectsAddProperty, map[string]string{
			"cveID":   pick("avCVE", genCVEs),
			"Product": pick("avProduct", products),
			"Version": pick("version", []string{"1.0.1", "1.0.2", "2.0", ""}),
		})
	}
	return ts
}

// writeTables writes every table as <dir>/<scriptName>.
func writeTables(dir string, ts mtables) error {
	for logical, name := range modelScriptNames {
		t := ts[logical]
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		w := csv.NewWriter(f)
		_ = w.Write(t.cols)
		for _, row := range t.rows {
			rec := make([]string, len(t.cols))
			for i, c := range t.cols {
				rec[i] = row[c]
			}
			_ = w.Write(rec)
		}
		w.Flush()
		if err := w.Error(); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

// genManifest builds a manifest for the files in dir with real checksums.
func genManifest(dir string) (*baseline.Manifest, error) {
	m := &baseline.Manifest{
		Upstream: baseline.Upstream{Repo: "https://example.test/VulKG", Commit: strings.Repeat("cd", 20), CopiedOn: "2024-01-02"},
		Bucket:   baseline.BucketRef{Name: "gen-bucket", Prefix: "vulkg/g/"},
	}
	for _, logical := range baseline.RequiredLogicalFiles {
		script := modelScriptNames[logical]
		data, err := os.ReadFile(filepath.Join(dir, script))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		repo := "import/" + script
		if logical == baseline.LogicalHasExploit || logical == baseline.LogicalDomainRelationship {
			repo = "import/" + strings.Replace(script, "Vulnerability_", "Vulnerabiliy_", 1)
		}
		m.Files = append(m.Files, baseline.ManifestFile{
			Logical: logical, RepoName: repo, ScriptName: script, Key: "vulkg/g/" + script,
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)),
		})
	}
	return m, m.Validate()
}

// ---- tests that run without Docker ----------------------------------------

// Feature: bellu-security-knowledge-graph, Property 23: Loader matches the reference model
// (fixture cross-check: the model must reproduce the README expected counts).
func TestModelReproducesFixtureReadmeCounts(t *testing.T) {
	ts, err := readModelTables("../../testdata/baseline")
	if err != nil {
		t.Fatal(err)
	}
	g := newMGraph()
	cn, err := g.applyLoad(ts)
	if err != nil {
		t.Fatal(err)
	}
	for label, want := range map[string]int64{
		"Vulnerability": 40, "Exploit": 15, "Author": 10, "Weakness": 12, "Domain": 9, "Product": 14, "Vendor": 13,
	} {
		if got := g.countNodes(label); got != want {
			t.Errorf("%s: got %d want %d", label, got, want)
		}
	}
	for typ, want := range map[string]int64{
		"WRITES": 15, "EXPLOITS": 13, "EXAMPLE_OF": 26, "REFERS_TO": 37, "AFFECTS": 37, "BELONGS_TO": 15,
	} {
		if got := g.countRels(typ); got != want {
			t.Errorf("%s: got %d want %d", typ, got, want)
		}
	}
	// Counts before step 13.
	for k, want := range map[string]int64{"Vulnerability": 43, "EXPLOITS": 14, "EXAMPLE_OF": 28, "REFERS_TO": 39, "AFFECTS": 40} {
		if cn.preReject[k] != want {
			t.Errorf("before step 13, %s: got %d want %d", k, cn.preReject[k], want)
		}
	}
	if cn.bare != 3 || cn.rejectNodes != 3 {
		t.Errorf("bare=%d rejected=%d, want 3 and 3", cn.bare, cn.rejectNodes)
	}
	for step, want := range map[string]int64{
		baseline.StepExploitsRel: 3, baseline.StepExampleOf: 6, baseline.StepDomainRefers: 2,
		baseline.StepProductAffects: 2, baseline.StepVendorBelongs: 0, baseline.StepAffectedVer: 2,
	} {
		if cn.missing[step] != want {
			t.Errorf("missing %s: got %d want %d", step, cn.missing[step], want)
		}
	}
	var expl1, expl0, nonEmpty, empty int
	for k, p := range g.nodes {
		if strings.HasPrefix(k, "Vulnerability"+sep) {
			switch p["exploitability"] {
			case "i:1":
				expl1++
			case "i:0":
				expl0++
			}
		}
	}
	for _, r := range g.rels {
		if r.typ == "AFFECTS" {
			if r.props["affectedVersion"] == "l:[]" {
				empty++
			} else {
				nonEmpty++
			}
		}
	}
	if expl1 != 12 || expl0 != 28 {
		t.Errorf("exploitability 1/0 = %d/%d, want 12/28", expl1, expl0)
	}
	if nonEmpty != 28 || empty != 9 {
		t.Errorf("affectedVersion non-empty/empty = %d/%d, want 28/9", nonEmpty, empty)
	}
	prodType := map[string]string{
		"openssl": "Application", "http_server": "Application", "chrome": "Application", "firefox": "Application",
		"flash_player": "Application", "jenkins": "Application", "mysql": "Application", "tomcat": "Application",
		"wordpress": "Application", "nginx": "Application", "orphan_product": "Application",
		"linux_kernel": "Operating System", "windows_10": "Operating System", "big-ip": "Hardware",
	}
	for p, want := range prodType {
		if got := g.nodes[nkey("Product", p)]["productType"]; got != "s:"+want {
			t.Errorf("productType(%s) = %q, want %q", p, got, want)
		}
	}
	for _, c := range []struct{ cve, prod, n string }{
		{"CVE-2019-1001", "openssl", "i:3"}, {"CVE-2019-1002", "openssl", "i:2"},
		{"CVE-2019-1002", "linux_kernel", "i:3"}, {"CVE-2018-9002", "nginx", "i:1"},
	} {
		r := g.rels[strings.Join([]string{"AFFECTS", "Vulnerability", c.cve, "Product", c.prod}, sep)]
		if r == nil || r.props["numOfVersion"] != c.n {
			t.Errorf("AFFECTS(%s,%s) numOfVersion: %+v want %s", c.cve, c.prod, r, c.n)
		}
	}
	for cve, want := range map[string]string{
		"CVE-2019-1002": canonList([]string{"2019-02-11", "2019-09-20"}),
		"CVE-2019-1022": canonList([]string{"2019-05-14"}),
		"CVE-2019-1023": canonList([]string{"2019-05-14"}),
		"CVE-2019-1004": canonList(nil),
	} {
		if got := g.nodes[nkey("Vulnerability", cve)]["exploitDate"]; got != want {
			t.Errorf("exploitDate(%s) = %q, want %q", cve, got, want)
		}
	}
	// Edge cases from the README: first duplicate row wins; bare nodes carry only their key.
	if p := g.nodes[nkey("Vulnerability", "CVE-2019-1005")]; p["numOfReference"] != "i:6" {
		t.Errorf("CVE-2019-1005 numOfReference = %q, want i:6", p["numOfReference"])
	}
	if p := g.nodes[nkey("Vulnerability", "CVE-2018-9001")]; len(p) != 2 {
		t.Errorf("bare node props = %v, want only exploitability and exploitDate", p)
	}
	if p := g.nodes[nkey("Vulnerability", "CVE-2019-1008")]; p["gainedAccess"] != "s:Gain Privileges" || p["vulnerabilityType"] != canonList([]string{"Bypass"}) {
		t.Errorf("CVE-2019-1008 last row should win: %v", p)
	}
}

// Feature: bellu-security-knowledge-graph, Property 24: Loader idempotence and resumability
// (model level: a second load of a graph without bare nodes changes nothing).
func TestModelReloadIsIdempotentWithoutBareNodes(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		ts := genTables(rt, false)
		g1 := newMGraph()
		if _, err := g1.applyLoad(ts); err != nil {
			rt.Fatal(err)
		}
		g2 := g1.clone()
		if _, err := g2.applyLoad(ts); err != nil {
			rt.Fatal(err)
		}
		if d := diffGraphs(g1, g2); d != "" {
			rt.Fatalf("second load changed the graph:\n%s", d)
		}
	})
}

// The generated CSV files and manifest must pass the real fetch verification and
// parse back to the same tables, so the container-backed properties start from
// valid input.
func TestGeneratedFilesAreVerifiedAndReadable(t *testing.T) {
	dir := t.TempDir()
	rapid.Check(t, func(rt *rapid.T) {
		ts := genTables(rt, true)
		if err := writeTables(dir, ts); err != nil {
			rt.Fatal(err)
		}
		m, err := genManifest(dir)
		if err != nil {
			rt.Fatal(err)
		}
		files, err := (&baseline.Fetcher{LocalDir: dir}).Fetch(context.Background(), m)
		if err != nil {
			rt.Fatal(err)
		}
		back, err := readModelTables(dir)
		if err != nil {
			rt.Fatal(err)
		}
		for logical, tab := range ts {
			n, err := baseline.CountRows(files[logical])
			if err != nil || int(n) != len(tab.rows) || len(back[logical].rows) != len(tab.rows) {
				rt.Fatalf("%s: rows %d (err %v), read back %d, generated %d", logical, n, err, len(back[logical].rows), len(tab.rows))
			}
			for i, row := range tab.rows {
				for _, c := range tab.cols {
					if back[logical].rows[i][c] != row[c] {
						rt.Fatalf("%s row %d column %s: %q != %q", logical, i, c, back[logical].rows[i][c], row[c])
					}
				}
			}
		}
		// The model accepts every generated table.
		if _, err := newMGraph().applyLoad(ts); err != nil {
			rt.Fatal(err)
		}
	})
}
