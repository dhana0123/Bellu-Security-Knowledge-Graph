package nvd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/resolve"
	"github.com/bellu/bskg/internal/source"
)

type cveRecord struct {
	ID           string `json:"id"`
	VulnStatus   string `json:"vulnStatus"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V31 []metric `json:"cvssMetricV31"`
		V30 []metric `json:"cvssMetricV30"`
		V2  []metric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []cpeMatch `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References *[]struct {
		URL string `json:"url"`
	} `json:"references"`
}

type metric struct {
	Type                    string   `json:"type"`
	BaseSeverity            string   `json:"baseSeverity"`
	ExploitabilityScore     *float64 `json:"exploitabilityScore"`
	ImpactScore             *float64 `json:"impactScore"`
	ACInsufInfo             *bool    `json:"acInsufInfo"`
	ObtainAllPrivilege      *bool    `json:"obtainAllPrivilege"`
	ObtainUserPrivilege     *bool    `json:"obtainUserPrivilege"`
	ObtainOtherPrivilege    *bool    `json:"obtainOtherPrivilege"`
	UserInteractionRequired *bool    `json:"userInteractionRequired"`
	Data                    struct {
		Version               string   `json:"version"`
		VectorString          string   `json:"vectorString"`
		BaseScore             *float64 `json:"baseScore"`
		BaseSeverity          string   `json:"baseSeverity"`
		AccessVector          string   `json:"accessVector"`
		AccessComplexity      string   `json:"accessComplexity"`
		Authentication        string   `json:"authentication"`
		AttackVector          string   `json:"attackVector"`
		AttackComplexity      string   `json:"attackComplexity"`
		PrivilegesRequired    string   `json:"privilegesRequired"`
		UserInteraction       string   `json:"userInteraction"`
		Scope                 string   `json:"scope"`
		ConfidentialityImpact string   `json:"confidentialityImpact"`
		IntegrityImpact       string   `json:"integrityImpact"`
		AvailabilityImpact    string   `json:"availabilityImpact"`
	} `json:"cvssData"`
}

type cpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// Normalize implements source.Adapter. It is pure. An empty payload (a cursor
// marker) yields an empty result.
func (a *Adapter) Normalize(rec source.Record) (source.Normalized, error) {
	if len(rec.Payload) == 0 {
		return source.Normalized{}, nil
	}
	var c cveRecord
	if err := json.Unmarshal(rec.Payload, &c); err != nil {
		return source.Normalized{}, fmt.Errorf("nvd: decode %s: %w", rec.ID, err)
	}
	_, err := resolve.CVE(c.ID)
	if err != nil {
		return source.Normalized{}, fmt.Errorf("nvd: %w", err)
	}
	vref := source.Ref{Kind: source.RefCVE, Raw: c.ID}
	props := map[string]any{}
	var clear []string
	var n source.Normalized

	if d, ok := parseDate(c.Published); ok {
		props["publishedDate"] = d
	} else {
		n.Missing = true
	}
	if d, ok := parseDate(c.LastModified); ok {
		props["lastModifiedDate"] = d
	} else {
		n.Missing = true
	}
	desc := false
	for _, d := range c.Descriptions {
		if strings.EqualFold(d.Lang, "en") && d.Value != "" {
			props["description"] = d.Value
			desc = true
			break
		}
	}
	if !desc {
		n.Missing = true
	}
	if c.References != nil {
		props["numOfReference"] = int64(len(*c.References))
	} else {
		n.Missing = true
	}
	rejected := c.VulnStatus == "Rejected"
	if rejected {
		props["rejected"] = true
	} else {
		clear = append(clear, "rejected")
	}

	v3 := c.Metrics.V31
	if len(v3) == 0 {
		v3 = c.Metrics.V30
	}
	m2, ok2 := pickMetric(c.Metrics.V2)
	m3, ok3 := pickMetric(v3)
	if ok2 {
		setV2(props, m2)
	}
	if ok3 {
		setV3(props, m3)
	}
	// Rejected records carry no scores by design, so they are not counted.
	if !ok2 && !ok3 && !rejected {
		n.Missing = true
	}

	n.Entities = append(n.Entities, source.Entity{Ref: vref, Props: props, Clear: clear})
	n.Anchor = &source.Ref{Kind: source.RefCVE, Raw: c.ID}
	n.Owned = []source.OwnedRel{{Type: "EXAMPLE_OF"}, {Type: "REFERS_TO"}, {Type: "REFERS_TO_REPOSITORY"}, {Type: "AFFECTS"}}

	// Weaknesses: never created here. NVD-CWE-* values are unresolved.
	seenCWE := map[string]bool{}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			v := strings.TrimSpace(d.Value)
			if v == "" || seenCWE[v] {
				continue
			}
			seenCWE[v] = true
			n.Rels = append(n.Rels, source.Rel{
				From: vref, Type: "EXAMPLE_OF",
				To: source.Ref{Kind: source.RefCWE, Raw: v, MustExist: true},
			})
		}
	}

	// Reference hosts.
	seenHost := map[string]bool{}
	if c.References != nil {
		for _, r := range *c.References {
			k, err := resolve.Domain(r.URL)
			if err != nil {
				n.Notes = append(n.Notes, source.Note{Kind: "warning", ID: c.ID, Text: "reference URL without a host: " + r.URL})
				continue
			}
			if seenHost[k.Value] {
				continue
			}
			seenHost[k.Value] = true
			d := source.Ref{Kind: source.RefDomain, Raw: k.Value}
			n.Entities = append(n.Entities, source.Entity{Ref: d, Props: map[string]any{}})
			n.Rels = append(n.Rels, source.Rel{From: vref, Type: "REFERS_TO", To: d})
		}
	}

	if c.References != nil {
		urls := make([]string, 0, len(*c.References))
		for _, r := range *c.References {
			urls = append(urls, r.URL)
		}
		gitLinks(c.ID, vref, urls, &n)
	}
	n.Entities, n.Rels, n.Notes = appendAffects(c, vref, n.Entities, n.Rels, n.Notes)
	return n, nil
}

// appendAffects maps vulnerable cpeMatch entries to Product, Vendor, AFFECTS,
// and BELONGS_TO. AFFECTS carries the distinct versions per Product.
func appendAffects(c cveRecord, vref source.Ref, ents []source.Entity, rels []source.Rel, notes []source.Note) ([]source.Entity, []source.Rel, []source.Note) {
	type prod struct {
		ref      source.Ref
		versions []string
		seen     map[string]bool
	}
	var order []string
	prods := map[string]*prod{}
	seenVendor := map[string]bool{}
	seenBelongs := map[string]bool{}
	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				keys, err := resolve.CPE(m.Criteria)
				if err != nil {
					notes = append(notes, source.Note{Kind: "warning", ID: c.ID, Text: err.Error()})
					continue
				}
				pk := keys.Product.Value
				p := prods[pk]
				if p == nil {
					p = &prod{ref: source.Ref{Kind: source.RefCPE, Raw: m.Criteria}, seen: map[string]bool{}}
					prods[pk] = p
					order = append(order, pk)
					ents = append(ents, source.Entity{Ref: p.ref, Props: map[string]any{}})
				}
				if v := versionOf(m); !p.seen[v] {
					p.seen[v] = true
					p.versions = append(p.versions, v)
				}
				vend := source.Ref{Kind: source.RefCPEVend, Raw: m.Criteria}
				if vk := keys.Vendor.Value; !seenVendor[vk] {
					seenVendor[vk] = true
					ents = append(ents, source.Entity{Ref: vend, Props: map[string]any{}})
				}
				if bk := pk + "\x00" + keys.Vendor.Value; !seenBelongs[bk] {
					seenBelongs[bk] = true
					rels = append(rels, source.Rel{From: p.ref, To: vend, Type: "BELONGS_TO"})
				}
			}
		}
	}
	for _, pk := range order {
		p := prods[pk]
		rels = append(rels, source.Rel{From: vref, To: p.ref, Type: "AFFECTS", Props: map[string]any{
			"affectedVersion": p.versions,
			"numOfVersion":    int64(len(p.versions)),
		}})
	}
	return ents, rels, notes
}

// versionOf returns the affectedVersion entry of one cpeMatch: a range string
// such as "[1.0,2.0)" when a bound is present (a missing bound is left empty,
// as in "(,2.0)"), otherwise the CPE version field, which is "*" for an
// unbounded wildcard.
func versionOf(m cpeMatch) string {
	if m.VersionStartIncluding != "" || m.VersionStartExcluding != "" || m.VersionEndIncluding != "" || m.VersionEndExcluding != "" {
		var b strings.Builder
		switch {
		case m.VersionStartIncluding != "":
			b.WriteString("[" + m.VersionStartIncluding)
		case m.VersionStartExcluding != "":
			b.WriteString("(" + m.VersionStartExcluding)
		default:
			b.WriteString("(")
		}
		b.WriteString(",")
		switch {
		case m.VersionEndIncluding != "":
			b.WriteString(m.VersionEndIncluding + "]")
		case m.VersionEndExcluding != "":
			b.WriteString(m.VersionEndExcluding + ")")
		default:
			b.WriteString(")")
		}
		return b.String()
	}
	f := splitCPE(strings.TrimSpace(m.Criteria))
	if len(f) > 5 && f[5] != "" {
		return unescape(f[5])
	}
	return "*"
}

func splitCPE(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case ':':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// pickMetric returns the Primary entry, else the first.
func pickMetric(ms []metric) (metric, bool) {
	for _, m := range ms {
		if m.Type == "Primary" {
			return m, true
		}
	}
	if len(ms) > 0 {
		return ms[0], true
	}
	return metric{}, false
}

func setStr(p map[string]any, k, v string) {
	if v != "" {
		p[k] = v
	}
}

func setF(p map[string]any, k string, v *float64) {
	if v != nil {
		p[k] = *v
	}
}

func setB(p map[string]any, k string, v *bool) {
	if v != nil {
		p[k] = *v
	}
}

func setV2(p map[string]any, m metric) {
	d := m.Data
	if f, ok := parseVersion(d.Version); ok {
		p["v2version"] = int64(f)
	}
	setF(p, "v2baseScore", d.BaseScore)
	setF(p, "v2impactScore", m.ImpactScore)
	setF(p, "v2exploitabilityScore", m.ExploitabilityScore)
	setStr(p, "v2accessVector", d.AccessVector)
	setStr(p, "v2accessComplexity", d.AccessComplexity)
	setStr(p, "v2authentication", d.Authentication)
	setStr(p, "v2confidentialityImpact", d.ConfidentialityImpact)
	setStr(p, "v2integrityImpact", d.IntegrityImpact)
	setStr(p, "v2availabilityImpact", d.AvailabilityImpact)
	setStr(p, "v2vectorString", d.VectorString)
	setStr(p, "v2severity", m.BaseSeverity)
	setB(p, "v2userInteractionRequired", m.UserInteractionRequired)
	setB(p, "v2obtainUserPrivilege", m.ObtainUserPrivilege)
	setB(p, "v2obtainAllPrivilege", m.ObtainAllPrivilege)
	setB(p, "v2acInsufInfo", m.ACInsufInfo)
	setB(p, "v2obtainOtherPrivilege", m.ObtainOtherPrivilege)
}

func setV3(p map[string]any, m metric) {
	d := m.Data
	if f, ok := parseVersion(d.Version); ok {
		p["v3version"] = f
	}
	setF(p, "v3baseScore", d.BaseScore)
	setF(p, "v3impactScore", m.ImpactScore)
	setF(p, "v3exploitabilityScore", m.ExploitabilityScore)
	setStr(p, "v3attackVector", d.AttackVector)
	setStr(p, "v3attackComplexity", d.AttackComplexity)
	setStr(p, "v3privilegesRequired", d.PrivilegesRequired)
	setStr(p, "v3userInteraction", d.UserInteraction)
	setStr(p, "v3scope", d.Scope)
	setStr(p, "v3confidentialityImpact", d.ConfidentialityImpact)
	setStr(p, "v3integrityImpact", d.IntegrityImpact)
	setStr(p, "v3availabilityImpact", d.AvailabilityImpact)
	setStr(p, "v3vectorString", d.VectorString)
	setStr(p, "v3baseSeverity", d.BaseSeverity)
}

func parseVersion(s string) (float64, bool) {
	var f float64
	if _, err := fmt.Sscanf(s, "%g", &f); err != nil {
		return 0, false
	}
	return f, true
}

// parseDate reads an NVD timestamp (UTC, usually without a zone) and returns
// its UTC date.
func parseDate(s string) (neo4j.Date, bool) {
	for _, layout := range []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			return neo4j.DateOf(t.UTC()), true
		}
	}
	return neo4j.Date{}, false
}
