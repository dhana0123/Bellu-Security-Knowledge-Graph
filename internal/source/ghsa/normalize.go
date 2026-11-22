package ghsa

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bellu/bskg/internal/resolve"
	"github.com/bellu/bskg/internal/source"
	"github.com/bellu/bskg/internal/source/gitref"
)

// SummaryMax is the longest ghsaSummary in characters.
const SummaryMax = 2000

// maxRanges is the most affectedRanges entries on one AFFECTS_PACKAGE.
const maxRanges = 100

type score struct {
	Vector *string  `json:"vector_string"`
	Score  *float64 `json:"score"`
}

type advisory struct {
	GHSAID      string  `json:"ghsa_id"`
	CVEID       *string `json:"cve_id"`
	Summary     string  `json:"summary"`
	Severity    string  `json:"severity"`
	Identifiers []struct {
		Value string `json:"value"`
		Type  string `json:"type"`
	} `json:"identifiers"`
	References         []string `json:"references"`
	SourceCodeLocation string   `json:"source_code_location"`
	PublishedAt        string   `json:"published_at"`
	UpdatedAt          string   `json:"updated_at"`
	WithdrawnAt        *string  `json:"withdrawn_at"`
	Vulnerabilities    []struct {
		Package *struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string          `json:"vulnerable_version_range"`
		FirstPatchedVersion    json.RawMessage `json:"first_patched_version"`
	} `json:"vulnerabilities"`
	CVSSSeverities struct {
		V3 *score `json:"cvss_v3"`
		V4 *score `json:"cvss_v4"`
	} `json:"cvss_severities"`
	CVSS *score `json:"cvss"`
	CWEs []struct {
		ID string `json:"cwe_id"`
	} `json:"cwes"`
}

// ecosystems maps the GHSA ecosystem names to the OSV names that
// resolve.PurlFromOSV accepts.
var ecosystems = map[string]string{
	"npm":      "npm",
	"pip":      "PyPI",
	"maven":    "Maven",
	"nuget":    "NuGet",
	"go":       "Go",
	"rubygems": "RubyGems",
	"rust":     "crates.io",
	"composer": "Packagist",
	"erlang":   "Hex",
	"actions":  "GitHub Actions",
	"pub":      "Pub",
	"swift":    "SwiftURL",
}

type pkgAcc struct {
	purl, eco, name string
	ranges          []string
	fixed           []string
}

// Normalize implements source.Adapter. It is pure. An empty payload (a cursor
// marker) yields an empty result. A record without ghsa_id or updated_at is
// skipped: the result is empty, Missing is set and one warning is returned.
func (a *Adapter) Normalize(rec source.Record) (source.Normalized, error) {
	if len(rec.Payload) == 0 {
		return source.Normalized{}, nil
	}
	var g advisory
	if err := json.Unmarshal(rec.Payload, &g); err != nil {
		return source.Normalized{}, fmt.Errorf("ghsa: decode %s: %w", rec.ID, err)
	}
	id := strings.TrimSpace(g.GHSAID)
	updated, uerr := time.Parse(time.RFC3339, g.UpdatedAt)
	if id == "" || uerr != nil {
		return source.Normalized{Missing: true, Notes: []source.Note{{
			Kind: "warning", ID: rec.ID, Text: "skipped advisory without ghsa_id or updated_at",
		}}}, nil
	}
	if _, err := resolve.Advisory(id); err != nil {
		return source.Normalized{}, fmt.Errorf("ghsa: %w", err)
	}
	vref := source.Ref{Kind: source.RefAdvisory, Raw: id}
	var n source.Normalized

	props := map[string]any{"ghsaUpdated": updated.UTC()}
	var clear []string
	if s := strings.TrimSpace(g.Summary); s != "" {
		props["ghsaSummary"] = cut(s, SummaryMax)
	} else {
		n.Missing = true
	}
	if s := strings.ToLower(strings.TrimSpace(g.Severity)); s != "" {
		props["ghsaSeverity"] = s
	}
	if sc := pickScore(g); sc != nil {
		if sc.Score != nil {
			props["ghsaCvssScore"] = *sc.Score
		}
		if sc.Vector != nil && *sc.Vector != "" {
			props["ghsaCvssVector"] = *sc.Vector
		}
	}
	if p, err := time.Parse(time.RFC3339, g.PublishedAt); err == nil {
		props["ghsaPublished"] = p.UTC()
	} else {
		n.Missing = true
	}
	if g.WithdrawnAt != nil && *g.WithdrawnAt != "" {
		if w, err := time.Parse(time.RFC3339, *g.WithdrawnAt); err == nil {
			props["ghsaWithdrawn"] = w.UTC()
		} else {
			n.Notes = append(n.Notes, source.Note{Kind: "warning", ID: id, Text: "unreadable withdrawn_at"})
		}
	}
	if _, ok := props["ghsaWithdrawn"]; !ok {
		clear = append(clear, "ghsaWithdrawn")
	}
	n.Entities = append(n.Entities, source.Entity{Ref: vref, Props: props, Clear: clear})
	n.Anchor = &source.Ref{Kind: source.RefAdvisory, Raw: id}
	n.Owned = []source.OwnedRel{{Type: "AFFECTS_PACKAGE"}, {Type: "REFERS_TO_REPOSITORY"}}

	n.Advisory = aliases(g, id, &n)

	// Weaknesses: never created here.
	seenCWE := map[string]bool{}
	for _, w := range g.CWEs {
		k, err := resolve.CWE(w.ID)
		if err != nil {
			n.Notes = append(n.Notes, source.Note{Kind: "warning", ID: id, Text: "unusable cwe_id " + fmt.Sprintf("%q", w.ID)})
			continue
		}
		if seenCWE[k.Value] {
			continue
		}
		seenCWE[k.Value] = true
		n.Rels = append(n.Rels, source.Rel{
			From: vref, Type: "EXAMPLE_OF",
			To: source.Ref{Kind: source.RefCWE, Raw: k.Value, MustExist: true},
		})
	}

	// Repository of the advisory and git references.
	loc := strings.TrimSpace(g.SourceCodeLocation)
	var repoURL string
	urls := make([]string, 0, len(g.References)+1)
	if loc != "" {
		if l, ok := gitref.Parse(loc); ok {
			repoURL = l.Repo
			urls = append(urls, loc)
		} else {
			n.Notes = append(n.Notes, source.Note{Kind: "warning", ID: id, Text: "unusable source_code_location " + fmt.Sprintf("%q", loc)})
		}
	}
	urls = append(urls, g.References...)
	gitref.Append(id, vref, urls, &n)

	// Packages.
	for _, p := range packages(g, id, &n) {
		pref := source.Ref{Kind: source.RefPackage, Raw: p.purl}
		n.Entities = append(n.Entities, source.Entity{Ref: pref, Props: map[string]any{"ecosystem": p.eco, "name": p.name}})
		rp := map[string]any{}
		if len(p.ranges) > 0 {
			rp["affectedRanges"] = p.ranges
		}
		if len(p.fixed) > 0 {
			rp["fixed"] = strings.Join(p.fixed, ", ")
		}
		if len(p.ranges) == 1 {
			intro, last := derive(p.ranges[0])
			if intro != "" {
				rp["introduced"] = intro
			}
			if last != "" {
				rp["lastAffected"] = last
			}
		}
		n.Rels = append(n.Rels, source.Rel{From: vref, To: pref, Type: "AFFECTS_PACKAGE", Props: rp})
		if repoURL != "" {
			n.Rels = append(n.Rels, source.Rel{From: pref, To: source.Ref{Kind: source.RefRepository, Raw: repoURL}, Type: "HOSTED_IN"})
		}
	}
	return n, nil
}

// aliases builds the Advisory of the record: CVE ids (cve_id and identifiers
// of type CVE) and every other identifier except the advisory id itself.
func aliases(g advisory, id string, n *source.Normalized) *source.Advisory {
	adv := &source.Advisory{ID: id}
	seen := map[string]bool{strings.ToUpper(id): true}
	addCVE := func(v string) {
		v = strings.ToUpper(strings.TrimSpace(v))
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		if _, err := resolve.CVE(v); err != nil {
			n.Notes = append(n.Notes, source.Note{Kind: "warning", ID: id, Text: "invalid CVE identifier " + fmt.Sprintf("%q", v)})
			return
		}
		adv.CVEs = append(adv.CVEs, v)
	}
	if g.CVEID != nil {
		addCVE(*g.CVEID)
	}
	for _, i := range g.Identifiers {
		if strings.EqualFold(i.Type, "CVE") {
			addCVE(i.Value)
		}
	}
	for _, i := range g.Identifiers {
		v := strings.TrimSpace(i.Value)
		if v == "" || strings.EqualFold(i.Type, "CVE") || seen[strings.ToUpper(v)] {
			continue
		}
		seen[strings.ToUpper(v)] = true
		adv.OtherAliases = append(adv.OtherAliases, v)
	}
	return adv
}

// pickScore prefers CVSS v3, then v4, then the legacy cvss object. A score
// without a vector and with value 0 is GitHub's placeholder for "none".
func pickScore(g advisory) *score {
	for _, s := range []*score{g.CVSSSeverities.V3, g.CVSSSeverities.V4, g.CVSS} {
		if s != nil && s.Vector != nil && *s.Vector != "" {
			return s
		}
	}
	return nil
}

// packages groups the vulnerabilities[] entries by package, in order.
func packages(g advisory, id string, n *source.Normalized) []*pkgAcc {
	var out []*pkgAcc
	idx := map[string]*pkgAcc{}
	for _, v := range g.Vulnerabilities {
		if v.Package == nil || strings.TrimSpace(v.Package.Name) == "" {
			continue
		}
		osv, ok := ecosystems[strings.ToLower(strings.TrimSpace(v.Package.Ecosystem))]
		if !ok {
			n.Notes = append(n.Notes, source.Note{Kind: "warning", ID: id,
				Text: fmt.Sprintf("unsupported ecosystem %q (package %q)", v.Package.Ecosystem, v.Package.Name)})
			continue
		}
		purl, err := resolve.PurlFromOSV(osv, v.Package.Name)
		if err != nil {
			n.Notes = append(n.Notes, source.Note{Kind: "warning", ID: id, Text: err.Error()})
			continue
		}
		p := idx[purl]
		if p == nil {
			p = &pkgAcc{purl: purl, eco: osv, name: strings.TrimSpace(v.Package.Name)}
			idx[purl] = p
			out = append(out, p)
		}
		if r := strings.TrimSpace(v.VulnerableVersionRange); r != "" && len(p.ranges) < maxRanges && !contains(p.ranges, r) {
			p.ranges = append(p.ranges, r)
		}
		if f := patched(v.FirstPatchedVersion); f != "" && !contains(p.fixed, f) {
			p.fixed = append(p.fixed, f)
		}
	}
	return out
}

// patched reads first_patched_version: a string, or an object with an
// identifier field in some API versions.
func patched(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var o struct {
		Identifier string `json:"identifier"`
	}
	if json.Unmarshal(raw, &o) == nil {
		return strings.TrimSpace(o.Identifier)
	}
	return ""
}

// derive reads introduced and lastAffected from one range such as
// ">= 1.0, < 2.0" or "<= 0.19.0" or "= 1.2.3". Anything else yields "".
func derive(r string) (introduced, lastAffected string) {
	for _, c := range strings.Split(r, ",") {
		c = strings.TrimSpace(c)
		switch {
		case strings.HasPrefix(c, ">="):
			introduced = strings.TrimSpace(c[2:])
		case strings.HasPrefix(c, "<="):
			lastAffected = strings.TrimSpace(c[2:])
		case strings.HasPrefix(c, "="):
			v := strings.TrimSpace(c[1:])
			introduced, lastAffected = v, v
		}
	}
	return
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// cut shortens s to at most n characters on a character boundary.
func cut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
