package osv

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/resolve"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source/gitref"
)

const (
	maxSummary    = 2000
	maxProp       = 256
	maxRanges     = 100
	maxPropString = 1024
)

type osvRecord struct {
	osvHeaderFields
	Published        string          `json:"published"`
	Withdrawn        string          `json:"withdrawn"`
	Summary          string          `json:"summary"`
	Aliases          []string        `json:"aliases"`
	Upstream         []string        `json:"upstream"`
	Severity         []osvSeverity   `json:"severity"`
	Affected         []osvAffected   `json:"affected"`
	References       []osvReference  `json:"references"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
	Failure          string          `json:"osvFailure"`
	Ecosystem        string          `json:"ecosystem"`
}

type osvHeaderFields struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Repo   string     `json:"repo"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

// pkgAcc collects what one package gets from all affected[] entries of the
// record: AFFECTS_PACKAGE is one relationship per vulnerability and package.
type pkgAcc struct {
	ref                        source.Ref
	introduced, fixed, lastAff string
	ranges                     []string
	seenRange                  map[string]bool
	truncated                  bool
}

// Normalize implements source.Adapter. It is pure. An empty payload (a cursor
// marker) yields an empty result.
func (a *Adapter) Normalize(rec source.Record) (source.Normalized, error) {
	if len(rec.Payload) == 0 {
		return source.Normalized{}, nil
	}
	var r osvRecord
	if err := json.Unmarshal(rec.Payload, &r); err != nil {
		return source.Normalized{}, fmt.Errorf("osv: decode %s: %w", rec.ID, err)
	}
	if r.Failure != "" {
		return source.Normalized{}, fmt.Errorf("osv: ecosystem %q aborted, mark and data kept: %s", r.Ecosystem, r.Failure)
	}
	id := strings.TrimSpace(r.ID)
	modified, mok := parseTime(r.Modified)
	if id == "" || !mok {
		// Requirement 14.8: skipped and counted.
		what := "id"
		if id != "" {
			what = "modified time"
		}
		return source.Normalized{Missing: true, Notes: []source.Note{{
			Kind: "warning", ID: rec.ID, Text: "record skipped: it has no valid " + what,
		}}}, nil
	}

	var n source.Normalized
	vref := source.Ref{Kind: source.RefAdvisory, Raw: id}
	if _, err := resolve.Advisory(id); err != nil {
		if k, cerr := resolve.CVE(id); cerr == nil {
			// An OSV record whose own id is a CVE id (converted NVD data).
			vref = source.Ref{Kind: source.RefCVE, Raw: k.Value}
		} else {
			return source.Normalized{}, fmt.Errorf("osv: %s: %w", id, err)
		}
	}
	if vref.Kind == source.RefAdvisory {
		n.Advisory = aliases(id, r.Aliases, r.Upstream)
	}

	props := map[string]any{"osvModified": modified}
	var clear []string
	if t, ok := parseTime(r.Published); ok {
		props["osvPublished"] = t
	} else {
		clear = append(clear, "osvPublished")
	}
	if t, ok := parseTime(r.Withdrawn); ok {
		props["osvWithdrawn"] = t
	} else {
		clear = append(clear, "osvWithdrawn")
	}
	if s := strings.TrimSpace(r.Summary); s != "" {
		props["osvSummary"] = truncateRunes(s, maxSummary)
	} else {
		clear = append(clear, "osvSummary")
		n.Missing = true
	}
	if v := firstCVSS(r.Severity); v != "" {
		props["osvSeverity"] = truncateRunes(v, maxPropString)
	} else {
		clear = append(clear, "osvSeverity")
	}
	n.Entities = append(n.Entities, source.Entity{Ref: vref, Props: props, Clear: clear})
	n.Anchor = &source.Ref{Kind: vref.Kind, Raw: vref.Raw}
	n.Owned = []source.OwnedRel{{Type: "AFFECTS_PACKAGE"}, {Type: "REFERS_TO_REPOSITORY"}}

	b := &builder{n: &n, id: id, vref: vref, ents: map[string]int{}, rels: map[string]bool{}}
	var pkgs []*pkgAcc
	byPurl := map[string]*pkgAcc{}
	for _, af := range r.Affected {
		var acc *pkgAcc
		eco, name := strings.TrimSpace(af.Package.Ecosystem), strings.TrimSpace(af.Package.Name)
		if eco != "" && name != "" {
			base, _, _ := strings.Cut(eco, ":")
			purl, err := resolve.PurlFromOSV(base, name)
			if err != nil {
				b.note("warning", fmt.Sprintf("package skipped: %v", err))
			} else if acc = byPurl[purl]; acc == nil {
				acc = &pkgAcc{ref: source.Ref{Kind: source.RefPackage, Raw: purl}, seenRange: map[string]bool{}}
				byPurl[purl] = acc
				pkgs = append(pkgs, acc)
				b.entity(acc.ref, map[string]any{
					"ecosystem": truncateRunes(base, maxProp),
					"name":      truncateRunes(name, maxProp),
				})
			}
		}
		for _, rg := range af.Ranges {
			switch strings.ToUpper(rg.Type) {
			case "ECOSYSTEM", "SEMVER":
				if acc != nil {
					acc.addRange(rg)
				}
			case "GIT":
				b.gitRange(rg, acc)
			}
		}
	}
	for _, acc := range pkgs {
		props := map[string]any{"affectedRanges": acc.ranges}
		if acc.ranges == nil {
			props["affectedRanges"] = []string{}
		}
		if acc.introduced != "" {
			props["introduced"] = truncateRunes(acc.introduced, maxProp)
		}
		if acc.fixed != "" {
			props["fixed"] = truncateRunes(acc.fixed, maxProp)
		}
		if acc.lastAff != "" {
			props["lastAffected"] = truncateRunes(acc.lastAff, maxProp)
		}
		if acc.truncated {
			b.note("warning", fmt.Sprintf("more than %d affected ranges for %s; extra ranges dropped", maxRanges, acc.ref.Raw))
		}
		b.rel(vref, acc.ref, "AFFECTS_PACKAGE", props)
	}

	// Reference URLs: gitref makes the Repository, FixCommit and the three git
	// relationships; entries the GIT ranges already made are not repeated.
	var urls []string
	for _, rf := range r.References {
		if u := strings.TrimSpace(rf.URL); u != "" {
			urls = append(urls, u)
		}
	}
	var ref source.Normalized
	gitref.Append(id, vref, urls, &ref)
	for _, e := range ref.Entities {
		b.entity(e.Ref, e.Props)
	}
	for _, rl := range ref.Rels {
		b.rel(rl.From, rl.To, rl.Type, rl.Props)
	}
	n.Notes = append(n.Notes, ref.Notes...)

	// Weakness links; the Weakness is never created here.
	for _, c := range cweIDs(r.DatabaseSpecific) {
		k, err := resolve.CWE(c)
		if err != nil {
			b.note("warning", fmt.Sprintf("weakness %q not linked: %v", truncateRunes(c, 40), err))
			continue
		}
		b.rel(vref, source.Ref{Kind: source.RefCWE, Raw: k.Value, MustExist: true}, "EXAMPLE_OF", nil)
	}
	return n, nil
}

// builder adds deduplicated entities and relationships to a Normalized.
type builder struct {
	n    *source.Normalized
	id   string
	vref source.Ref
	ents map[string]int // entity key -> index in n.Entities
	rels map[string]bool
}

func refKey(r source.Ref) string { return string(r.Kind) + "|" + r.Raw }

func (b *builder) note(kind, text string) {
	b.n.Notes = append(b.n.Notes, source.Note{Kind: kind, ID: b.id, Text: text})
}

// entity adds the entity, or adds the properties a repeat brings that the
// first one lacked.
func (b *builder) entity(r source.Ref, props map[string]any) {
	k := refKey(r)
	if i, ok := b.ents[k]; ok {
		have := b.n.Entities[i].Props
		for pk, pv := range props {
			if _, ok := have[pk]; !ok {
				have[pk] = pv
			}
		}
		return
	}
	cp := make(map[string]any, len(props))
	for pk, pv := range props {
		cp[pk] = pv
	}
	b.ents[k] = len(b.n.Entities)
	b.n.Entities = append(b.n.Entities, source.Entity{Ref: r, Props: cp})
}

func (b *builder) rel(from, to source.Ref, typ string, props map[string]any) {
	k := refKey(from) + "|" + typ + "|" + refKey(to)
	if b.rels[k] {
		return
	}
	b.rels[k] = true
	b.n.Rels = append(b.n.Rels, source.Rel{From: from, To: to, Type: typ, Props: props})
}

// gitRange maps a GIT range: the repository, the fixed commits, and the
// package that lives there. acc is nil when the affected entry has no usable
// package.
func (b *builder) gitRange(rg osvRange, acc *pkgAcc) {
	repo, err := resolve.NormalizeRepoURL(rg.Repo)
	if err != nil {
		b.note("warning", fmt.Sprintf("repository URL %q not normalized, nothing linked: %v", truncateRunes(rg.Repo, 200), err))
		return
	}
	rref := source.Ref{Kind: source.RefRepository, Raw: repo}
	host := strings.TrimPrefix(repo, "https://")
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	b.entity(rref, map[string]any{"host": host})
	b.rel(b.vref, rref, "REFERS_TO_REPOSITORY", nil)
	if acc != nil {
		b.rel(acc.ref, rref, "HOSTED_IN", nil)
	}
	for _, ev := range rg.Events {
		sha := strings.TrimSpace(ev.Fixed)
		if sha == "" {
			continue
		}
		key, err := resolve.FixCommitKey(repo, sha)
		if err != nil {
			b.note("warning", fmt.Sprintf("fix %q in %s is not a 40-digit hex commit id: no FixCommit", truncateRunes(sha, 80), repo))
			continue
		}
		fc := source.Ref{Kind: source.RefFixCommit, Raw: key}
		b.entity(fc, map[string]any{"repoUrl": repo, "sha": strings.ToLower(sha)})
		b.rel(rref, fc, "HAS_FIX_COMMIT", nil)
		b.rel(fc, b.vref, "FIXES", nil)
	}
}

// addRange records the intervals of an ECOSYSTEM or SEMVER range as strings
// such as "introduced=1.0,fixed=1.2" and keeps the first introduced, fixed
// and last_affected values.
func (p *pkgAcc) addRange(rg osvRange) {
	var cur []string
	flush := func() {
		if len(cur) == 0 {
			return
		}
		s := strings.Join(cur, ",")
		cur = nil
		if p.seenRange[s] {
			return
		}
		if len(p.ranges) >= maxRanges {
			p.truncated = true
			return
		}
		p.seenRange[s] = true
		p.ranges = append(p.ranges, s)
	}
	hasIntro := false
	for _, ev := range rg.Events {
		switch {
		case ev.Introduced != "":
			if hasIntro || len(cur) > 0 {
				flush()
			}
			cur, hasIntro = []string{"introduced=" + ev.Introduced}, true
			if p.introduced == "" {
				p.introduced = ev.Introduced
			}
		case ev.Fixed != "":
			cur = append(cur, "fixed="+ev.Fixed)
			if p.fixed == "" {
				p.fixed = ev.Fixed
			}
			flush()
			hasIntro = false
		case ev.LastAffected != "":
			cur = append(cur, "lastAffected="+ev.LastAffected)
			if p.lastAff == "" {
				p.lastAff = ev.LastAffected
			}
			flush()
			hasIntro = false
		case ev.Limit != "":
			cur = append(cur, "limit="+ev.Limit)
			flush()
			hasIntro = false
		}
	}
	flush()
}

// aliases splits aliases and upstream ids into CVE ids and other ids.
func aliases(id string, lists ...[]string) *source.Advisory {
	adv := &source.Advisory{ID: id}
	seen := map[string]bool{strings.ToUpper(id): true}
	for _, l := range lists {
		for _, a := range l {
			a = strings.TrimSpace(a)
			if a == "" || seen[strings.ToUpper(a)] {
				continue
			}
			seen[strings.ToUpper(a)] = true
			if len(a) > 4 && strings.EqualFold(a[:4], "CVE-") {
				adv.CVEs = append(adv.CVEs, a)
			} else {
				adv.OtherAliases = append(adv.OtherAliases, a)
			}
		}
	}
	return adv
}

// firstCVSS returns the first severity entry that holds a CVSS vector string.
func firstCVSS(sev []osvSeverity) string {
	for _, s := range sev {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(s.Type)), "CVSS") && strings.TrimSpace(s.Score) != "" {
			return strings.TrimSpace(s.Score)
		}
	}
	return ""
}

// cweIDs reads database_specific.cwe_ids leniently: anything but a list of
// strings is ignored.
func cweIDs(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var ds struct {
		CWEIDs []string `json:"cwe_ids"`
	}
	if json.Unmarshal(raw, &ds) != nil {
		return nil
	}
	return ds.CWEIDs
}

func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}
