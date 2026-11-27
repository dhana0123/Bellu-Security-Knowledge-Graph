// Package capec is the MITRE CAPEC Source_Adapter (Requirement 17). It
// downloads the official CAPEC XML catalog, validates all of it in a first
// pass, and emits one record per Attack_Pattern. A record creates the
// AttackPattern and its cross-references that appear in the data:
//
//   - Related_Weaknesses: (Weakness)-[:RELATED_ATTACK_PATTERN]->(AttackPattern).
//     The Weakness must exist (MustExist); the CWE adapter loads it.
//   - Taxonomy_Mappings with Taxonomy_Name="ATTACK" and an Entry_ID such as
//     "1574.010": (AttackPattern)-[:MAPS_TO_TECHNIQUE]->(Technique T1574.010).
//     The Technique must exist (MustExist); the ATT&CK adapter loads it.
//
// Links are made only from these explicit identifiers, never from names or
// text (Requirement 17.5). The catalog Version attribute is the
// Cursor.Version: when it equals the version of the last successful run the
// adapter emits nothing.
//
// Removal: the anchor is the AttackPattern and it owns MAPS_TO_TECHNIQUE, so
// a mapping the catalog no longer lists is marked removed.
// RELATED_ATTACK_PATTERN starts at the Weakness, which is not the anchor of
// this adapter, so a dropped weakness link is not marked removed.
package capec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/httpx"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/resolve"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source/fetch"
)

// Name is the adapter and source name.
const Name = "capec"

// Host is the only host the adapter may reach.
const Host = "capec.mitre.org"

// DefaultURL is the official CAPEC catalog (XML).
const DefaultURL = "https://capec.mitre.org/data/xml/capec_latest.xml"

// CacheFile is the name of the downloaded catalog under Options.CacheDir.
const CacheFile = "capec.xml"

// Text limits of Requirement 17.1.
const (
	MaxNameChars = 500
	MaxTextChars = 20000
)

// Policy is the retry policy of the download: waits of 2 and 4 s, 3 attempts
// in total (the MITRE policy of the CWE adapter).
var Policy = httpx.CWEPolicy

const downloadTimeout = 2 * time.Minute

// Options configures the adapter. Every field is optional.
type Options struct {
	// CacheDir is BSKG_CACHE_DIR. Empty means os.TempDir().
	CacheDir string
	// Version is the product version, sent in the User-Agent header.
	Version string
	// URL, Client and Clock replace the defaults (tests).
	URL    string
	Client *http.Client
	Clock  httpx.Clock
}

// Adapter is the MITRE CAPEC Source_Adapter.
type Adapter struct {
	url     string
	dir     string
	version string
	client  *http.Client
	clock   httpx.Clock

	mu     sync.Mutex
	totals map[string]int64
}

var (
	_ source.Adapter = (*Adapter)(nil)
	_ source.Totaler = (*Adapter)(nil)
)

// New returns the adapter.
func New(o Options) *Adapter {
	a := &Adapter{url: o.URL, dir: o.CacheDir, version: o.Version, client: o.Client, clock: o.Clock}
	if a.url == "" {
		a.url = DefaultURL
	}
	if a.dir == "" {
		a.dir = os.TempDir()
	}
	if a.client == nil {
		a.client = httpx.NewAllowList(Host).NewClient(downloadTimeout)
	}
	if a.clock == nil {
		a.clock = httpx.RealClock{}
	}
	return a
}

// Name implements source.Adapter.
func (*Adapter) Name() string { return Name }

// Totals implements source.Totaler: {"attackPatterns": Attack_Pattern
// elements of the last parsed catalog}. It is empty when nothing was parsed
// in this process.
func (a *Adapter) Totals(context.Context) (map[string]int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]int64, len(a.totals))
	for k, v := range a.totals {
		out[k] = v
	}
	return out, nil
}

// fail names the source and the release (Requirement 17.7).
func fail(release, last string, err error) error {
	switch {
	case release != "":
		return fmt.Errorf("source %s, release %s: %w", Name, release, err)
	case last != "":
		return fmt.Errorf("source %s, release not read (latest; last loaded %s): %w", Name, last, err)
	default:
		return fmt.Errorf("source %s, release not read (latest): %w", Name, err)
	}
}

// canonID returns the number of a CAPEC id without leading zeros.
func canonID(id string) (string, bool) {
	n, err := strconv.ParseUint(id, 10, 64)
	if err != nil || n == 0 {
		return "", false
	}
	return strconv.FormatUint(n, 10), true
}

// Fetch implements source.Adapter. It downloads and fully parses the catalog
// before it returns, so a failure happens before the first write.
func (a *Adapter) Fetch(ctx context.Context, cp source.Checkpoint, _ source.RunOptions) (source.Iterator, error) {
	v := a.version
	if v == "" {
		v = "dev"
	}
	res, err := fetch.DownloadWith(ctx, a.client, a.url, a.dir, CacheFile, Policy, a.clock, fetch.Options{
		Header:   http.Header{"User-Agent": []string{"bskg/" + v}},
		MaxBytes: MaxXMLBytes,
	})
	if err != nil {
		return nil, fail("", cp.Version, fmt.Errorf("download catalog: %w", err))
	}
	cr, err := openCatalog(res.Path)
	if err != nil {
		return nil, fail("", cp.Version, err)
	}
	release := cr.Version
	var recs []source.Record
	seen := map[string]bool{}
	for {
		p, err := cr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			cr.Close()
			return nil, fail(release, cp.Version, err)
		}
		n, ok := canonID(p.ID)
		if !ok {
			cr.Close()
			return nil, fail(release, cp.Version, fmt.Errorf("Attack_Pattern has invalid ID %q", p.ID))
		}
		if seen[n] {
			cr.Close()
			return nil, fail(release, cp.Version, fmt.Errorf("Attack_Pattern CAPEC-%s appears twice", n))
		}
		seen[n] = true
		if p.Name == "" {
			cr.Close()
			return nil, fail(release, cp.Version, fmt.Errorf("Attack_Pattern CAPEC-%s has no Name", n))
		}
		p.ID = n
		b, err := json.Marshal(p)
		if err != nil {
			cr.Close()
			return nil, fail(release, cp.Version, err)
		}
		recs = append(recs, source.Record{ID: "CAPEC-" + n, Payload: b, Cursor: source.Cursor{Version: release}})
	}
	cr.Close()
	a.mu.Lock()
	a.totals = map[string]int64{"attackPatterns": int64(len(recs))}
	a.mu.Unlock()
	if cp.Version != "" && cp.Version == release {
		return &sliceIter{}, nil // unchanged release: no record, no write
	}
	return &sliceIter{recs: recs}, nil
}

type sliceIter struct {
	recs []source.Record
	i    int
}

func (s *sliceIter) Next(ctx context.Context) (source.Record, error) {
	if err := ctx.Err(); err != nil {
		return source.Record{}, err
	}
	if s.i >= len(s.recs) {
		return source.Record{}, io.EOF
	}
	r := s.recs[s.i]
	s.i++
	return r, nil
}

func cut(s string, max int, key, prop string, notes *[]source.Note) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	*notes = append(*notes, source.Note{Kind: "warning", ID: key,
		Text: fmt.Sprintf("%s truncated to %d characters", prop, max)})
	return string(r[:max])
}

var entryRe = regexp.MustCompile(`^\d{4}(\.\d{3})?$`)

// Normalize implements source.Adapter. It is pure.
func (*Adapter) Normalize(rec source.Record) (source.Normalized, error) {
	var p pattern
	if err := json.Unmarshal(rec.Payload, &p); err != nil {
		return source.Normalized{}, fmt.Errorf("decode capec record %s: %w", rec.ID, err)
	}
	k, err := resolve.CAPEC(p.ID)
	if err != nil {
		return source.Normalized{}, fmt.Errorf("capec record %s: %w", rec.ID, err)
	}
	if p.Name == "" {
		return source.Normalized{}, fmt.Errorf("capec record %s: no name", rec.ID)
	}
	ref := source.Ref{Kind: source.RefCAPEC, Raw: k.Value}
	var out source.Normalized

	props := map[string]any{"name": cut(p.Name, MaxNameChars, k.Value, "name", &out.Notes)}
	var clear []string
	for _, f := range []struct{ prop, val string }{
		{"abstraction", p.Abstraction}, {"status", p.Status},
		{"likelihood", p.Likelihood}, {"severity", p.Severity},
	} {
		if f.val != "" {
			props[f.prop] = f.val
		} else {
			clear = append(clear, f.prop)
		}
	}
	if p.Description != "" {
		props["description"] = cut(p.Description, MaxTextChars, k.Value, "description", &out.Notes)
	} else {
		clear = append(clear, "description")
	}
	out.Entities = []source.Entity{{Ref: ref, Props: props, Clear: clear}}
	out.Missing = p.Abstraction == "" || p.Status == ""

	seenCWE := map[string]bool{}
	for _, raw := range p.CWEs {
		w, err := resolve.CWE(raw)
		if err != nil {
			out.Notes = append(out.Notes, source.Note{Kind: "warning", ID: k.Value,
				Text: fmt.Sprintf("Related_Weakness CWE_ID %q is not a CWE id; relationship skipped", raw)})
			continue
		}
		if seenCWE[w.Value] {
			continue
		}
		seenCWE[w.Value] = true
		out.Rels = append(out.Rels, source.Rel{
			From: source.Ref{Kind: source.RefCWE, Raw: w.Value, MustExist: true},
			To:   ref,
			Type: "RELATED_ATTACK_PATTERN",
		})
	}
	seenTech := map[string]bool{}
	for _, raw := range p.Techniques {
		if !entryRe.MatchString(raw) {
			out.Notes = append(out.Notes, source.Note{Kind: "warning", ID: k.Value,
				Text: fmt.Sprintf("ATTACK taxonomy Entry_ID %q is not a technique id; mapping skipped", raw)})
			continue
		}
		t, err := resolve.Technique("T" + raw)
		if err != nil {
			out.Notes = append(out.Notes, source.Note{Kind: "warning", ID: k.Value,
				Text: fmt.Sprintf("ATTACK taxonomy Entry_ID %q is not a technique id; mapping skipped", raw)})
			continue
		}
		if seenTech[t.Value] {
			continue
		}
		seenTech[t.Value] = true
		out.Rels = append(out.Rels, source.Rel{
			From: ref,
			To:   source.Ref{Kind: source.RefTechnique, Raw: t.Value, MustExist: true},
			Type: "MAPS_TO_TECHNIQUE",
		})
	}
	out.Anchor = &ref
	out.Owned = []source.OwnedRel{{Type: "MAPS_TO_TECHNIQUE"}}
	return out, nil
}
