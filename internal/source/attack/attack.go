// Package attack is the MITRE ATT&CK Source_Adapter (Requirement 17.3). It
// downloads the official ATT&CK STIX 2.1 bundles (enterprise, mobile and ICS)
// from the mitre-attack/attack-stix-data repository, validates all of them in
// a first pass, and emits one record per technique and sub-technique.
//
// The release version is the x_mitre_version of the x-mitre-collection
// object. It is the Cursor.Version: when it equals the version of the last
// successful run the adapter emits nothing. The adapter creates only
// Technique nodes; it writes no relationships, so it has no Anchor.
package attack

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/httpx"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/resolve"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source/fetch"
)

// Name is the adapter and source name.
const Name = "attack"

// Host is the only host the adapter may reach.
const Host = "raw.githubusercontent.com"

// DefaultBaseURL is the directory of the official ATT&CK STIX data. The
// bundle of a domain is <base>/<domain>/<domain>.json.
const DefaultBaseURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"

// Domains are the ATT&CK collections that are loaded, in load order.
var Domains = []string{"enterprise-attack", "mobile-attack", "ics-attack"}

// Text limits of Requirement 17.1.
const (
	MaxNameChars = 500
	MaxTextChars = 20000
)

// Policy is the retry policy of the downloads: waits of 2 and 4 s, 3
// attempts in total (the MITRE policy of the CWE adapter).
var Policy = httpx.CWEPolicy

// downloadTimeout is the time limit of one file download.
const downloadTimeout = 5 * time.Minute

// Options configures the adapter. Every field is optional.
type Options struct {
	// CacheDir is BSKG_CACHE_DIR. Empty means os.TempDir().
	CacheDir string
	// Version is the product version, sent in the User-Agent header.
	Version string
	// BaseURL, Client and Clock replace the defaults (tests).
	BaseURL string
	Client  *http.Client
	Clock   httpx.Clock
}

// Adapter is the MITRE ATT&CK Source_Adapter.
type Adapter struct {
	base    string
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
	a := &Adapter{base: strings.TrimRight(o.BaseURL, "/"), dir: o.CacheDir, version: o.Version, client: o.Client, clock: o.Clock}
	if a.base == "" {
		a.base = DefaultBaseURL
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

// Totals implements source.Totaler: {"techniques": techniques and
// sub-techniques of the last parsed release, revoked and deprecated ones
// included}. It is empty when nothing was parsed in this process.
func (a *Adapter) Totals(context.Context) (map[string]int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]int64, len(a.totals))
	for k, v := range a.totals {
		out[k] = v
	}
	return out, nil
}

// fail names the source and the release (Requirement 17.7). release is empty
// while the release is not yet known (a download failed); the last stored
// release is then named so the error still says which release is affected.
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

func (a *Adapter) userAgent() http.Header {
	v := a.version
	if v == "" {
		v = "dev"
	}
	return http.Header{"User-Agent": []string{"bskg/" + v}}
}

func cacheFile(domain string) string { return "attack-" + domain + ".json" }

// release combines the collection versions of the bundles: the version
// itself when all agree, else "<domain>=<version>;..." in load order.
func release(versions []string) string {
	same := true
	for _, v := range versions[1:] {
		if v != versions[0] {
			same = false
		}
	}
	if same {
		return versions[0]
	}
	parts := make([]string, len(versions))
	for i, v := range versions {
		parts[i] = Domains[i] + "=" + v
	}
	return strings.Join(parts, ";")
}

// Fetch implements source.Adapter. It downloads and fully parses every
// bundle before it returns, so a failure happens before the first write and
// existing data stays unchanged.
func (a *Adapter) Fetch(ctx context.Context, cp source.Checkpoint, _ source.RunOptions) (source.Iterator, error) {
	var bundles []bundle
	var versions []string
	for _, d := range Domains {
		url := a.base + "/" + d + "/" + d + ".json"
		res, err := fetch.DownloadWith(ctx, a.client, url, a.dir, cacheFile(d), Policy, a.clock, fetch.Options{Header: a.userAgent()})
		if err != nil {
			return nil, fail("", cp.Version, fmt.Errorf("download %s: %w", d, err))
		}
		b, err := parseBundle(res.Path, d)
		if err != nil {
			return nil, fail(strings.TrimSpace(b.Release), cp.Version, fmt.Errorf("parse %s: %w", cacheFile(d), err))
		}
		bundles = append(bundles, b)
		versions = append(versions, b.Release)
	}
	rel := release(versions)

	// Merge the domains. A technique that is in several bundles keeps one
	// record with the union of domains and tactics.
	merged := map[string]*technique{}
	for _, b := range bundles {
		for i := range b.Techniques {
			t := b.Techniques[i]
			if m, ok := merged[t.ID]; ok {
				m.Domains = addAll(m.Domains, t.Domains)
				m.Tactics = addAll(m.Tactics, t.Tactics)
				m.Revoked = m.Revoked && t.Revoked
				m.Deprecated = m.Deprecated && t.Deprecated
				continue
			}
			merged[t.ID] = &t
		}
	}
	a.mu.Lock()
	a.totals = map[string]int64{"techniques": int64(len(merged))}
	a.mu.Unlock()

	if cp.Version != "" && cp.Version == rel {
		return &sliceIter{}, nil // unchanged release: no record, no write
	}
	ids := make([]string, 0, len(merged))
	for id := range merged {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	recs := make([]source.Record, 0, len(ids))
	for _, id := range ids {
		b, err := json.Marshal(merged[id])
		if err != nil {
			return nil, fail(rel, cp.Version, err)
		}
		recs = append(recs, source.Record{ID: id, Payload: b, Cursor: source.Cursor{Version: rel}})
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

// Normalize implements source.Adapter. It is pure.
func (*Adapter) Normalize(rec source.Record) (source.Normalized, error) {
	var t technique
	if err := json.Unmarshal(rec.Payload, &t); err != nil {
		return source.Normalized{}, fmt.Errorf("decode attack record %s: %w", rec.ID, err)
	}
	k, err := resolve.Technique(t.ID)
	if err != nil {
		return source.Normalized{}, fmt.Errorf("attack record %s: %w", rec.ID, err)
	}
	if t.Name == "" {
		return source.Normalized{}, fmt.Errorf("attack record %s: no name", rec.ID)
	}
	var out source.Normalized
	props := map[string]any{
		"name":       cut(t.Name, MaxNameChars, k.Value, "name", &out.Notes),
		"deprecated": t.Deprecated,
		"revoked":    t.Revoked,
		"domains":    nonNil(t.Domains),
		"tactics":    nonNil(t.Tactics),
	}
	var clear []string
	if t.Description != "" {
		props["description"] = cut(t.Description, MaxTextChars, k.Value, "description", &out.Notes)
	} else {
		clear = append(clear, "description")
	}
	if t.URL != "" {
		props["url"] = t.URL
	} else {
		clear = append(clear, "url")
	}
	out.Entities = []source.Entity{{
		Ref:   source.Ref{Kind: source.RefTechnique, Raw: k.Value},
		Props: props,
		Clear: clear,
	}}
	return out, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
