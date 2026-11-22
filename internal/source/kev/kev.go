// Package kev is the CISA Known Exploited Vulnerabilities Source_Adapter
// (Requirement 16.1 to 16.3, 16.8). It downloads the JSON catalog once per
// run, sets the kev properties on Vulnerabilities that already exist and sets
// kev=false on stored KEV Vulnerabilities that left the catalog.
package kev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bellu/bskg/internal/httpx"
	"github.com/bellu/bskg/internal/resolve"
	"github.com/bellu/bskg/internal/source"
	"github.com/bellu/bskg/internal/source/fetch"
)

// Name is the adapter name.
const Name = "kev"

// Host is the only host the adapter may reach.
const Host = "www.cisa.gov"

// DefaultURL is the official CISA KEV JSON feed.
const DefaultURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// CacheFile is the name of the downloaded catalog under Options.CacheDir.
const CacheFile = "kev.json"

// Policy is the retry policy of the download: 3 retries, 1 s doubling.
var Policy = httpx.Policy{Retries: 3, Base: time.Second}

// Stored returns the cveID of every Vulnerability that has kev=true in the
// graph. It is injected so the Pipeline needs no change (Requirement 16.3).
type Stored func(ctx context.Context) (map[string]struct{}, error)

// Options configures the adapter. Every field is optional except that
// removal handling needs Stored.
type Options struct {
	// CacheDir is BSKG_CACHE_DIR. Empty means os.TempDir().
	CacheDir string
	// Version is the product version. It is accepted for symmetry with the
	// other adapters; the CISA download sends no custom User-Agent.
	Version string
	// Stored reads the cveIDs with kev=true. When nil the adapter emits no
	// removals.
	Stored Stored
	// URL, Client and Clock replace the defaults (tests).
	URL    string
	Client *http.Client
	Clock  httpx.Clock
}

// Adapter is the CISA KEV Source_Adapter.
type Adapter struct {
	url    string
	dir    string
	client *http.Client
	clock  httpx.Clock
	stored Stored

	mu     sync.Mutex
	totals map[string]int64
}

var (
	_ source.Adapter = (*Adapter)(nil)
	_ source.Totaler = (*Adapter)(nil)
)

// New returns the adapter.
func New(o Options) *Adapter {
	a := &Adapter{url: o.URL, dir: o.CacheDir, client: o.Client, clock: o.Clock, stored: o.Stored}
	if a.url == "" {
		a.url = DefaultURL
	}
	if a.dir == "" {
		a.dir = os.TempDir()
	}
	if a.client == nil {
		a.client = httpx.NewAllowList(Host).NewClient(120 * time.Second)
	}
	if a.clock == nil {
		a.clock = httpx.RealClock{}
	}
	return a
}

// Name implements source.Adapter.
func (a *Adapter) Name() string { return Name }

// Totals implements source.Totaler: {"entries": vulnerabilities in the last
// fetched catalog}. It is empty when nothing was fetched in this process.
func (a *Adapter) Totals(context.Context) (map[string]int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]int64, len(a.totals))
	for k, v := range a.totals {
		out[k] = v
	}
	return out, nil
}

// entry is the part of a catalog entry the adapter reads. Descriptions,
// required actions, notes and CWE lists are not stored.
type entry struct {
	CVEID      string `json:"cveID"`
	DateAdded  string `json:"dateAdded"`
	DueDate    string `json:"dueDate"`
	Ransomware string `json:"knownRansomwareCampaignUse"`
	Name       string `json:"vulnerabilityName"`
}

// payload is the stored form of a record.
type payload struct {
	entry
	Remove bool `json:"remove,omitempty"`
}

// Fetch downloads the catalog, parses it completely, and only then returns
// the records. A download, parse or graph-read error fails the run before any
// record is returned, so nothing changes and no kev=false is written
// (Requirement 16.8). All entries are always emitted, because removal needs
// the full set; unchanged values produce no write downstream.
func (a *Adapter) Fetch(ctx context.Context, _ source.Checkpoint, _ source.RunOptions) (source.Iterator, error) {
	res, err := fetch.DownloadToCache(ctx, a.client, a.url, a.dir, CacheFile, Policy, a.clock)
	if err != nil {
		return nil, fmt.Errorf("kev: download catalog: %w", err)
	}
	cat, err := scan(res.Path)
	if err != nil {
		return nil, fmt.Errorf("kev: parse catalog: %w", err)
	}
	var gone []string
	if a.stored != nil {
		st, err := a.stored(ctx)
		if err != nil {
			return nil, fmt.Errorf("kev: read stored KEV vulnerabilities: %w", err)
		}
		gone = removed(st, cat.ids)
	}
	f, err := os.Open(res.Path)
	if err != nil {
		return nil, fmt.Errorf("kev: open catalog: %w", err)
	}
	s, err := newStream(f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("kev: parse catalog: %w", err)
	}
	a.mu.Lock()
	a.totals = map[string]int64{"entries": int64(cat.count)}
	a.mu.Unlock()
	return &iter{
		f: f, s: s, gone: gone, seen: map[string]struct{}{},
		version: cat.version + "+" + res.SHA256,
	}, nil
}

// catalog is the result of the validating first pass.
type catalog struct {
	version string
	count   int
	ids     map[string]struct{} // canonical CVE ids
}

// scan reads the whole file once, streaming, and validates it: valid JSON,
// a catalogVersion, a vulnerabilities array, and a count equal to the number
// of entries (a truncated or cut file fails).
func scan(path string) (catalog, error) {
	f, err := os.Open(path)
	if err != nil {
		return catalog{}, err
	}
	defer f.Close()
	s, err := newStream(f)
	if err != nil {
		return catalog{}, err
	}
	cat := catalog{ids: map[string]struct{}{}}
	for {
		e, err := s.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return catalog{}, err
		}
		cat.count++
		if k, err := resolve.CVE(e.CVEID); err == nil {
			cat.ids[k.Value] = struct{}{}
		}
	}
	if err := s.finish(); err != nil {
		return catalog{}, err
	}
	if s.version == "" {
		return catalog{}, errors.New("missing catalogVersion")
	}
	if !s.hasCount || s.count != cat.count {
		return catalog{}, fmt.Errorf("count %d does not match %d entries", s.count, cat.count)
	}
	if cat.count == 0 {
		return catalog{}, errors.New("catalog has no entries")
	}
	cat.version = s.version
	return cat, nil
}

// removed returns the ascending CVE ids that are stored with kev=true and are
// not in the catalog.
func removed(stored, catalog map[string]struct{}) []string {
	var gone []string
	for id := range stored {
		k, err := resolve.CVE(id)
		if err != nil {
			continue
		}
		if _, ok := catalog[k.Value]; !ok {
			gone = append(gone, k.Value)
		}
	}
	sort.Strings(gone)
	return gone
}

// stream pulls entries from the vulnerabilities array of the catalog without
// loading the file.
type stream struct {
	dec      *json.Decoder
	inArray  bool
	done     bool
	version  string
	count    int
	hasCount bool
	hasVulns bool
}

func newStream(r io.Reader) (*stream, error) {
	s := &stream{dec: json.NewDecoder(r)}
	t, err := s.dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, errors.New("catalog is not a JSON object")
	}
	return s, nil
}

// skipToArray reads top-level members until the vulnerabilities array opens.
func (s *stream) skipToArray() error {
	for s.dec.More() {
		t, err := s.dec.Token()
		if err != nil {
			return err
		}
		key, _ := t.(string)
		if key == "vulnerabilities" {
			t, err := s.dec.Token()
			if err != nil {
				return err
			}
			if d, ok := t.(json.Delim); !ok || d != '[' {
				return errors.New("vulnerabilities is not an array")
			}
			s.inArray, s.hasVulns = true, true
			return nil
		}
		if err := s.member(key); err != nil {
			return err
		}
	}
	return errors.New("missing vulnerabilities array")
}

func (s *stream) member(key string) error {
	switch key {
	case "catalogVersion":
		return s.dec.Decode(&s.version)
	case "count":
		s.hasCount = true
		return s.dec.Decode(&s.count)
	}
	var skip json.RawMessage
	return s.dec.Decode(&skip)
}

// next returns the next entry, or io.EOF after the last one.
func (s *stream) next() (entry, error) {
	if s.done {
		return entry{}, io.EOF
	}
	if !s.inArray {
		if err := s.skipToArray(); err != nil {
			return entry{}, err
		}
	}
	if !s.dec.More() {
		if _, err := s.dec.Token(); err != nil { // ]
			return entry{}, err
		}
		s.inArray, s.done = false, true
		return entry{}, io.EOF
	}
	var e entry
	if err := s.dec.Decode(&e); err != nil {
		return entry{}, err
	}
	return e, nil
}

// finish reads the members after the array and the closing brace.
func (s *stream) finish() error {
	if !s.hasVulns {
		return errors.New("missing vulnerabilities array")
	}
	for s.dec.More() {
		t, err := s.dec.Token()
		if err != nil {
			return err
		}
		key, _ := t.(string)
		if err := s.member(key); err != nil {
			return err
		}
	}
	if _, err := s.dec.Token(); err != nil { // }
		return err
	}
	if _, err := s.dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after the catalog")
	}
	return nil
}

// iter streams the entry records, then the removal records, then a cursor
// record that carries the catalog version.
type iter struct {
	f       *os.File
	s       *stream
	gone    []string
	seen    map[string]struct{}
	version string
	phase   int
	i       int
}

func (it *iter) close() {
	if it.f != nil {
		_ = it.f.Close()
		it.f = nil
	}
}

// Close releases the cached file when the caller stops before io.EOF.
func (it *iter) Close() error { it.close(); return nil }

func (it *iter) Next(ctx context.Context) (source.Record, error) {
	if err := ctx.Err(); err != nil {
		it.close()
		return source.Record{}, err
	}
	for it.phase == 0 {
		e, err := it.s.next()
		if errors.Is(err, io.EOF) {
			it.phase = 1
			it.close()
			break
		}
		if err != nil {
			it.close()
			return source.Record{}, fmt.Errorf("kev: read catalog: %w", err)
		}
		id := strings.TrimSpace(e.CVEID)
		if k, err := resolve.CVE(id); err == nil {
			if _, dup := it.seen[k.Value]; dup {
				continue // the first entry of an id wins
			}
			it.seen[k.Value] = struct{}{}
		}
		return mkRecord(id, payload{entry: e}), nil
	}
	if it.phase == 1 && it.i < len(it.gone) {
		id := it.gone[it.i]
		it.i++
		return mkRecord(id, payload{entry: entry{CVEID: id}, Remove: true}), nil
	}
	if it.phase == 1 {
		it.phase = 2
		return source.Record{ID: "catalog", Cursor: source.Cursor{Version: it.version}}, nil
	}
	return source.Record{}, io.EOF
}

func mkRecord(id string, p payload) source.Record {
	b, _ := json.Marshal(p)
	return source.Record{ID: id, Payload: b}
}

// Normalize maps one record to the Vulnerability update. It is pure.
func (a *Adapter) Normalize(rec source.Record) (source.Normalized, error) {
	var p payload
	if err := json.Unmarshal(rec.Payload, &p); err != nil {
		return source.Normalized{}, fmt.Errorf("record %s: invalid payload: %w", rec.ID, err)
	}
	key, err := resolve.CVE(p.CVEID)
	if err != nil {
		return source.Normalized{}, fmt.Errorf("record %s: invalid cveID %q", rec.ID, clip(p.CVEID))
	}
	ref := source.Ref{Kind: source.RefCVE, Raw: key.Value}
	gate := source.Ref{Kind: source.RefCVE, Raw: key.Value, MustExist: true}

	if p.Remove {
		return source.Normalized{
			Entities: []source.Entity{{Ref: ref, Props: map[string]any{"kev": false}}},
			Gate:     []source.Ref{gate},
		}, nil
	}

	added, err := parseDate(p.DateAdded)
	if err != nil {
		return source.Normalized{}, fmt.Errorf("record %s: dateAdded: %w", rec.ID, err)
	}
	props := map[string]any{"kev": true, "kevDateAdded": added}
	var n source.Normalized
	warn := func(text string) {
		n.Missing = true
		n.Notes = append(n.Notes, source.Note{Kind: "warning", ID: rec.ID, Text: text})
	}
	if due, err := parseDate(p.DueDate); err == nil {
		props["kevDueDate"] = due
	} else {
		warn("dueDate missing or invalid: " + err.Error())
	}
	if v := strings.TrimSpace(p.Ransomware); v != "" {
		props["kevRansomwareUse"] = v
	} else {
		warn("knownRansomwareCampaignUse missing")
	}
	if v := strings.TrimSpace(p.Name); v != "" {
		props["kevVulnerabilityName"] = v
	} else {
		warn("vulnerabilityName missing")
	}
	n.Entities = []source.Entity{{Ref: ref, Props: props}}
	n.Gate = []source.Ref{gate}
	return n, nil
}

func parseDate(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid date %q: want YYYY-MM-DD", clip(s))
	}
	return t, nil
}

func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
