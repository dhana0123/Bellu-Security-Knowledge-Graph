// Package atlas is the MITRE ATLAS Source_Adapter (Requirement 17.4). It
// downloads the official ATLAS data file of the mitre-atlas/atlas-data
// repository (format version 6, dist/ATLAS-latest.yaml), validates it in a
// first pass, and emits one record per technique and sub-technique.
//
// The release version is collection.version (for example 2026.10). It is the
// Cursor.Version: when it equals the version of the last successful run the
// adapter emits nothing.
//
// A technique that carries an explicit ATT&CK reference (attack-reference.id,
// or ATT&CK-reference.id in older files) gets a relationship
// (AtlasTechnique)-[:ADAPTED_FROM]->(Technique) with the Technique MustExist:
// it is created by the ATT&CK adapter, never here. Nothing is linked by name
// or text. The anchor is the AtlasTechnique and it owns ADAPTED_FROM, so a
// reference that the data drops is marked removed.
package atlas

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/httpx"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/resolve"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source/fetch"
)

// Name is the adapter and source name.
const Name = "atlas"

// Host is the only host the adapter may reach.
const Host = "raw.githubusercontent.com"

// DefaultURL is the latest ATLAS data in the current format. In the
// repository it is a symbolic link; raw.githubusercontent.com serves the link
// target as a one-line text, which the adapter follows (see download).
const DefaultURL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS-latest.yaml"

// CacheFile is the name of the downloaded data file under Options.CacheDir.
const CacheFile = "atlas.yaml"

// SupportedFormat is the major format version of the data file that is read.
const SupportedFormat = "6"

// Limits.
const (
	MaxNameChars = 500
	MaxTextChars = 20000
	// MaxYAMLBytes caps the data file. The live file is about 1.2 MB.
	MaxYAMLBytes = 64 << 20
	maxLinkHops  = 4
)

// Policy is the retry policy of the downloads: waits of 2 and 4 s, 3
// attempts in total (the MITRE policy of the CWE adapter).
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

// Adapter is the MITRE ATLAS Source_Adapter.
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

// Totals implements source.Totaler: {"techniques": techniques and
// sub-techniques of the last parsed data file}. It is empty when nothing was
// parsed in this process.
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

var linkRe = regexp.MustCompile(`^[A-Za-z0-9._/-]+\.ya?ml$`)

// download fetches the data file. The repository stores ATLAS-latest.yaml as
// a symbolic link to v6/ATLAS-latest.yaml, which is a link to the release
// file. The raw host serves a link as its target path (a short text with no
// YAML syntax); download follows such a link relative to the URL it came
// from, at most maxLinkHops times.
func (a *Adapter) download(ctx context.Context) (string, error) {
	u := a.url
	hdr := http.Header{"User-Agent": []string{"bskg/" + orDev(a.version)}}
	for hop := 0; hop <= maxLinkHops; hop++ {
		res, err := fetch.DownloadWith(ctx, a.client, u, a.dir, CacheFile, Policy, a.clock, fetch.Options{Header: hdr, MaxBytes: MaxYAMLBytes})
		if err != nil {
			return "", err
		}
		if res.Size > 256 {
			return res.Path, nil
		}
		b, err := os.ReadFile(res.Path)
		if err != nil {
			return "", err
		}
		target := strings.TrimSpace(string(b))
		if !linkRe.MatchString(target) {
			return res.Path, nil
		}
		base, err := neturl.Parse(u)
		if err != nil {
			return "", err
		}
		ref, err := neturl.Parse(target)
		if err != nil {
			return "", err
		}
		u = base.ResolveReference(ref).String()
	}
	return "", fmt.Errorf("more than %d symbolic links from %s", maxLinkHops, a.url)
}

func orDev(v string) string {
	if v == "" {
		return "dev"
	}
	return v
}

// Fetch implements source.Adapter. It downloads and fully parses the data
// file before it returns, so a failure happens before the first write.
func (a *Adapter) Fetch(ctx context.Context, cp source.Checkpoint, _ source.RunOptions) (source.Iterator, error) {
	path, err := a.download(ctx)
	if err != nil {
		return nil, fail("", cp.Version, fmt.Errorf("download data file: %w", err))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fail("", cp.Version, err)
	}
	defer f.Close()
	rel, techs, err := parse(f)
	if err != nil {
		return nil, fail(rel, cp.Version, err)
	}
	a.mu.Lock()
	a.totals = map[string]int64{"techniques": int64(len(techs))}
	a.mu.Unlock()
	if cp.Version != "" && cp.Version == rel {
		return &sliceIter{}, nil // unchanged release: no record, no write
	}
	recs := make([]source.Record, 0, len(techs))
	for _, t := range techs {
		b, err := json.Marshal(t)
		if err != nil {
			return nil, fail(rel, cp.Version, err)
		}
		recs = append(recs, source.Record{ID: t.ID, Payload: b, Cursor: source.Cursor{Version: rel}})
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

// technique is the stored form of an ATLAS technique or sub-technique.
type technique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tactics     []string `json:"tactics,omitempty"`
	// AttackRef is the ATT&CK technique id the data cites, as written.
	AttackRef string `json:"attackRef,omitempty"`
}

type ref struct {
	ID string `yaml:"id"`
}

type rawTechnique struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	AttackRef   *ref   `yaml:"attack-reference"`
	AttackRefV5 *ref   `yaml:"ATT&CK-reference"`
}

type rawDoc struct {
	FormatVersion string `yaml:"format-version"`
	Collection    struct {
		Version string `yaml:"version"`
	} `yaml:"collection"`
	Tactics map[string]struct {
		Name string `yaml:"name"`
	} `yaml:"tactics"`
	Techniques    map[string]rawTechnique         `yaml:"techniques"`
	Relationships map[string]map[string]yaml.Node `yaml:"relationships"`
}

// parse reads the data file and returns the release, and the techniques
// sorted by id. The release is returned with an error when it was read.
func parse(r io.Reader) (string, []technique, error) {
	var d rawDoc
	dec := yaml.NewDecoder(r)
	if err := dec.Decode(&d); err != nil {
		return "", nil, fmt.Errorf("parse data file: %w", err)
	}
	rel := strings.TrimSpace(d.Collection.Version)
	if rel == "" {
		return "", nil, fmt.Errorf("data file has no collection.version")
	}
	fv := strings.TrimSpace(d.FormatVersion)
	if fv != SupportedFormat && !strings.HasPrefix(fv, SupportedFormat+".") {
		return rel, nil, fmt.Errorf("unsupported format-version %q (want %s.x)", fv, SupportedFormat)
	}
	if len(d.Techniques) == 0 {
		return rel, nil, fmt.Errorf("data file has no techniques")
	}
	ids := make([]string, 0, len(d.Techniques))
	for id := range d.Techniques {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]technique, 0, len(ids))
	for _, id := range ids {
		rt := d.Techniques[id]
		k, err := resolve.Atlas(id)
		if err != nil || k.Value != id {
			return rel, nil, fmt.Errorf("technique key %q is not an ATLAS technique id", id)
		}
		if rt.ID != "" && rt.ID != id {
			return rel, nil, fmt.Errorf("technique %s has id field %q", id, rt.ID)
		}
		if strings.TrimSpace(rt.Name) == "" {
			return rel, nil, fmt.Errorf("technique %s has no name", id)
		}
		t := technique{ID: id, Name: strings.TrimSpace(rt.Name), Description: strings.TrimSpace(rt.Description)}
		switch {
		case rt.AttackRef != nil:
			t.AttackRef = strings.TrimSpace(rt.AttackRef.ID)
		case rt.AttackRefV5 != nil:
			t.AttackRef = strings.TrimSpace(rt.AttackRefV5.ID)
		}
		if n, ok := d.Relationships[id]["achieves"]; ok {
			var links []struct {
				Target string `yaml:"target"`
			}
			if err := n.Decode(&links); err != nil {
				return rel, nil, fmt.Errorf("technique %s: relationships.achieves: %w", id, err)
			}
			for _, l := range links {
				name := l.Target
				if tac, ok := d.Tactics[l.Target]; ok && strings.TrimSpace(tac.Name) != "" {
					name = strings.TrimSpace(tac.Name)
				}
				if name != "" && !contains(t.Tactics, name) {
					t.Tactics = append(t.Tactics, name)
				}
			}
		}
		out = append(out, t)
	}
	return rel, out, nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
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
		return source.Normalized{}, fmt.Errorf("decode atlas record %s: %w", rec.ID, err)
	}
	k, err := resolve.Atlas(t.ID)
	if err != nil {
		return source.Normalized{}, fmt.Errorf("atlas record %s: %w", rec.ID, err)
	}
	if t.Name == "" {
		return source.Normalized{}, fmt.Errorf("atlas record %s: no name", rec.ID)
	}
	self := source.Ref{Kind: source.RefAtlas, Raw: k.Value}
	var out source.Normalized
	props := map[string]any{"name": cut(t.Name, MaxNameChars, k.Value, "name", &out.Notes)}
	var clear []string
	if t.Description != "" {
		props["description"] = cut(t.Description, MaxTextChars, k.Value, "description", &out.Notes)
	} else {
		clear = append(clear, "description")
	}
	if len(t.Tactics) > 0 {
		props["tactics"] = t.Tactics
	} else {
		props["tactics"] = []string{}
	}
	out.Entities = []source.Entity{{Ref: self, Props: props, Clear: clear}}
	if t.AttackRef != "" {
		tk, err := resolve.Technique(t.AttackRef)
		if err != nil {
			out.Notes = append(out.Notes, source.Note{Kind: "warning", ID: k.Value,
				Text: fmt.Sprintf("ATT&CK reference %q is not a technique id; ADAPTED_FROM skipped", t.AttackRef)})
		} else {
			out.Rels = []source.Rel{{
				From: self,
				To:   source.Ref{Kind: source.RefTechnique, Raw: tk.Value, MustExist: true},
				Type: "ADAPTED_FROM",
			}}
		}
	}
	out.Anchor = &self
	out.Owned = []source.OwnedRel{{Type: "ADAPTED_FROM"}}
	return out, nil
}
