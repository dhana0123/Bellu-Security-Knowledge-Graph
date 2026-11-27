// Package cwe is the MITRE CWE Source_Adapter. It downloads the official
// catalog archive, validates it in a first pass, and then emits one record
// per Weakness or Category (nodes first, then CHILD_OF relationships), as
// described in Requirement 4.
package cwe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/httpx"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
)

// DefaultURL is the official MITRE CWE catalog archive.
const DefaultURL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

// Name is the adapter and source name.
const Name = "cwe"

// MaxTextChars is the longest description or extendedDescription kept.
const MaxTextChars = 20000

// attemptTimeout is the time limit of one download attempt (Requirement 4.14).
const attemptTimeout = 120 * time.Second

// Adapter is the MITRE CWE Source_Adapter.
type Adapter struct {
	url    string
	client *http.Client
	clock  httpx.Clock
	policy httpx.Policy

	mu     sync.Mutex
	totals map[string]int64 // counts of the last parsed catalog; nil if none
}

// Option configures an Adapter.
type Option func(*Adapter)

// WithBaseURL replaces DefaultURL, for tests.
func WithBaseURL(u string) Option { return func(a *Adapter) { a.url = u } }

// WithHTTPClient replaces the HTTP client, for tests.
func WithHTTPClient(c *http.Client) Option { return func(a *Adapter) { a.client = c } }

// WithClock replaces the clock used for retry waits, for tests.
func WithClock(c httpx.Clock) Option { return func(a *Adapter) { a.clock = c } }

// New returns the CWE adapter.
func New(opts ...Option) *Adapter {
	a := &Adapter{url: DefaultURL, client: &http.Client{}, clock: httpx.RealClock{}, policy: httpx.CWEPolicy}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Name implements source.Adapter.
func (*Adapter) Name() string { return Name }

// download fetches the archive with CWEPolicy and a 120 s limit per attempt.
func (a *Adapter) download(ctx context.Context) ([]byte, error) {
	var data []byte
	err := httpx.Do(ctx, a.policy, a.clock, func(int) error {
		actx, cancel := context.WithTimeout(ctx, attemptTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(actx, http.MethodGet, a.url, nil)
		if err != nil {
			return err
		}
		resp, err := a.client.Do(req)
		if err != nil {
			return httpx.Retryable(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			e := fmt.Errorf("download %s: HTTP %d", a.url, resp.StatusCode)
			if httpx.IsRetryableStatus(resp.StatusCode) {
				return httpx.Retryable(e)
			}
			return e
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxZipBytes+1))
		if err != nil {
			return httpx.Retryable(err)
		}
		if len(b) > maxZipBytes {
			return errors.New("archive exceeds 64 MB")
		}
		data = b
		return nil
	})
	return data, err
}

func fail(version string, err error) error {
	if version != "" {
		return fmt.Errorf("source %s, catalog version %s: %w", Name, version, err)
	}
	return fmt.Errorf("source %s: %w", Name, err)
}

// canon returns the key number of a CWE id without leading zeros.
func canon(id string) (string, bool) {
	n, err := strconv.ParseUint(id, 10, 64)
	if err != nil || n == 0 {
		return "", false
	}
	return strconv.FormatUint(n, 10), true
}

// Totals implements source.Totaler. It returns the element counts of the last
// catalog parsed in this process, or an empty map when none was parsed. Views
// are not parsed, so no "views" key is reported.
func (a *Adapter) Totals(context.Context) (map[string]int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]int64, len(a.totals))
	for k, v := range a.totals {
		out[k] = v
	}
	return out, nil
}

// Fetch implements source.Adapter. Pass 1 validates the whole catalog and
// collects the ids; pass 2 is streamed by the returned iterator. Any error
// here happens before the first write.
func (a *Adapter) Fetch(ctx context.Context, cp source.Checkpoint, _ source.RunOptions) (source.Iterator, error) {
	data, err := a.download(ctx)
	if err != nil {
		return nil, fail("", fmt.Errorf("download catalog: %w", err))
	}
	cr, err := openCatalog(data, MaxUnzippedBytes)
	if err != nil {
		return nil, fail("", err)
	}
	version := cr.Version
	unchanged := cp.Version != "" && cp.Version == version
	ids := map[string]bool{}
	counts := map[string]int64{"weaknesses": 0, "categories": 0}
	for {
		el, err := cr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			cr.Close()
			if unchanged {
				return &iterator{}, nil // unchanged: no record, no write; counts are not recorded
			}
			return nil, fail(version, err)
		}
		switch el.Kind {
		case "Weakness":
			counts["weaknesses"]++
		case "Category":
			counts["categories"]++
		}
		n, ok := canon(el.ID)
		if !ok {
			if unchanged {
				continue
			}
			cr.Close()
			return nil, fail(version, fmt.Errorf("%s has invalid ID %q", el.Kind, el.ID))
		}
		ids[n] = true
	}
	a.mu.Lock()
	a.totals = counts
	a.mu.Unlock()
	if unchanged {
		cr.Close()
		return &iterator{}, nil // unchanged: no record, no write
	}
	cr.Close()
	return &iterator{data: data, version: version, ids: ids}, nil
}

// iterator streams phase A (nodes) and then phase B (relationships).
type iterator struct {
	data    []byte
	version string
	ids     map[string]bool
	phase   int // 0 = A, 1 = B, 2 = done
	cr      *catalogReader
}

// payload is the raw record of the adapter.
type payload struct {
	Phase   string  `json:"phase"` // "node" or "rels"
	Element element `json:"element"`
	// Found[i] tells whether Element.Parents[i] is in the catalog (rels only).
	Found []bool `json:"found,omitempty"`
}

func (it *iterator) Next(ctx context.Context) (source.Record, error) {
	for {
		if err := ctx.Err(); err != nil {
			return source.Record{}, err
		}
		if it.phase >= 2 || it.data == nil {
			return source.Record{}, io.EOF
		}
		if it.cr == nil {
			cr, err := openCatalog(it.data, MaxUnzippedBytes)
			if err != nil {
				return source.Record{}, fail(it.version, err)
			}
			it.cr = cr
		}
		el, err := it.cr.Next()
		if errors.Is(err, io.EOF) {
			it.cr.Close()
			it.cr = nil
			it.phase++
			continue
		}
		if err != nil {
			return source.Record{}, fail(it.version, err)
		}
		n, _ := canon(el.ID)
		p := payload{Phase: "node", Element: el}
		id := "CWE-" + n
		if it.phase == 1 {
			p.Phase = "rels"
			id += "#rels"
			for _, par := range el.Parents {
				pn, ok := canon(par.ID)
				p.Found = append(p.Found, ok && it.ids[pn])
			}
		}
		b, err := json.Marshal(p)
		if err != nil {
			return source.Record{}, fail(it.version, err)
		}
		return source.Record{ID: id, Payload: b, Cursor: source.Cursor{Version: it.version}}, nil
	}
}

func cut(s string, key, prop string, notes *[]source.Note) string {
	r := []rune(s)
	if len(r) <= MaxTextChars {
		return s
	}
	*notes = append(*notes, source.Note{Kind: "warning", ID: key, Text: fmt.Sprintf("%s truncated to %d characters", prop, MaxTextChars)})
	return string(r[:MaxTextChars])
}

// Normalize implements source.Adapter. It is pure.
func (*Adapter) Normalize(rec source.Record) (source.Normalized, error) {
	var p payload
	if err := json.Unmarshal(rec.Payload, &p); err != nil {
		return source.Normalized{}, fmt.Errorf("decode cwe record %s: %w", rec.ID, err)
	}
	el := p.Element
	n, ok := canon(el.ID)
	if !ok {
		return source.Normalized{}, fmt.Errorf("cwe record %s: invalid ID %q", rec.ID, el.ID)
	}
	key := "CWE-" + n
	ref := source.Ref{Kind: source.RefCWE, Raw: key}
	var out source.Normalized

	switch p.Phase {
	case "node":
		abstraction := el.Abstraction
		if el.Kind == "Category" {
			abstraction = "Category"
		}
		views := make([]string, 0, len(el.Parents))
		for _, par := range el.Parents {
			views = append(views, par.View)
		}
		props := map[string]any{
			"cweName":             el.Name,
			"weaknessAbstraction": abstraction,
			"status":              el.Status,
			"cweView":             views,
		}
		if el.Description != "" {
			props["description"] = cut(el.Description, key, "description", &out.Notes)
		}
		if el.Extended != "" {
			props["extendedDescription"] = cut(el.Extended, key, "extendedDescription", &out.Notes)
		}
		out.Missing = el.Name == "" || el.Status == "" || abstraction == ""
		out.Entities = []source.Entity{{Ref: ref, Props: props}}
	case "rels":
		seen := map[string]bool{}
		for i, par := range el.Parents {
			pn, valid := canon(par.ID)
			if !valid || i >= len(p.Found) || !p.Found[i] {
				out.Notes = append(out.Notes, source.Note{Kind: "unresolved", ID: "CWE-" + par.ID,
					Text: fmt.Sprintf("ChildOf parent %s of %s (view %s) is not in the catalog; relationship skipped", par.ID, key, par.View)})
				continue
			}
			id := pn + "|" + par.View
			if seen[id] {
				continue
			}
			seen[id] = true
			out.Rels = append(out.Rels, source.Rel{
				From: ref, To: source.Ref{Kind: source.RefCWE, Raw: "CWE-" + pn},
				Type: "CHILD_OF", Key: map[string]any{"viewID": par.View},
			})
		}
		out.Anchor = &ref
		out.Owned = []source.OwnedRel{{Type: "CHILD_OF"}}
	default:
		return source.Normalized{}, fmt.Errorf("cwe record %s: unknown phase %q", rec.ID, p.Phase)
	}
	return out, nil
}
