// Package ghsa is the GitHub Security Advisories Source_Adapter (Requirement
// 14). It reads the reviewed global advisories of the GitHub REST API
// (GET /advisories), oldest update first, and resumes by the `after` cursor
// of the Link header.
//
// The token (Options.Token) is sent only in the Authorization header. It is
// never logged, never part of an error, and never stored in a Checkpoint.
//
// No Totaler: the API gives cursor links only (no total count and no `last`
// page), so a count would need a full crawl.
package ghsa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/httpx"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
)

// Name is the adapter name.
const Name = "ghsa"

const (
	// Endpoint is the GitHub REST URL of the global security advisories.
	Endpoint = "https://api.github.com/advisories"
	// Host is the only host the default client may reach.
	Host = "api.github.com"
	// APIVersion is sent in the X-GitHub-Api-Version header.
	APIVersion = "2022-11-28"
	// MaxPageSize is the largest per_page GitHub accepts.
	MaxPageSize = 100

	resumePrefix = "v1|"
	sinceLayout  = time.RFC3339
	// maxLimitWaits bounds consecutive waits for one rate-limit window.
	maxLimitWaits = 5
	// resetMargin is added to the reset time so the window has surely opened.
	resetMargin = time.Second
)

// Options configures the adapter. Zero values select production defaults.
type Options struct {
	BaseURL string // default Endpoint
	// Token is a GitHub token; sent as a Bearer token only when not empty.
	Token   string
	Version string // product version for the User-Agent, default "dev"
	// Client defaults to a client restricted to Host.
	Client *http.Client
	Clock  httpx.Clock   // default RealClock
	Policy *httpx.Policy // default httpx.OSVPolicy
	Log    *slog.Logger
	// PageSize is per_page, at most MaxPageSize (default MaxPageSize).
	PageSize int
}

// Adapter implements source.Adapter for GHSA.
type Adapter struct {
	base   string
	token  string
	ua     string
	client *http.Client
	clock  httpx.Clock
	policy httpx.Policy
	log    *slog.Logger
	page   int
	warn   sync.Once

	mu        sync.Mutex
	remaining int // X-RateLimit-Remaining of the last response; -1 unknown
	reset     time.Time
}

// New returns the adapter.
func New(o Options) *Adapter {
	a := &Adapter{
		base: o.BaseURL, token: strings.TrimSpace(o.Token), client: o.Client, clock: o.Clock,
		policy: httpx.OSVPolicy, log: o.Log, remaining: -1,
	}
	if a.base == "" {
		a.base = Endpoint
	}
	v := o.Version
	if v == "" {
		v = "dev"
	}
	a.ua = "bskg/" + v
	if a.client == nil {
		a.client = httpx.NewAllowList(Host).NewClient(120 * time.Second)
	}
	if a.clock == nil {
		a.clock = httpx.RealClock{}
	}
	if o.Policy != nil {
		a.policy = *o.Policy
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	a.page = MaxPageSize
	if o.PageSize > 0 && o.PageSize < MaxPageSize {
		a.page = o.PageSize
	}
	return a
}

// Name implements source.Adapter.
func (a *Adapter) Name() string { return Name }

// EncodeResume builds the Checkpoint.Resume string: the lower bound of the
// `updated` filter of the run and the `after` cursor of the page to read next.
// Both are public query values (no secret).
func EncodeResume(since time.Time, after string) string {
	s := ""
	if !since.IsZero() {
		s = since.UTC().Format(sinceLayout)
	}
	return resumePrefix + s + "|" + after
}

func parseResume(r string) (time.Time, string, error) {
	bad := func() (time.Time, string, error) {
		return time.Time{}, "", fmt.Errorf("ghsa: invalid resume cursor %q", r)
	}
	body, ok := strings.CutPrefix(r, resumePrefix)
	if !ok {
		return bad()
	}
	s, after, ok := strings.Cut(body, "|")
	if !ok {
		return bad()
	}
	var since time.Time
	if s != "" {
		t, err := time.Parse(sinceLayout, s)
		if err != nil {
			return bad()
		}
		since = t.UTC()
	}
	return since, after, nil
}

// Fetch implements source.Adapter. SampleLimit > 0 ignores cp and returns the
// first N reviewed advisories without moving the cursor. Otherwise a Resume
// continues an interrupted run; else the Watermark is the lower bound of
// `updated`; else all reviewed advisories are read.
func (a *Adapter) Fetch(ctx context.Context, cp source.Checkpoint, opts source.RunOptions) (source.Iterator, error) {
	if a.token == "" {
		a.warn.Do(func() {
			a.log.Warn("GITHUB_TOKEN is not set; the GitHub API allows 60 requests per hour without a token")
		})
	}
	it := &iter{a: a, pageSize: a.page}
	switch {
	case opts.SampleLimit > 0:
		it.sample, it.limit = true, opts.SampleLimit
		it.pageSize = min(a.page, opts.SampleLimit)
	case cp.Resume != "":
		since, after, err := parseResume(cp.Resume)
		if err != nil {
			return nil, err
		}
		it.since, it.after = since, after
		it.max = cp.Watermark
	default:
		it.since = cp.Watermark.UTC().Truncate(time.Second)
		it.max = cp.Watermark
	}
	return it, nil
}

type iter struct {
	a        *Adapter
	pageSize int
	since    time.Time
	sample   bool
	limit    int
	emitted  int
	skipped  int

	after     string // cursor of the page in buf
	nextAfter string
	hasNext   bool
	started   bool
	buf       []rawRec
	pos       int
	max       time.Time // greatest updated_at handed out
	done      bool
	pending   []source.Record
}

type rawRec struct {
	id      string
	updated time.Time // zero when missing or invalid
	raw     json.RawMessage
}

// Next implements source.Iterator.
func (it *iter) Next(ctx context.Context) (source.Record, error) {
	for {
		if len(it.pending) > 0 {
			r := it.pending[0]
			it.pending = it.pending[1:]
			return r, nil
		}
		if it.pos < len(it.buf) {
			return it.emit(), nil
		}
		if it.done {
			return source.Record{}, io.EOF
		}
		if it.started && (!it.hasNext || (it.sample && it.emitted >= it.limit)) {
			it.finish()
			continue
		}
		if err := it.advance(ctx); err != nil {
			return source.Record{}, err
		}
	}
}

// emit returns the next buffered record with the cursor after it.
func (it *iter) emit() source.Record {
	r := it.buf[it.pos]
	it.pos++
	it.emitted++
	rec := source.Record{ID: r.id, Payload: r.raw}
	if r.updated.IsZero() {
		it.skipped++
	} else if r.updated.After(it.max) {
		it.max = r.updated
	}
	if it.sample {
		return rec
	}
	rec.Cursor.Watermark = it.max
	if it.pos == len(it.buf) && it.hasNext {
		rec.Cursor.Resume = EncodeResume(it.since, it.nextAfter)
	} else {
		rec.Cursor.Resume = EncodeResume(it.since, it.after)
	}
	return rec
}

// finish ends the run; a full or incremental run ends with a marker that
// clears the Resume and sets the Watermark.
func (it *iter) finish() {
	if it.skipped > 0 {
		it.a.log.Warn("ghsa: skipped advisories without ghsa_id or updated_at", "count", it.skipped)
	}
	if !it.sample {
		it.pending = append(it.pending, source.Record{Cursor: source.Cursor{Watermark: it.max}})
	}
	it.done = true
}

// advance loads the next page.
func (it *iter) advance(ctx context.Context) error {
	if it.started {
		it.after = it.nextAfter
	}
	pg, err := it.request(ctx)
	if err != nil {
		return err
	}
	it.started = true
	it.buf, it.pos = pg.recs, 0
	if it.sample && len(it.buf) > it.limit-it.emitted {
		it.buf = it.buf[:it.limit-it.emitted]
	}
	it.nextAfter, it.hasNext = pg.next, pg.next != ""
	if len(pg.recs) == 0 {
		it.hasNext = false
	}
	return nil
}

type page struct {
	recs []rawRec
	next string // the `after` value of rel="next", empty at the last page
}

func (it *iter) query() string {
	q := url.Values{}
	q.Set("type", "reviewed")
	q.Set("per_page", strconv.Itoa(it.pageSize))
	q.Set("sort", "updated")
	q.Set("direction", "asc")
	if !it.since.IsZero() {
		q.Set("updated", ">="+it.since.UTC().Format(sinceLayout))
	}
	if it.after != "" {
		q.Set("after", it.after)
	}
	return q.Encode()
}

func (it *iter) request(ctx context.Context) (page, error) {
	u := it.a.base + "?" + it.query()
	where := "first page"
	if it.after != "" {
		where = "page after " + it.after
	}
	a := it.a
	var pg page
	for waits := 0; ; waits++ {
		var last error
		err := httpx.Do(ctx, a.policy, a.clock, func(int) error {
			var err error
			pg, err = a.get(ctx, u)
			last = err
			return err
		})
		if err != nil {
			if last != nil {
				err = last
			}
			var rl *rateLimitError
			if errors.As(err, &rl) && waits < maxLimitWaits {
				continue // get recorded the reset time; the next get waits for it
			}
			return page{}, fmt.Errorf("ghsa: %s: %w", where, err)
		}
		return pg, nil
	}
}

// StatusError is an unexpected HTTP status.
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("last response status %d", e.Code) }

type rateLimitError struct{ Code int }

func (e *rateLimitError) Error() string {
	return fmt.Sprintf("rate limit exhausted (status %d)", e.Code)
}

// waitForLimit sleeps until the reset time when the last response said that
// no requests remain (Requirement 14.3).
func (a *Adapter) waitForLimit(ctx context.Context) error {
	a.mu.Lock()
	rem, reset := a.remaining, a.reset
	a.mu.Unlock()
	if rem != 0 {
		return nil
	}
	d := reset.Sub(a.clock.Now()) + resetMargin
	if d < resetMargin {
		d = resetMargin
	}
	a.log.Info("ghsa: GitHub rate limit reached, waiting for the reset", "seconds", int64(d/time.Second))
	if err := a.clock.Sleep(ctx, d); err != nil {
		return err
	}
	a.mu.Lock()
	a.remaining = -1
	a.mu.Unlock()
	return nil
}

func (a *Adapter) noteLimit(h http.Header) {
	rem, err := strconv.Atoi(h.Get("X-RateLimit-Remaining"))
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.remaining = rem
	if ts, err := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64); err == nil {
		a.reset = time.Unix(ts, 0)
	}
}

func (a *Adapter) get(ctx context.Context, u string) (page, error) {
	if err := a.waitForLimit(ctx); err != nil {
		return page{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return page{}, err
	}
	req.Header.Set("User-Agent", a.ua)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", APIVersion)
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		var he *httpx.HostNotAllowedError
		if ctx.Err() != nil || errors.As(err, &he) {
			return page{}, err
		}
		return page{}, httpx.Retryable(err)
	}
	defer resp.Body.Close()
	a.noteLimit(resp.Header)
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		se := &StatusError{Code: resp.StatusCode}
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			ra := httpx.ParseRetryAfter(resp.Header.Get("Retry-After"), a.clock.Now())
			a.mu.Lock()
			exhausted := a.remaining == 0
			a.mu.Unlock()
			if ra == 0 && exhausted {
				return page{}, &rateLimitError{Code: resp.StatusCode}
			}
			// Secondary limit (Retry-After) or a transient 403 or 429.
			return page{}, &httpx.RetryableError{Err: se, RetryAfter: ra}
		}
		if httpx.IsRetryableStatus(resp.StatusCode) {
			ra := httpx.ParseRetryAfter(resp.Header.Get("Retry-After"), a.clock.Now())
			return page{}, &httpx.RetryableError{Err: se, RetryAfter: ra}
		}
		return page{}, se
	}
	pg, err := decodePage(resp.Body)
	if err != nil {
		if ctx.Err() != nil {
			return page{}, err
		}
		return page{}, httpx.Retryable(err)
	}
	next, err := nextAfter(resp.Header.Values("Link"))
	if err != nil {
		return page{}, err
	}
	pg.next = next
	return pg, nil
}

// nextAfter returns the `after` cursor of the rel="next" link, or "" when the
// response has none. Only the cursor is used, never the URL, so the adapter
// cannot be sent to another host.
func nextAfter(links []string) (string, error) {
	for _, h := range links {
		for _, part := range strings.Split(h, ",") {
			target, params, ok := strings.Cut(part, ";")
			if !ok || !strings.Contains(params, `rel="next"`) {
				continue
			}
			target = strings.Trim(strings.TrimSpace(target), "<>")
			u, err := url.Parse(target)
			if err != nil {
				return "", errors.New("ghsa: unreadable next link")
			}
			after := u.Query().Get("after")
			if after == "" {
				return "", errors.New("ghsa: next link without an after cursor")
			}
			return after, nil
		}
	}
	return "", nil
}

// decodePage streams the JSON array, one advisory at a time.
func decodePage(r io.Reader) (page, error) {
	dec := json.NewDecoder(r)
	var pg page
	t, err := dec.Token()
	if err != nil {
		return pg, err
	}
	if d, ok := t.(json.Delim); !ok || d != '[' {
		return pg, fmt.Errorf("unexpected JSON token %v, want an array", t)
	}
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return pg, err
		}
		var h struct {
			ID      string `json:"ghsa_id"`
			Updated string `json:"updated_at"`
			URL     string `json:"html_url"`
		}
		if err := json.Unmarshal(raw, &h); err != nil {
			return pg, err
		}
		rec := rawRec{id: h.ID, raw: raw}
		if rec.id == "" {
			rec.id = h.URL
		}
		if t, err := time.Parse(time.RFC3339, h.Updated); err == nil && h.ID != "" {
			rec.updated = t.UTC()
		}
		pg.recs = append(pg.recs, rec)
	}
	if _, err := dec.Token(); err != nil {
		return pg, err
	}
	return pg, nil
}
