// Package nvd is the NVD Source_Adapter (Requirement 5). It reads the NVD CVE
// API 2.0 and supports three modes selected in Fetch:
//
//   - sample: the first N records without date filters (Requirement 12.4);
//   - full catch-up: every record without date filters, resumable;
//   - incremental: records modified since the Checkpoint, in windows of at
//     most 120 days.
package nvd

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
const Name = "nvd"

const (
	// Endpoint is the NVD CVE API 2.0 URL.
	Endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	// Host is the only host the default client may reach.
	Host = "services.nvd.nist.gov"
	// MaxPageSize is the largest resultsPerPage NVD accepts.
	MaxPageSize = 2000
	// MaxWindow is the longest lastMod window NVD accepts.
	MaxWindow = 120 * 24 * time.Hour

	keyedLimit   = 50
	keylessLimit = 5
	limitWindow  = 30 * time.Second

	fullPrefix = "full@"
	winPrefix  = "win:"
	dateLayout = "2006-01-02T15:04:05.000"
)

// Options configures the adapter. Zero values select production defaults.
type Options struct {
	BaseURL string // default Endpoint
	APIKey  string // sent in the apiKey header when not empty
	Version string // product version for the User-Agent, default "dev"
	// Client defaults to a client restricted to Host.
	Client  *http.Client
	Clock   httpx.Clock // default RealClock
	Limiter *httpx.RollingLimiter
	Policy  *httpx.Policy // default httpx.NVDPolicy
	Log     *slog.Logger
	// PageSize is resultsPerPage for full and incremental runs, at most
	// MaxPageSize (default MaxPageSize). Tests use it to force several pages.
	PageSize int
}

// Adapter implements source.Adapter for NVD.
type Adapter struct {
	base    string
	key     string
	ua      string
	client  *http.Client
	clock   httpx.Clock
	limiter *httpx.RollingLimiter
	policy  httpx.Policy
	log     *slog.Logger
	page    int
	warn    sync.Once
}

// New returns the adapter.
func New(o Options) *Adapter {
	a := &Adapter{base: o.BaseURL, key: o.APIKey, client: o.Client, clock: o.Clock, limiter: o.Limiter, policy: httpx.NVDPolicy, log: o.Log}
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
	if a.limiter == nil {
		n := keylessLimit
		if a.key != "" {
			n = keyedLimit
		}
		a.limiter = httpx.NewRollingLimiter(n, limitWindow, a.clock)
	}
	a.page = MaxPageSize
	if o.PageSize > 0 && o.PageSize < MaxPageSize {
		a.page = o.PageSize
	}
	if o.Policy != nil {
		a.policy = *o.Policy
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	return a
}

// Name implements source.Adapter.
func (a *Adapter) Name() string { return Name }

var _ source.Totaler = (*Adapter)(nil)

// Totals implements source.Totaler. It asks NVD for one record twice and reads
// totalResults: "cves" counts every CVE, "cvesNotRejected" excludes rejected
// ones (noRejected). The requests use the adapter's client, limiter and policy.
func (a *Adapter) Totals(ctx context.Context) (map[string]int64, error) {
	out := map[string]int64{}
	for _, c := range []struct {
		key        string
		noRejected bool
	}{{"cves", false}, {"cvesNotRejected", true}} {
		q := url.Values{}
		q.Set("resultsPerPage", "1")
		q.Set("startIndex", "0")
		u := a.base + "?" + q.Encode()
		if c.noRejected {
			u += "&noRejected" // a flag parameter without a value
		}
		var pg page
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
			return nil, fmt.Errorf("nvd: totals %s: %w", c.key, err)
		}
		out[c.key] = int64(pg.total)
	}
	return out, nil
}

// Fetch implements source.Adapter. SampleLimit > 0 selects the sample rule and
// ignores cp; SampleOrder "latest" takes the last SampleLimit records instead
// of the first. Otherwise a Resume of the form full@... or an empty Checkpoint
// selects the full catch-up, and a Watermark selects incremental windows.
func (a *Adapter) Fetch(ctx context.Context, cp source.Checkpoint, opts source.RunOptions) (source.Iterator, error) {
	if a.key == "" {
		a.warn.Do(func() {
			a.log.Warn("NVD_API_KEY is not set; requests are limited to 5 per 30 seconds")
		})
	}
	it := &iter{a: a}
	switch {
	case opts.SampleLimit > 0:
		it.mode = modeSample
		it.limit = opts.SampleLimit
		it.pageSize = min(MaxPageSize, opts.SampleLimit)
		if opts.SampleOrder == source.SampleLatest {
			// Read totalResults with a one-record request, then start so that
			// the last SampleLimit records remain (ascending index order).
			it.pageSize = 1
			pg, err := it.request(ctx)
			if err != nil {
				return nil, err
			}
			it.total, it.haveTot = pg.total, true
			it.next = max(0, pg.total-opts.SampleLimit)
			it.pageSize = min(MaxPageSize, opts.SampleLimit)
		}
	case strings.HasPrefix(cp.Resume, fullPrefix):
		ts, idx, err := parseResume(cp.Resume, fullPrefix)
		if err != nil {
			return nil, err
		}
		it.mode, it.fullStart, it.next, it.pageSize = modeFull, ts, idx, a.page
	case cp.Watermark.IsZero():
		it.mode, it.fullStart, it.pageSize = modeFull, a.clock.Now().UTC(), a.page
	default:
		it.mode, it.pageSize = modeWindow, a.page
		it.now = a.clock.Now().UTC().Truncate(time.Millisecond)
		it.winStart = cp.Watermark.UTC().Truncate(time.Millisecond)
		if strings.HasPrefix(cp.Resume, winPrefix) {
			ts, idx, err := parseResume(cp.Resume, winPrefix)
			if err != nil {
				return nil, err
			}
			it.winStart, it.next = ts, idx
		}
		it.setWindow()
	}
	return it, nil
}

func parseResume(s, prefix string) (time.Time, int, error) {
	body := strings.TrimPrefix(s, prefix)
	i := strings.LastIndex(body, ":")
	if i < 0 {
		return time.Time{}, 0, fmt.Errorf("nvd: invalid resume cursor %q", s)
	}
	ts, err := time.Parse(time.RFC3339Nano, body[:i])
	idx, err2 := strconv.Atoi(body[i+1:])
	if err != nil || err2 != nil || idx < 0 {
		return time.Time{}, 0, fmt.Errorf("nvd: invalid resume cursor %q", s)
	}
	return ts.UTC(), idx, nil
}

type mode int

const (
	modeSample mode = iota
	modeFull
	modeWindow
)

type iter struct {
	a        *Adapter
	mode     mode
	pageSize int

	// paging
	next    int // next startIndex to request
	total   int
	haveTot bool
	buf     []rawRec
	pos     int
	bufBase int // startIndex of buf[0]
	emitted int // records returned in sample mode
	limit   int // sample limit
	done    bool
	pending []source.Record

	// full catch-up
	fullStart time.Time

	// incremental
	now      time.Time
	winStart time.Time
	winEnd   time.Time
}

type rawRec struct {
	id  string
	raw json.RawMessage
}

func (it *iter) setWindow() {
	it.winEnd = it.winStart.Add(MaxWindow - time.Millisecond)
	if it.winEnd.After(it.now) {
		it.winEnd = it.now
	}
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
			r := it.buf[it.pos]
			it.pos++
			it.emitted++
			return source.Record{ID: r.id, Payload: r.raw, Cursor: it.cursorAfter(it.bufBase + it.pos)}, nil
		}
		if it.done {
			return source.Record{}, io.EOF
		}
		if err := it.advance(ctx); err != nil {
			return source.Record{}, err
		}
	}
}

// cursorAfter is the state after the record that makes the next index n.
func (it *iter) cursorAfter(n int) source.Cursor {
	switch it.mode {
	case modeFull:
		return source.Cursor{Resume: fmt.Sprintf("%s%s:%d", fullPrefix, it.fullStart.Format(time.RFC3339Nano), n)}
	case modeWindow:
		return source.Cursor{Resume: fmt.Sprintf("%s%s:%d", winPrefix, it.winStart.Format(dateLayout+"Z"), n)}
	}
	return source.Cursor{}
}

// advance loads the next page or finishes the current scope.
func (it *iter) advance(ctx context.Context) error {
	it.buf, it.pos = nil, 0
	if it.mode == modeSample && it.emitted >= it.limit {
		it.done = true
		return nil
	}
	if it.haveTot && it.next >= it.total {
		it.finishScope()
		return nil
	}
	pg, err := it.request(ctx)
	if err != nil {
		return err
	}
	it.total, it.haveTot = pg.total, true
	recs := pg.recs
	if it.mode == modeSample && len(recs) > it.limit-it.emitted {
		recs = recs[:it.limit-it.emitted]
	}
	if len(recs) == 0 {
		it.finishScope()
		return nil
	}
	it.buf, it.bufBase = recs, it.next
	it.next += len(pg.recs)
	return nil
}

// finishScope ends the sample or full run, or the current window.
func (it *iter) finishScope() {
	switch it.mode {
	case modeSample:
		it.done = true
	case modeFull:
		it.pending = append(it.pending, source.Record{Cursor: source.Cursor{Watermark: it.fullStart}})
		it.done = true
	case modeWindow:
		it.pending = append(it.pending, source.Record{Cursor: source.Cursor{Watermark: it.winEnd}})
		it.winStart = it.winEnd.Add(time.Millisecond)
		it.next, it.total, it.haveTot = 0, 0, false
		if it.winStart.After(it.now) {
			it.done = true
			return
		}
		it.setWindow()
	}
}

type page struct {
	total int
	recs  []rawRec
}

// where describes the request for error messages.
func (it *iter) where() string {
	if it.mode == modeWindow {
		return fmt.Sprintf("window %s to %s startIndex %d", it.winStart.Format(dateLayout+"Z"), it.winEnd.Format(dateLayout+"Z"), it.next)
	}
	return fmt.Sprintf("startIndex %d", it.next)
}

func (it *iter) request(ctx context.Context) (page, error) {
	q := url.Values{}
	q.Set("startIndex", strconv.Itoa(it.next))
	q.Set("resultsPerPage", strconv.Itoa(it.pageSize))
	if it.mode == modeWindow {
		q.Set("lastModStartDate", it.winStart.Format(dateLayout)+"+00:00")
		q.Set("lastModEndDate", it.winEnd.Format(dateLayout)+"+00:00")
	}
	u := it.a.base + "?" + q.Encode()
	var pg page
	var last error
	err := httpx.Do(ctx, it.a.policy, it.a.clock, func(attempt int) error {
		var err error
		pg, err = it.a.get(ctx, u)
		last = err
		return err
	})
	if err != nil {
		if last != nil {
			err = last
		}
		return page{}, fmt.Errorf("nvd: %s: %w", it.where(), err)
	}
	return pg, nil
}

// StatusError is an unexpected HTTP status.
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("last response status %d", e.Code) }

func (a *Adapter) get(ctx context.Context, u string) (page, error) {
	if err := a.limiter.Wait(ctx); err != nil {
		return page{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return page{}, err
	}
	req.Header.Set("User-Agent", a.ua)
	req.Header.Set("Accept", "application/json")
	if a.key != "" {
		req.Header.Set("apiKey", a.key)
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
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		se := &StatusError{Code: resp.StatusCode}
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
	return pg, nil
}

// decodePage streams the response with a json.Decoder, one vulnerability at a
// time, and keeps only each CVE object.
func decodePage(r io.Reader) (page, error) {
	dec := json.NewDecoder(r)
	var pg page
	if err := expectDelim(dec, '{'); err != nil {
		return pg, err
	}
	seenTotal := false
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return pg, err
		}
		key, _ := t.(string)
		switch key {
		case "totalResults":
			if err := dec.Decode(&pg.total); err != nil {
				return pg, fmt.Errorf("totalResults: %w", err)
			}
			seenTotal = true
		case "vulnerabilities":
			t, err := dec.Token()
			if err != nil {
				return pg, err
			}
			if t == nil { // "vulnerabilities": null
				continue
			}
			if d, ok := t.(json.Delim); !ok || d != '[' {
				return pg, fmt.Errorf("vulnerabilities: unexpected token %v", t)
			}
			for dec.More() {
				var e struct {
					CVE json.RawMessage `json:"cve"`
				}
				if err := dec.Decode(&e); err != nil {
					return pg, err
				}
				var h struct {
					ID string `json:"id"`
				}
				if err := json.Unmarshal(e.CVE, &h); err != nil {
					return pg, err
				}
				pg.recs = append(pg.recs, rawRec{id: h.ID, raw: e.CVE})
			}
			if err := expectDelim(dec, ']'); err != nil {
				return pg, err
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return pg, err
			}
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return pg, err
	}
	if !seenTotal {
		return pg, errors.New("response has no totalResults")
	}
	return pg, nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != want {
		return fmt.Errorf("unexpected JSON token %v, want %q", t, want)
	}
	return nil
}
