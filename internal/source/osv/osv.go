// Package osv is the OSV Source_Adapter (Requirement 14.1, 14.4 to 14.8 and
// Requirement 15). It reads the OSV.dev bulk exports per ecosystem:
//
//	<base>/<ECOSYSTEM>/all.zip          every record of the ecosystem
//	<base>/<ECOSYSTEM>/modified_id.csv  "<modified>,<id>" lines, newest first
//
// Each zip is downloaded to the cache directory and its entries are read one
// at a time, so memory use does not depend on the size of the ecosystem.
//
// # Checkpoint encoding
//
// The per-ecosystem modified-time high-water marks live in Checkpoint.Resume
// as one JSON object (Checkpoint.Version and Checkpoint.Watermark stay empty,
// so no "same version" shortcut applies):
//
//	{"v":1,
//	 "marks":{"npm":"2026-11-21T12:30:14.560451276Z","PyPI":"..."},
//	 "licenses":{"npm":"CC-BY-4.0 (GitHub Advisory Database); Apache-2.0 (...)"}}
//
// A mark is an RFC 3339 UTC time: the largest `modified` found in the
// ecosystem's zip. A run emits a record only when its `modified` is after the
// mark of its ecosystem (every record when the ecosystem has no mark). A mark
// moves only when its ecosystem was read to the end; an ecosystem that failed
// keeps its old mark. Every record carries the marks that are final at that
// point, and a cursor-only record follows each finished ecosystem, so the
// pipeline stores a mark as soon as the batch with that marker commits.
// Marks of ecosystems that are no longer configured are kept.
// "licenses" records, per finished ecosystem, the licence and attribution
// string of Licenses (Requirement 14.5).
package osv

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bellu/bskg/internal/httpx"
	"github.com/bellu/bskg/internal/resolve"
	"github.com/bellu/bskg/internal/source"
	"github.com/bellu/bskg/internal/source/fetch"
)

// Name is the adapter name.
const Name = "osv"

const (
	// Host is the only host the default client may reach.
	Host = "osv-vulnerabilities.storage.googleapis.com"
	// BaseURL is the root of the OSV.dev bulk export bucket.
	BaseURL = "https://" + Host

	// MaxZipBytes caps one ecosystem download (npm is about 222 MB).
	MaxZipBytes = 1 << 30
	// MaxEntryBytes caps one record inside a zip.
	MaxEntryBytes = 16 << 20

	stateVersion = 1
)

// Options configures the adapter.
type Options struct {
	// Ecosystems are the OSV ecosystem names to load, in order
	// (BSKG_OSV_ECOSYSTEMS). Names with a space are URL-escaped.
	Ecosystems []string
	// CacheDir receives the zip downloads (BSKG_CACHE_DIR).
	CacheDir string
	// Version is the product version for the User-Agent, default "dev".
	Version string
	// BaseURL replaces BaseURL (tests).
	BaseURL string
	// Client defaults to a client restricted to Host.
	Client *http.Client
	// Clock is the retry clock, default RealClock.
	Clock httpx.Clock
	// Policy defaults to httpx.OSVPolicy (3 retries from 1 s).
	Policy *httpx.Policy
}

// Adapter implements source.Adapter and source.Totaler for OSV.
type Adapter struct {
	base   string
	ecos   []string
	cache  string
	ua     string
	client *http.Client
	clock  httpx.Clock
	policy httpx.Policy

	mu     sync.Mutex
	counts map[string]int64 // records per ecosystem, from zips read to the end
	csv    map[string]int64 // lines of modified_id.csv, cached by Totals
}

var (
	_ source.Adapter = (*Adapter)(nil)
	_ source.Totaler = (*Adapter)(nil)
)

// New returns the adapter.
func New(o Options) *Adapter {
	a := &Adapter{
		base: strings.TrimRight(o.BaseURL, "/"), cache: o.CacheDir,
		client: o.Client, clock: o.Clock, policy: httpx.OSVPolicy,
		counts: map[string]int64{},
	}
	if a.base == "" {
		a.base = BaseURL
	}
	if a.client == nil {
		a.client = httpx.NewAllowList(Host).NewClient(0)
	}
	if a.clock == nil {
		a.clock = httpx.RealClock{}
	}
	if o.Policy != nil {
		a.policy = *o.Policy
	}
	v := o.Version
	if v == "" {
		v = "dev"
	}
	a.ua = "bskg/" + v
	seen := map[string]bool{}
	for _, e := range o.Ecosystems {
		e = strings.TrimSpace(e)
		if e != "" && !seen[e] {
			seen[e] = true
			a.ecos = append(a.ecos, e)
		}
	}
	return a
}

// Name implements source.Adapter.
func (a *Adapter) Name() string { return Name }

// state is the decoded Checkpoint.Resume.
type state struct {
	V        int               `json:"v"`
	Marks    map[string]string `json:"marks,omitempty"`
	Licenses map[string]string `json:"licenses,omitempty"`
}

func decodeState(resume string) (state, error) {
	st := state{V: stateVersion, Marks: map[string]string{}, Licenses: map[string]string{}}
	if resume == "" {
		return st, nil
	}
	var in state
	if err := json.Unmarshal([]byte(resume), &in); err != nil {
		return st, fmt.Errorf("osv: invalid checkpoint: %w", err)
	}
	for k, v := range in.Marks {
		if _, err := time.Parse(time.RFC3339Nano, v); err != nil {
			return st, fmt.Errorf("osv: invalid checkpoint mark for %q: %w", k, err)
		}
		st.Marks[k] = v
	}
	for k, v := range in.Licenses {
		st.Licenses[k] = v
	}
	return st, nil
}

func (s state) encode() string {
	b, _ := json.Marshal(s) // maps of strings never fail; keys are sorted
	return string(b)
}

// Fetch implements source.Adapter. It does no network I/O itself: each
// ecosystem is downloaded when the iterator reaches it, so a sample build
// that ends early downloads only what it needs.
func (a *Adapter) Fetch(ctx context.Context, cp source.Checkpoint, opts source.RunOptions) (source.Iterator, error) {
	st := state{V: stateVersion, Marks: map[string]string{}, Licenses: map[string]string{}}
	if opts.SampleLimit <= 0 {
		var err error
		if st, err = decodeState(cp.Resume); err != nil {
			return nil, err
		}
	}
	it := &iter{a: a, st: st, limit: opts.SampleLimit}
	it.resume = st.encode()
	return it, nil
}

// iter walks the configured ecosystems in order.
type iter struct {
	a      *Adapter
	st     state
	resume string
	limit  int // sample limit, 0 for none

	idx     int
	emitted int
	cur     *ecoRun
	queue   []source.Record
	done    bool
}

// ecoRun is the ecosystem being read.
type ecoRun struct {
	name    string
	path    string
	zr      *zip.ReadCloser
	i       int
	mark    time.Time
	hasMark bool
	max     time.Time
	count   int64
}

// payload markers for records that are not OSV records.
type failurePayload struct {
	Failure string `json:"osvFailure"`
	Eco     string `json:"ecosystem"`
}

func (it *iter) Next(ctx context.Context) (source.Record, error) {
	for {
		if err := ctx.Err(); err != nil {
			it.closeCur()
			return source.Record{}, err
		}
		if len(it.queue) > 0 {
			r := it.queue[0]
			it.queue = it.queue[1:]
			return r, nil
		}
		if it.done {
			return source.Record{}, io.EOF
		}
		if it.limit > 0 && it.emitted >= it.limit {
			it.closeCur()
			it.done = true
			return source.Record{}, io.EOF
		}
		if it.cur == nil {
			if it.idx >= len(it.a.ecos) {
				it.done = true
				return source.Record{}, io.EOF
			}
			eco := it.a.ecos[it.idx]
			it.idx++
			it.start(ctx, eco)
			continue
		}
		rec, ok, err := it.readEntry()
		if err != nil {
			if ctx.Err() != nil {
				it.closeCur()
				return source.Record{}, ctx.Err()
			}
			it.fail(it.cur.name, err)
			it.closeCur()
			continue
		}
		if !ok { // end of the zip
			it.finish()
			continue
		}
		if rec.ID == "" {
			continue // filtered out (older than the mark)
		}
		it.emitted++
		return rec, nil
	}
}

// fail queues the failure record of an ecosystem: Normalize rejects it, so the
// run ends succeeded_with_errors and the reason is in the dead-letter list.
func (it *iter) fail(eco string, err error) {
	b, _ := json.Marshal(failurePayload{Failure: truncateRunes(err.Error(), 500), Eco: eco})
	it.queue = append(it.queue, source.Record{
		ID: "osv-ecosystem:" + eco, Payload: b,
		Cursor: source.Cursor{Resume: it.resume},
	})
}

// start prepares an ecosystem: the modified_id.csv shortcut, the download and
// the zip. Any failure aborts only this ecosystem.
func (it *iter) start(ctx context.Context, eco string) {
	a := it.a
	if _, ok := resolve.OSVEcosystemType(eco); !ok {
		it.fail(eco, fmt.Errorf("unsupported OSV ecosystem %q", eco))
		return
	}
	run := &ecoRun{name: eco}
	if m, ok := it.st.Marks[eco]; ok && it.limit == 0 {
		run.mark, _ = time.Parse(time.RFC3339Nano, m)
		run.hasMark = true
		// modified_id.csv lists the newest record first. If it holds nothing
		// after the mark the zip is not needed. Any problem with the file
		// falls back to the zip.
		if latest, err := a.latestModified(ctx, eco); err == nil && !latest.After(run.mark) {
			it.markFinished(eco, run.mark)
			return
		}
	}
	res, err := fetch.DownloadWith(ctx, a.client, a.ecoURL(eco, "all.zip"), a.cache, cacheName(eco),
		a.policy, a.clock, fetch.Options{Header: http.Header{"User-Agent": {a.ua}}, MaxBytes: MaxZipBytes})
	if err != nil {
		it.fail(eco, fmt.Errorf("download all.zip: %w", err))
		return
	}
	run.path = res.Path
	zr, err := zip.OpenReader(res.Path)
	if err != nil {
		_ = os.Remove(res.Path)
		it.fail(eco, fmt.Errorf("open all.zip: %w", err))
		return
	}
	run.zr = zr
	it.cur = run
}

func (it *iter) closeCur() {
	if it.cur == nil {
		return
	}
	if it.cur.zr != nil {
		_ = it.cur.zr.Close()
	}
	// A zip that was read to the end or failed is not needed again; the next
	// download replaces it anyway. Keep the cache small.
	if it.cur.path != "" {
		_ = os.Remove(it.cur.path)
	}
	it.cur = nil
}

// finish advances the mark of the current ecosystem and queues a cursor
// marker that carries it.
func (it *iter) finish() {
	run := it.cur
	mark := run.max
	if run.hasMark && run.mark.After(mark) {
		mark = run.mark
	}
	count := run.count
	name := run.name
	it.closeCur()
	it.a.mu.Lock()
	it.a.counts[name] = count
	it.a.mu.Unlock()
	it.markFinished(name, mark)
}

func (it *iter) markFinished(eco string, mark time.Time) {
	if it.limit > 0 {
		return
	}
	if !mark.IsZero() {
		it.st.Marks[eco] = mark.UTC().Format(time.RFC3339Nano)
	}
	if l := Licenses[eco]; l != "" {
		it.st.Licenses[eco] = l
	} else {
		it.st.Licenses[eco] = "unspecified"
	}
	it.resume = it.st.encode()
	it.queue = append(it.queue, source.Record{
		ID: "osv-cursor:" + eco, Cursor: source.Cursor{Resume: it.resume},
	})
}

// recordHeader is the part of a record Fetch needs.
type recordHeader struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// readEntry returns the next record to emit. ok is false at the end of the
// zip. A record with an empty ID in the result was filtered out.
func (it *iter) readEntry() (source.Record, bool, error) {
	run := it.cur
	for run.i < len(run.zr.File) {
		f := run.zr.File[run.i]
		run.i++
		if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			continue
		}
		b, err := readZipEntry(f)
		if err != nil {
			return source.Record{}, false, fmt.Errorf("read %s: %w", cleanName(f.Name), err)
		}
		run.count++
		var h recordHeader
		var modified time.Time
		hok := false
		if json.Unmarshal(b, &h) == nil {
			if t, err := time.Parse(time.RFC3339Nano, h.Modified); err == nil {
				modified, hok = t.UTC(), true
			}
		}
		if hok && modified.After(run.max) {
			run.max = modified
		}
		if hok && run.hasMark && !modified.After(run.mark) {
			return source.Record{}, true, nil // unchanged since the last run
		}
		id := strings.TrimSpace(h.ID)
		if id == "" {
			id = strings.TrimSuffix(cleanName(f.Name), ".json")
		}
		return source.Record{ID: id, Payload: b, Cursor: source.Cursor{Resume: it.resume}}, true, nil
	}
	return source.Record{}, false, nil
}

func readZipEntry(f *zip.File) ([]byte, error) {
	if f.UncompressedSize64 > MaxEntryBytes {
		return nil, fmt.Errorf("entry larger than %d bytes", MaxEntryBytes)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, MaxEntryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxEntryBytes {
		return nil, fmt.Errorf("entry larger than %d bytes", MaxEntryBytes)
	}
	return b, nil
}

func cleanName(n string) string {
	if i := strings.LastIndex(n, "/"); i >= 0 {
		n = n[i+1:]
	}
	return truncateRunes(n, 200)
}

var nonAlnum = regexp.MustCompile(`[^A-Za-z0-9]+`)

func cacheName(eco string) string { return "osv-" + nonAlnum.ReplaceAllString(eco, "-") + ".zip" }

// ecoURL builds <base>/<ECOSYSTEM>/<file> with the ecosystem path-escaped.
func (a *Adapter) ecoURL(eco, file string) string {
	return a.base + "/" + url.PathEscape(eco) + "/" + file
}

// latestModified reads the first line of modified_id.csv: the newest
// modification time of the ecosystem.
func (a *Adapter) latestModified(ctx context.Context, eco string) (time.Time, error) {
	var out time.Time
	err := httpx.Do(ctx, a.policy, a.clock, func(int) error {
		resp, err := a.get(ctx, a.ecoURL(eco, "modified_id.csv"))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		line, err := bufio.NewReader(io.LimitReader(resp.Body, 4096)).ReadString('\n')
		if err != nil && !(errors.Is(err, io.EOF) && line != "") {
			if errors.Is(err, io.EOF) {
				return errors.New("modified_id.csv is empty")
			}
			return httpx.Retryable(err)
		}
		ts, _, _ := strings.Cut(strings.TrimSpace(line), ",")
		t, perr := time.Parse(time.RFC3339Nano, ts)
		if perr != nil {
			return fmt.Errorf("modified_id.csv: bad time %q", truncateRunes(ts, 40))
		}
		out = t.UTC()
		return nil
	})
	return out, err
}

// get issues one GET; retryable failures are wrapped for httpx.Do.
func (a *Adapter) get(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", a.ua)
	resp, err := a.client.Do(req)
	if err != nil {
		var denied *httpx.HostNotAllowedError
		if ctx.Err() != nil || errors.As(err, &denied) {
			return nil, err
		}
		return nil, httpx.Retryable(err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		e := fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
		if httpx.IsRetryableStatus(resp.StatusCode) {
			return nil, &httpx.RetryableError{Err: e, RetryAfter: httpx.ParseRetryAfter(resp.Header.Get("Retry-After"), a.clock.Now())}
		}
		return nil, e
	}
	return resp, nil
}

// Totals implements source.Totaler: the number of records per ecosystem and
// their sum. Keys are the ecosystem names without characters outside
// [A-Za-z0-9] ("crates.io" is "cratesio", "GitHub Actions" is
// "GitHubActions"), plus "total". An ecosystem read to the end in this process
// is counted from its zip; any other configured ecosystem is counted from the
// lines of its modified_id.csv. An ecosystem that cannot be counted is left
// out (and so is "total" when any is missing).
func (a *Adapter) Totals(ctx context.Context) (map[string]int64, error) {
	out := map[string]int64{}
	var total int64
	complete := true
	for _, eco := range a.ecos {
		key := nonAlnum.ReplaceAllString(eco, "")
		if key == "" || !(key[0] >= 'A' && key[0] <= 'Z' || key[0] >= 'a' && key[0] <= 'z') {
			continue
		}
		a.mu.Lock()
		n, ok := a.counts[eco]
		a.mu.Unlock()
		if !ok {
			var err error
			if n, err = a.countCSV(ctx, eco); err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				complete = false
				continue
			}
		}
		out[key] = n
		total += n
	}
	if complete && len(out) > 0 {
		out["total"] = total
	}
	return out, nil
}

func (a *Adapter) countCSV(ctx context.Context, eco string) (int64, error) {
	var n int64
	err := httpx.Do(ctx, a.policy, a.clock, func(int) error {
		resp, err := a.get(ctx, a.ecoURL(eco, "modified_id.csv"))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		n = 0
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) != "" {
				n++
			}
		}
		if err := sc.Err(); err != nil {
			return httpx.Retryable(err)
		}
		return nil
	})
	return n, err
}

func truncateRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
