package osv

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/fetch"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// DefaultBaseURL is the official OSV bulk-dump bucket.
const DefaultBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

const (
	maxEntryBytes       = 64 << 20
	defaultCheckpointN  = 200
	defaultLiveInterval = 100 * time.Millisecond
)

// EcosystemError reports a failure scoped to one ecosystem (Ecosystem is empty for
// failures that precede ecosystem discovery).
type EcosystemError struct {
	Ecosystem string
	Err       error
}

func (e *EcosystemError) Error() string {
	if e.Ecosystem == "" {
		return fmt.Sprintf("osv: %v", e.Err)
	}
	return fmt.Sprintf("osv: ecosystem %q failed: %v", e.Ecosystem, e.Err)
}
func (e *EcosystemError) Unwrap() error { return e.Err }

// RecordError reports one record (zip entry file name or CSV/record id) that could
// not be fetched or parsed.
type RecordError struct {
	Ecosystem string
	Name      string
	Err       error
}

func (e *RecordError) Error() string {
	return fmt.Sprintf("osv: %s: %s: %v", e.Ecosystem, e.Name, e.Err)
}
func (e *RecordError) Unwrap() error { return e.Err }

// EcosystemResult summarizes how one ecosystem was processed in the last Fetch.
type EcosystemResult struct {
	Name     string
	Method   string // "zip" or "modified_id.csv"; empty if it failed before choosing
	Resumed  bool   // continued an interrupted zip pass
	Skipped  bool   // full mode: already completed in the current full pass
	Records  int    // records yielded successfully
	Failures int    // record-level failures (parse or fetch)
	Err      error  // set when the whole ecosystem failed
}

// LiveSource ingests the official OSV bulk dumps.
type LiveSource struct {
	// BaseURL of the bucket; DefaultBaseURL when empty.
	BaseURL string
	// Ecosystems is an optional allow-list. Empty means every ecosystem in ecosystems.txt.
	Ecosystems []string
	// Checkpoints stores per-ecosystem cursors; an in-memory store is used when nil.
	Checkpoints Checkpointer
	// HTTP is the retrying, rate-limited client.
	HTTP *fetch.Client
	// CheckpointEvery is the number of records between progress saves (default 200).
	CheckpointEvery int
	// TempDir holds the downloaded archive (os.TempDir when empty).
	TempDir string

	mu      sync.Mutex
	results []EcosystemResult
}

var _ connectors.Source = (*LiveSource)(nil)

// NewLive returns a live bulk source for baseURL (DefaultBaseURL when empty).
func NewLive(baseURL string) *LiveSource {
	h := fetch.NewClient(NameOSV, false)
	_ = h.SetInterval(defaultLiveInterval)
	return &LiveSource{BaseURL: baseURL, HTTP: h, Checkpoints: NewMemoryCheckpoints()}
}

func (s *LiveSource) Name() string { return NameOSV }

// Summary returns per-ecosystem results of the most recent (or running) Fetch.
func (s *LiveSource) Summary() []EcosystemResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]EcosystemResult(nil), s.results...)
}

func (s *LiveSource) addResult(r EcosystemResult) {
	s.mu.Lock()
	s.results = append(s.results, r)
	s.mu.Unlock()
}

func (s *LiveSource) base() string {
	b := s.BaseURL
	if b == "" {
		b = DefaultBaseURL
	}
	return strings.TrimRight(b, "/")
}

func (s *LiveSource) every() int {
	if s.CheckpointEvery > 0 {
		return s.CheckpointEvery
	}
	return defaultCheckpointN
}

func (s *LiveSource) client() *fetch.Client {
	if s.HTTP == nil {
		s.HTTP = fetch.NewClient(NameOSV, false)
		_ = s.HTTP.SetInterval(defaultLiveInterval)
	}
	return s.HTTP
}

func (s *LiveSource) store() Checkpointer {
	if s.Checkpoints == nil {
		s.Checkpoints = NewMemoryCheckpoints()
	}
	return s.Checkpoints
}

// ecoURL builds <base>/<escaped ecosystem>/<escaped name>.
func (s *LiveSource) ecoURL(eco, name string) string {
	return s.base() + "/" + url.PathEscape(eco) + "/" + url.PathEscape(name)
}

func (s *LiveSource) get(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "bellu-global-intel/1.0")
	resp, err := s.client().Do(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return resp, nil
}

func (s *LiveSource) listEcosystems(ctx context.Context) ([]string, error) {
	resp, err := s.get(ctx, s.base()+"/ecosystems.txt")
	if err != nil {
		return nil, fmt.Errorf("read ecosystems.txt: %w", err)
	}
	defer resp.Body.Close()
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read ecosystems.txt: %w", err)
	}
	return out, nil
}

type emit func(connectors.Item, error) bool

// Fetch ingests every selected ecosystem. Full mode (or Incremental without a
// checkpoint) streams <eco>/all.zip; Incremental with a checkpoint reads
// <eco>/modified_id.csv and fetches only records modified after it. The since
// argument is ignored: checkpoints are per ecosystem. Failures of a single record
// yield a *RecordError, failures of a whole ecosystem yield an *EcosystemError, and
// iteration continues with the next record or ecosystem.
func (s *LiveSource) Fetch(ctx context.Context, mode connectors.Mode, _ time.Time) iter.Seq2[connectors.Item, error] {
	return func(yield func(connectors.Item, error) bool) {
		s.mu.Lock()
		s.results = nil
		s.mu.Unlock()
		listed, err := s.listEcosystems(ctx)
		if err != nil {
			yield(connectors.Item{}, &EcosystemError{Err: err})
			return
		}
		ecos := listed
		notListed := map[string]bool{}
		if len(s.Ecosystems) > 0 {
			in := map[string]bool{}
			for _, e := range listed {
				in[e] = true
			}
			ecos = nil
			seen := map[string]bool{}
			for _, e := range s.Ecosystems {
				e = strings.TrimSpace(e)
				if e == "" || seen[e] {
					continue
				}
				seen[e] = true
				ecos = append(ecos, e)
				if !in[e] {
					notListed[e] = true
				}
			}
		}
		target := 0
		if mode == connectors.Full {
			if target, err = s.fullTarget(ctx, ecos, notListed); err != nil {
				yield(connectors.Item{}, &EcosystemError{Err: err})
				return
			}
		}
		for _, eco := range ecos {
			if err := ctx.Err(); err != nil {
				yield(connectors.Item{}, &EcosystemError{Ecosystem: eco, Err: err})
				return
			}
			res := EcosystemResult{Name: eco}
			cont := true
			if notListed[eco] {
				cont = s.fail(&res, eco, errors.New("not listed in ecosystems.txt"), yield)
			} else {
				cont = s.runEcosystem(ctx, mode, target, eco, &res, yield)
			}
			s.addResult(res)
			if !cont {
				return
			}
		}
	}
}

// fail records an ecosystem-level failure and yields it. It returns the yield result.
func (s *LiveSource) fail(res *EcosystemResult, eco string, err error, yield emit) bool {
	res.Err = err
	return yield(connectors.Item{}, &EcosystemError{Ecosystem: eco, Err: err})
}

// fullTarget returns the number of the full pass this run belongs to. The pass is the
// highest pass number any selected ecosystem completed, as long as some selected
// ecosystem has not reached it; once all have, a new pass (number+1) starts. Because
// the number lives in each ecosystem's cursor, a bounded or interrupted full run
// continues the same pass and skips the ecosystems that already finished it.
func (s *LiveSource) fullTarget(ctx context.Context, ecos []string, notListed map[string]bool) (int, error) {
	passes := make([]int, 0, len(ecos))
	top := 0
	for _, eco := range ecos {
		cur, err := loadCursor(ctx, s.store(), eco)
		if err != nil {
			return 0, fmt.Errorf("ecosystem %q: %w", eco, err)
		}
		passes = append(passes, cur.FullPass)
		top = max(top, cur.FullPass)
	}
	for i, p := range passes {
		if p < top && !notListed[ecos[i]] {
			return top, nil // an ecosystem is still missing from the pass in progress
		}
	}
	return top + 1, nil
}

func (s *LiveSource) runEcosystem(ctx context.Context, mode connectors.Mode, target int, eco string, res *EcosystemResult, yield emit) bool {
	cur, err := loadCursor(ctx, s.store(), eco)
	if err != nil {
		return s.fail(res, eco, err, yield)
	}
	if mode == connectors.Full && cur.FullPass >= target {
		res.Skipped = true
		return true
	}
	if mode == connectors.Incremental && !cur.Completed.IsZero() && cur.Partial == nil {
		res.Method = "modified_id.csv"
		return s.runIncremental(ctx, eco, cur, res, yield)
	}
	res.Method = "zip"
	return s.runZip(ctx, mode, target, eco, cur, res, yield)
}

type recHeader struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// parseHeader validates that data is JSON with an id and returns the normalized id and modified time.
func parseHeader(data []byte) (string, time.Time, error) {
	var h recHeader
	if err := json.Unmarshal(data, &h); err != nil {
		return "", time.Time{}, err
	}
	id := model.NormID(h.ID)
	if id == "" {
		return "", time.Time{}, errors.New("record without id")
	}
	return id, model.ParseTime(h.Modified), nil
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// ---- full pass over all.zip ----

func (s *LiveSource) download(ctx context.Context, eco string) (path, ident string, cleanup func(), err error) {
	resp, err := s.get(ctx, s.ecoURL(eco, "all.zip"))
	if err != nil {
		return "", "", nil, err
	}
	defer resp.Body.Close()
	f, err := os.CreateTemp(s.TempDir, "osv-*.zip")
	if err != nil {
		return "", "", nil, err
	}
	cleanup = func() { os.Remove(f.Name()) }
	n, err := io.Copy(f, resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("download all.zip: %w", err)
	}
	gen := resp.Header.Get("X-Goog-Generation")
	if gen == "" {
		gen = resp.Header.Get("ETag")
	}
	return f.Name(), fmt.Sprintf("%s|%d", gen, n), cleanup, nil
}

func (s *LiveSource) runZip(ctx context.Context, mode connectors.Mode, target int, eco string, cur Cursor, res *EcosystemResult, yield emit) bool {
	path, ident, cleanup, err := s.download(ctx, eco)
	if err != nil {
		return s.fail(res, eco, err, yield)
	}
	defer cleanup()
	zr, err := zip.OpenReader(path)
	if err != nil {
		return s.fail(res, eco, fmt.Errorf("open all.zip: %w", err), yield)
	}
	defer zr.Close()

	start := 0
	maxMod := time.Time{}
	if p := cur.Partial; p != nil && p.Ident == ident && p.Done >= 0 && p.Done <= len(zr.File) {
		start, maxMod = p.Done, p.MaxModified
		res.Resumed = true
	}
	savePartial := func(done int) error {
		return saveCursor(ctx, s.store(), eco, Cursor{
			Completed: cur.Completed,
			FullPass:  cur.FullPass,
			Partial:   &ZipProgress{Ident: ident, Done: done, MaxModified: maxMod},
		})
	}
	saved := start
	for i := start; i < len(zr.File); i++ {
		if err := ctx.Err(); err != nil {
			savePartial(i)
			return s.fail(res, eco, err, yield) && false
		}
		zf := zr.File[i]
		if strings.HasSuffix(zf.Name, "/") {
			continue
		}
		item, mod, err := readEntry(zf)
		var ok bool
		if err != nil {
			res.Failures++
			ok = yield(connectors.Item{}, &RecordError{Ecosystem: eco, Name: zf.Name, Err: err})
		} else {
			res.Records++
			ok = yield(item, nil)
			maxMod = later(maxMod, mod)
		}
		if !ok {
			// The consumer stopped; resume from this entry to be safe.
			if i > saved {
				savePartial(i)
			}
			return false
		}
		if i+1-saved >= s.every() {
			if err := savePartial(i + 1); err != nil {
				return s.fail(res, eco, err, yield)
			}
			saved = i + 1
		}
	}
	final := Cursor{Completed: later(cur.Completed, maxMod), FullPass: cur.FullPass}
	if mode == connectors.Full {
		final.FullPass = max(final.FullPass, target)
	}
	if err := saveCursor(ctx, s.store(), eco, final); err != nil {
		return s.fail(res, eco, err, yield)
	}
	return true
}

func readEntry(zf *zip.File) (connectors.Item, time.Time, error) {
	if !strings.HasSuffix(zf.Name, ".json") {
		return connectors.Item{}, time.Time{}, errors.New("unexpected entry, not a .json file")
	}
	if zf.UncompressedSize64 > maxEntryBytes {
		return connectors.Item{}, time.Time{}, fmt.Errorf("entry exceeds %d bytes", maxEntryBytes)
	}
	rc, err := zf.Open()
	if err != nil {
		return connectors.Item{}, time.Time{}, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxEntryBytes+1))
	if err != nil {
		return connectors.Item{}, time.Time{}, err
	}
	if len(data) > maxEntryBytes {
		return connectors.Item{}, time.Time{}, fmt.Errorf("entry exceeds %d bytes", maxEntryBytes)
	}
	id, mod, err := parseHeader(data)
	if err != nil {
		return connectors.Item{}, time.Time{}, err
	}
	return connectors.Item{ID: id, Payload: data}, mod, nil
}

// ---- incremental pass over modified_id.csv ----

type csvEntry struct {
	mod time.Time
	id  string
}

// readModified returns entries modified strictly after cutoff, oldest first, plus
// descriptions of malformed lines. The file is sorted newest first, so reading stops
// at the first entry at or before cutoff.
func readModified(r io.Reader, cutoff time.Time) (entries []csvEntry, bad []string, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		l := strings.TrimSpace(sc.Text())
		if l == "" {
			continue
		}
		ts, id, ok := strings.Cut(l, ",")
		id = strings.TrimSpace(id)
		t, perr := time.Parse(time.RFC3339, strings.TrimSpace(ts))
		if !ok || id == "" || perr != nil {
			bad = append(bad, fmt.Sprintf("line %d: malformed %q", line, l))
			continue
		}
		if !t.After(cutoff) {
			break
		}
		entries = append(entries, csvEntry{t, id})
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	return entries, bad, nil
}

func (s *LiveSource) fetchRecord(ctx context.Context, eco, id string) ([]byte, error) {
	resp, err := s.get(ctx, s.ecoURL(eco, id+".json"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxEntryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxEntryBytes {
		return nil, fmt.Errorf("record exceeds %d bytes", maxEntryBytes)
	}
	return data, nil
}

func (s *LiveSource) runIncremental(ctx context.Context, eco string, cur Cursor, res *EcosystemResult, yield emit) bool {
	resp, err := s.get(ctx, s.ecoURL(eco, "modified_id.csv"))
	if err != nil {
		return s.fail(res, eco, err, yield)
	}
	entries, bad, err := readModified(resp.Body, cur.Completed)
	resp.Body.Close()
	if err != nil {
		return s.fail(res, eco, fmt.Errorf("read modified_id.csv: %w", err), yield)
	}
	// The watermark must not advance past anything that failed to fetch or list.
	frozen := len(bad) > 0
	for _, b := range bad {
		res.Failures++
		if !yield(connectors.Item{}, &RecordError{Ecosystem: eco, Name: "modified_id.csv", Err: errors.New(b)}) {
			return false
		}
	}
	wm := cur.Completed
	saved := wm
	saveWM := func() error {
		if wm.After(saved) {
			if err := saveCursor(ctx, s.store(), eco, Cursor{Completed: wm, FullPass: cur.FullPass}); err != nil {
				return err
			}
			saved = wm
		}
		return nil
	}
	sinceSave := 0
	for i, e := range entries {
		if err := ctx.Err(); err != nil {
			saveWM()
			return s.fail(res, eco, err, yield) && false
		}
		var ok bool
		data, err := s.fetchRecord(ctx, eco, e.id)
		if err != nil {
			frozen = true
			res.Failures++
			ok = yield(connectors.Item{}, &RecordError{Ecosystem: eco, Name: e.id, Err: err})
		} else if id, _, perr := parseHeader(data); perr != nil {
			res.Failures++
			ok = yield(connectors.Item{}, &RecordError{Ecosystem: eco, Name: e.id + ".json", Err: perr})
		} else {
			res.Records++
			ok = yield(connectors.Item{ID: id, Payload: data}, nil)
		}
		if !ok {
			saveWM()
			return false
		}
		if !frozen && (i == len(entries)-1 || entries[i+1].mod.After(e.mod)) {
			wm = e.mod
		}
		sinceSave++
		if sinceSave >= s.every() {
			if err := saveWM(); err != nil {
				return s.fail(res, eco, err, yield)
			}
			sinceSave = 0
		}
	}
	if err := saveWM(); err != nil {
		return s.fail(res, eco, err, yield)
	}
	return true
}
