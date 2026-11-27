// Package epss is the FIRST EPSS Source_Adapter (Requirement 16.4 to 16.9). It
// downloads the daily scores file once per run, streams it, and sets
// epssScore, epssPercentile and epssDate on existing Vulnerabilities.
//
// File format (verified 2026-11-21): a gzip CSV whose first line is a comment,
//
//	#model_version:v2026.06.15,score_date:2026-11-21T12:00:24Z
//
// followed by the header `cve,epss,percentile` and one row per CVE (about
// 410,000 rows, 2.9 MB compressed).
package epss

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/httpx"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/resolve"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source/fetch"
)

const (
	// Name is the adapter name.
	Name = "epss"
	// Host is the only host the default client may reach. FIRST moved the
	// hosting from epss.cyentia.com (which redirects here) to Empirical
	// Security; first.org/epss/data names this URL.
	Host = "epss.empiricalsecurity.com"
	// DefaultURL is the stable URL of the current day's file. It redirects
	// (same host) to epss_scores-<date>.csv.gz.
	DefaultURL = "https://" + Host + "/epss_scores-current.csv.gz"
	// DefaultChangeThreshold is the default of BSKG_EPSS_CHANGE_THRESHOLD.
	DefaultChangeThreshold = 0.01
	// CacheFile is the name of the download under the cache directory.
	CacheFile = "epss_scores-current.csv.gz"
	// MaxDownloadBytes caps the compressed file (about 3 MB today).
	MaxDownloadBytes = 64 << 20
	// MaxExpandedBytes caps the uncompressed stream (about 12 MB today).
	MaxExpandedBytes = 512 << 20

	propScore      = "epssScore"
	propPercentile = "epssPercentile"
	propDate       = "epssDate"
)

// Options configures the adapter. Only CacheDir is required.
type Options struct {
	// CacheDir is BSKG_CACHE_DIR.
	CacheDir string
	// Version is the bskg version for logs; unused for requests.
	Version string
	// ChangeThreshold is the minimum absolute change of epssScore that
	// writes a Change_Record (BSKG_EPSS_CHANGE_THRESHOLD, 0.0 to 1.0). It is
	// used as given: 0 records every change. Pass cfg.EPSSChangeThreshold
	// (default DefaultChangeThreshold).
	ChangeThreshold float64
	// URL, Client and Clock are for tests. The default client reaches Host
	// only.
	URL    string
	Client *http.Client
	Clock  httpx.Clock
}

// Adapter is the EPSS Source_Adapter.
type Adapter struct {
	o      Options
	policy httpx.Policy

	mu     sync.Mutex
	totals map[string]int64
}

var (
	_ source.Adapter = (*Adapter)(nil)
	_ source.Totaler = (*Adapter)(nil)
)

// New returns the adapter.
func New(o Options) *Adapter {
	if o.URL == "" {
		o.URL = DefaultURL
	}
	if o.Client == nil {
		o.Client = httpx.NewAllowList(Host).NewClient(120 * time.Second)
	}
	if o.Clock == nil {
		o.Clock = httpx.RealClock{}
	}
	return &Adapter{o: o, policy: httpx.OSVPolicy}
}

// Name implements source.Adapter.
func (a *Adapter) Name() string { return Name }

// Totals implements source.Totaler: {"rows": scores in the file}. It is empty
// when no file was fetched in this process.
func (a *Adapter) Totals(context.Context) (map[string]int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]int64, len(a.totals))
	for k, v := range a.totals {
		out[k] = v
	}
	return out, nil
}

// meta is the comment line of the file.
type meta struct {
	Model string
	Date  time.Time // score_date
	Raw   string    // score_date as written
}

// version is the skip marker: score_date and model version.
func (m meta) version() string { return m.Raw + "|" + m.Model }

// payload is the stored form of one row. The numbers stay strings; Normalize
// parses and range-checks them.
type payload struct {
	CVE        string `json:"cve"`
	Score      string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"` // YYYY-MM-DD of score_date
	Model      string `json:"model,omitempty"`
}

// stream reads the gzip CSV row by row.
type stream struct {
	f    *os.File
	gz   *gzip.Reader
	cr   *csv.Reader
	meta meta
}

func openStream(path string) (*stream, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	s := &stream{f: f}
	fail := func(err error) (*stream, error) { s.Close(); return nil, err }
	if s.gz, err = gzip.NewReader(f); err != nil {
		return fail(fmt.Errorf("not a gzip file: %w", err))
	}
	br := bufio.NewReader(io.LimitReader(s.gz, MaxExpandedBytes))
	line, err := br.ReadString('\n')
	if err != nil {
		return fail(fmt.Errorf("read comment line: %w", err))
	}
	if s.meta, err = parseMeta(line); err != nil {
		return fail(err)
	}
	s.cr = csv.NewReader(br)
	s.cr.FieldsPerRecord = 3
	s.cr.ReuseRecord = true
	hdr, err := s.cr.Read()
	if err != nil {
		return fail(fmt.Errorf("read header: %w", err))
	}
	if strings.TrimSpace(hdr[0]) != "cve" || strings.TrimSpace(hdr[1]) != "epss" || strings.TrimSpace(hdr[2]) != "percentile" {
		return fail(fmt.Errorf("unexpected header %q: want cve,epss,percentile", strings.Join(hdr, ",")))
	}
	return s, nil
}

func (s *stream) Close() {
	if s.f != nil {
		s.f.Close()
		s.f = nil
	}
}

// next returns the next row, or io.EOF.
func (s *stream) next() (payload, error) {
	row, err := s.cr.Read()
	if err != nil {
		return payload{}, err
	}
	return payload{
		CVE: strings.TrimSpace(row[0]), Score: strings.TrimSpace(row[1]), Percentile: strings.TrimSpace(row[2]),
		Date: s.meta.Date.Format("2006-01-02"), Model: s.meta.Model,
	}, nil
}

func parseMeta(line string) (meta, error) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "#") {
		return meta{}, fmt.Errorf("first line %q is not the #model_version,score_date comment", clip(line))
	}
	var m meta
	for _, part := range strings.Split(strings.TrimPrefix(line, "#"), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), ":")
		if !ok {
			continue
		}
		switch k {
		case "model_version":
			m.Model = v
		case "score_date":
			m.Raw = v
		}
	}
	if m.Raw == "" {
		return meta{}, errors.New("comment line has no score_date")
	}
	t, err := time.Parse(time.RFC3339, m.Raw)
	if err != nil {
		return meta{}, fmt.Errorf("invalid score_date %q: %w", clip(m.Raw), err)
	}
	m.Date = t.UTC()
	return m, nil
}

// validate reads the whole file once: gzip checksum, CSV shape, header,
// comment line. It returns the metadata and the row count. A failure here
// fails the run before any record is returned (Requirement 16.8).
func validate(path string) (meta, int64, error) {
	s, err := openStream(path)
	if err != nil {
		return meta{}, 0, err
	}
	defer s.Close()
	var rows int64
	for {
		if _, err := s.next(); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return meta{}, 0, fmt.Errorf("row %d: %w", rows+1, err)
		}
		rows++
	}
	return s.meta, rows, nil
}

// Fetch downloads the file, validates it, and returns the rows. When the
// score_date and model version equal cp.Version it returns no records.
func (a *Adapter) Fetch(ctx context.Context, cp source.Checkpoint, opts source.RunOptions) (source.Iterator, error) {
	res, err := fetch.DownloadWith(ctx, a.o.Client, a.o.URL, a.o.CacheDir, CacheFile, a.policy, a.o.Clock,
		fetch.Options{MaxBytes: MaxDownloadBytes})
	if err != nil {
		return nil, fmt.Errorf("epss: fetch %s: %w", CacheFile, err)
	}
	m, rows, err := validate(res.Path)
	if err != nil {
		return nil, fmt.Errorf("epss: invalid file %s: %w", CacheFile, err)
	}
	a.mu.Lock()
	a.totals = map[string]int64{"rows": rows}
	a.mu.Unlock()
	if cp.Version != "" && cp.Version == m.version() {
		return &iter{}, nil
	}
	s, err := openStream(res.Path)
	if err != nil {
		return nil, fmt.Errorf("epss: open %s: %w", CacheFile, err)
	}
	return &iter{s: s, limit: opts.SampleLimit, version: m.version()}, nil
}

// iter streams the rows, then one cursor-only record that carries the version.
// A sample run (limit > 0) stops after limit rows and stores no version, so a
// later full run is not skipped.
type iter struct {
	s       *stream
	limit   int
	n       int
	version string
	done    bool
}

func (it *iter) Next(ctx context.Context) (source.Record, error) {
	if it.s == nil || it.done {
		it.finish()
		return source.Record{}, io.EOF
	}
	if err := ctx.Err(); err != nil {
		it.finish()
		return source.Record{}, err
	}
	if it.limit > 0 && it.n >= it.limit {
		it.finish()
		return source.Record{}, io.EOF
	}
	p, err := it.s.next()
	if errors.Is(err, io.EOF) {
		it.finish()
		if it.limit > 0 {
			return source.Record{}, io.EOF
		}
		return source.Record{ID: "score_date", Cursor: source.Cursor{Version: it.version}}, nil
	}
	if err != nil {
		it.finish()
		return source.Record{}, fmt.Errorf("epss: read %s: %w", CacheFile, err)
	}
	it.n++
	b, _ := json.Marshal(p)
	return source.Record{ID: strings.ToUpper(p.CVE), Payload: b}, nil
}

func (it *iter) finish() {
	it.done = true
	if it.s != nil {
		it.s.Close()
	}
}

// Normalize maps one row. It is pure.
func (a *Adapter) Normalize(rec source.Record) (source.Normalized, error) {
	var p payload
	if err := json.Unmarshal(rec.Payload, &p); err != nil {
		return source.Normalized{}, fmt.Errorf("%s: invalid payload: %w", rec.ID, err)
	}
	k, err := resolve.CVE(p.CVE)
	if err != nil {
		return source.Normalized{}, fmt.Errorf("%s: %w", rec.ID, err)
	}
	score, err := unit("epss", p.Score)
	if err != nil {
		return source.Normalized{}, fmt.Errorf("%s: %w", rec.ID, err)
	}
	pct, err := unit("percentile", p.Percentile)
	if err != nil {
		return source.Normalized{}, fmt.Errorf("%s: %w", rec.ID, err)
	}
	date, err := time.Parse("2006-01-02", p.Date)
	if err != nil {
		return source.Normalized{}, fmt.Errorf("%s: invalid date %q", rec.ID, clip(p.Date))
	}
	ref := source.Ref{Kind: source.RefCVE, Raw: k.Value, MustExist: true}
	return source.Normalized{
		Gate: []source.Ref{ref},
		Entities: []source.Entity{{
			Ref:             ref,
			Props:           map[string]any{propScore: score, propPercentile: pct, propDate: date},
			ChangeThreshold: map[string]float64{propScore: a.o.ChangeThreshold},
			ChangeFollows:   map[string]string{propPercentile: propScore, propDate: propScore},
		}},
	}, nil
}

// unit parses a probability in 0.0 to 1.0.
func unit(name, s string) (float64, error) {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q", name, clip(s))
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1 {
		return 0, fmt.Errorf("%s %q outside 0.0 to 1.0", name, clip(s))
	}
	return f, nil
}

func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
