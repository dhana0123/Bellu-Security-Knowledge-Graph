package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/fetch"
)

const (
	// DefaultBaseURL is the NVD CVE API 2.0 endpoint.
	DefaultBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	// ResultsPerPage is the page size requested from NVD.
	ResultsPerPage = 2000
	// MaxWindow is the longest date range NVD accepts per query.
	MaxWindow = 120 * 24 * time.Hour

	dateLayout = "2006-01-02T15:04:05.000Z"
)

// FullStart is where full mode begins.
var FullStart = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)

// Window is a half-open style date range [Start, End]; consecutive windows share a boundary instant.
type Window struct{ Start, End time.Time }

// Windows splits [since, end] into consecutive windows of at most max, with no gaps.
// It returns nil when end is not after since or max is not positive.
func Windows(since, end time.Time, max time.Duration) []Window {
	if !end.After(since) || max <= 0 {
		return nil
	}
	var out []Window
	for s := since; s.Before(end); {
		e := s.Add(max)
		if e.After(end) {
			e = end
		}
		out = append(out, Window{s, e})
		s = e
	}
	return out
}

// Client fetches CVEs from the NVD API 2.0. It implements connectors.Source.
type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *fetch.Client
	// Now supplies the end of the fetched range; defaults to time.Now.
	Now func() time.Time
	// Checkpoint, when set, receives the cursor after every completed page.
	Checkpoint Checkpointer
	// PageSize is resultsPerPage; zero or values above ResultsPerPage mean ResultsPerPage.
	PageSize int

	stats struct{ pages, records, failed atomic.Int64 }
}

// NewClient builds a client; an empty baseURL selects DefaultBaseURL.
func NewClient(baseURL, apiKey string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{BaseURL: baseURL, APIKey: apiKey, HTTP: fetch.NewClient(fetch.SourceNVD, apiKey != "")}
}

var _ connectors.Source = (*Client)(nil)

// Name returns the source name.
func (c *Client) Name() string { return Source }

// Windows plans windows with the client's maximum span.
func (c *Client) Windows(since, end time.Time) []Window { return Windows(since, end, MaxWindow) }

// RecordError reports one vulnerabilities[] entry that could not be read. ID is the
// CVE id when it could be recovered, otherwise empty; Index is the absolute startIndex
// of the entry within its window query.
type RecordError struct {
	ID     string
	Index  int
	Window Window
	Reason string
}

func (e *RecordError) Error() string {
	id := e.ID
	if id == "" {
		id = "<unknown>"
	}
	return fmt.Sprintf("nvd: record %s (index %d, window %s..%s): %s", id, e.Index,
		e.Window.Start.UTC().Format(dateLayout), e.Window.End.UTC().Format(dateLayout), e.Reason)
}

var idRe = regexp.MustCompile(`"id"\s*:\s*"(CVE-\d{4}-\d{4,})"`)

// Fetch yields one item per CVE. Incremental mode with a zero since falls back to the
// checkpoint's high-water mark when a Checkpoint is set and the last run completed, and
// to a full run otherwise. With a Checkpoint, an interrupted run of the same mode resumes
// at the last completed page. Every entry that cannot be read is yielded as a *RecordError.
func (c *Client) Fetch(ctx context.Context, mode connectors.Mode, since time.Time) iter.Seq2[connectors.Item, error] {
	return func(yield func(connectors.Item, error) bool) {
		now := time.Now
		if c.Now != nil {
			now = c.Now
		}
		var cur *Cursor
		if c.Checkpoint != nil {
			var err error
			if cur, err = loadCursor(ctx, c.Checkpoint); err != nil {
				yield(connectors.Item{}, err)
				return
			}
		}
		var runStart, runEnd, resumeWin time.Time
		resumeIdx := 0
		if cur != nil && !cur.Complete && cur.Mode == mode {
			runStart, runEnd, resumeWin, resumeIdx = cur.RunStart, cur.RunEnd, cur.WindowStart, cur.NextIndex
		} else {
			if mode == connectors.Full || since.IsZero() {
				since = FullStart
				if mode == connectors.Incremental && cur != nil && cur.Complete {
					since = cur.RunEnd
				}
			}
			runStart, runEnd = since.UTC(), now().UTC()
		}
		wins := c.Windows(runStart, runEnd)
		state := Cursor{Mode: mode, RunStart: runStart, RunEnd: runEnd}
		save := func(wi, next int) bool {
			if c.Checkpoint == nil {
				return true
			}
			st := state
			if wi >= len(wins) {
				st.Complete, st.WindowStart, st.WindowEnd = true, runEnd, runEnd
			} else {
				st.WindowStart, st.WindowEnd, st.NextIndex = wins[wi].Start, wins[wi].End, next
			}
			if err := saveCursor(ctx, c.Checkpoint, &st, now()); err != nil {
				yield(connectors.Item{}, err)
				return false
			}
			return true
		}
		for wi, w := range wins {
			start := 0
			if !resumeWin.IsZero() {
				if w.Start.Before(resumeWin) {
					continue
				}
				if w.Start.Equal(resumeWin) {
					start = resumeIdx
				}
				resumeWin = time.Time{}
			}
			for {
				resp, err := c.page(ctx, w, start)
				if err != nil {
					yield(connectors.Item{}, err)
					return
				}
				c.stats.pages.Add(1)
				for i, raw := range resp.Vulnerabilities {
					if err := ctx.Err(); err != nil {
						yield(connectors.Item{}, err)
						return
					}
					var h struct {
						CVE struct {
							ID string `json:"id"`
						} `json:"cve"`
					}
					uerr := json.Unmarshal(raw, &h)
					if uerr != nil || h.CVE.ID == "" {
						re := &RecordError{ID: h.CVE.ID, Index: start + i, Window: w}
						if m := idRe.FindSubmatch(raw); re.ID == "" && m != nil {
							re.ID = string(m[1])
						}
						if uerr != nil {
							re.Reason = "malformed entry: " + uerr.Error()
						} else {
							re.Reason = "entry without cve.id"
						}
						c.stats.failed.Add(1)
						if !yield(connectors.Item{ID: re.ID, Payload: raw}, re) {
							return
						}
						continue
					}
					c.stats.records.Add(1)
					if !yield(connectors.Item{ID: h.CVE.ID, Payload: raw}, nil) {
						return
					}
				}
				n := len(resp.Vulnerabilities)
				if n == 0 && start < resp.TotalResults {
					yield(connectors.Item{}, fmt.Errorf("nvd: window %s..%s returned no entries at startIndex %d of %d",
						w.Start.UTC().Format(dateLayout), w.End.UTC().Format(dateLayout), start, resp.TotalResults))
					return
				}
				start += n
				done := start >= resp.TotalResults
				if done {
					if !save(wi+1, 0) {
						return
					}
					break
				}
				if !save(wi, start) {
					return
				}
			}
		}
	}
}

// Stats counts what this client has read since creation.
type Stats struct{ Pages, Records, Failed int64 }

// Stats returns a snapshot of the page, record and failed-record counters.
func (c *Client) Stats() Stats {
	return Stats{c.stats.pages.Load(), c.stats.records.Load(), c.stats.failed.Load()}
}

func (c *Client) page(ctx context.Context, w Window, start int) (*Response, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("lastModStartDate", w.Start.UTC().Format(dateLayout))
	q.Set("lastModEndDate", w.End.UTC().Format(dateLayout))
	q.Set("startIndex", strconv.Itoa(start))
	per := c.PageSize
	if per <= 0 || per > ResultsPerPage {
		per = ResultsPerPage
	}
	q.Set("resultsPerPage", strconv.Itoa(per))
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "bellu-global-intel/1.0")
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.HTTP.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("nvd: GET %s: %s", u, resp.Status)
	}
	var out Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("nvd: decode page: %w", err)
	}
	return &out, nil
}
