package enrich

// Live KEV and EPSS sync (task 88.4).
//
// Storage reuses the existing schema, no new migration:
//   - kev: one row per CVE. An entry that was in an earlier catalogue and is absent from the
//     current one gets status='removed' (the row and its json stay). Canonical Enrichment()
//     only returns status='linked', so removed entries stop being served as KEV. A
//     removed entry that reappears is re-linked.
//   - epss_history: one row per (cve, score_date); the epss table caches the latest date.
//   - job: one row per sync run. Its detail is JSON with the as-of (KEV catalogVersion and
//     dateReleased, EPSS model_version and score_date) and the counters.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors/fetch"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/normalize"
)

// Default feed locations.
const (
	DefaultKEVURL         = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultEPSSCurrentURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
	// DefaultEPSSHistoryBase hosts epss_scores-YYYY-MM-DD.csv.gz.
	DefaultEPSSHistoryBase = "https://epss.empiricalsecurity.com"
)

const (
	// BatchSize is the number of EPSS rows written per transaction.
	BatchSize = 5000
	// MaxRejectionSamples bounds the rejection details kept in a result and job detail.
	MaxRejectionSamples = 50
)

// Config holds the feed locations. Empty fields take the defaults.
type Config struct {
	KEVURL          string
	EPSSCurrentURL  string
	EPSSHistoryBase string // history file URL is <base>/epss_scores-YYYY-MM-DD.csv.gz
	HTTP            *fetch.Client
}

// Syncer pulls KEV and EPSS into a canonical store.
type Syncer struct {
	Store *canonical.Store
	Cfg   Config
	// Now supplies the recorded-at time; defaults to time.Now.
	Now func() time.Time
	// OnReject, when set, is called for every rejected feed entry (not only the samples kept
	// in the result). It must not use the store: it runs while a write transaction may be open.
	OnReject func(RejectedItem)
	// LastJobID is the job row of the most recent run.
	LastJobID canonical.JobID
}

func (s *Syncer) reject(r RejectedItem) {
	if s.OnReject != nil {
		s.OnReject(r)
	}
}

// NewSyncer returns a Syncer with defaults filled in.
func NewSyncer(st *canonical.Store, cfg Config) *Syncer {
	if cfg.KEVURL == "" {
		cfg.KEVURL = DefaultKEVURL
	}
	if cfg.EPSSCurrentURL == "" {
		cfg.EPSSCurrentURL = DefaultEPSSCurrentURL
	}
	if cfg.EPSSHistoryBase == "" {
		cfg.EPSSHistoryBase = DefaultEPSSHistoryBase
	}
	if cfg.HTTP == nil {
		cfg.HTTP = fetch.NewClient("bulk", false)
	}
	return &Syncer{Store: st, Cfg: cfg, Now: time.Now}
}

// RejectedItem is one rejected feed entry with the reason.
type RejectedItem struct {
	ID     string `json:"id"`
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

func (r RejectedItem) String() string {
	return fmt.Sprintf("%q: %s: %s", r.ID, r.Field, r.Reason)
}

func (s *Syncer) stamp() string {
	return s.Now().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

// get issues a GET through the retrying client. Redirects are followed by the HTTP client.
// The caller closes the body.
func (s *Syncer) get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "bellu-global-intel/1.0")
	resp, err := s.Cfg.HTTP.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp, nil
}

// runJob records the run in the job table. fn returns the detail value (JSON-encoded).
func (s *Syncer) runJob(ctx context.Context, source string, fn func() (any, error)) error {
	id, err := s.Store.StartJob(ctx, source, canonical.ModeFull)
	if err != nil {
		return err
	}
	s.LastJobID = id
	detail, ferr := fn()
	status := canonical.JobSuccess
	var b []byte
	if ferr != nil {
		status = canonical.JobFailed
		b, _ = json.Marshal(map[string]any{"error": ferr.Error(), "partial": detail})
	} else {
		b, _ = json.Marshal(detail)
	}
	// Finish with a context that survives cancellation of the sync itself.
	if err := s.Store.FinishJob(context.WithoutCancel(ctx), id, status, string(b)); err != nil && ferr == nil {
		return err
	}
	if ferr == nil {
		// Point KEV/EPSS rows at the resolved vulnerability (no-op while the CVE is pending).
		if err := s.Store.LinkEnrichmentIDs(ctx, false); err != nil {
			return err
		}
	}
	return ferr
}

type execQuerier interface {
	ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
}

// knownCVEs returns every CVE id the store already knows: canonical vulnerabilities,
// resolved records and source records (by id or alias). Same definition as the store's
// "linked" status, computed once per sync instead of once per row.
func knownCVEs(ctx context.Context, q execQuerier) (map[string]struct{}, error) {
	rows, err := q.QueryContext(ctx, `SELECT id FROM vulnerability
UNION SELECT vulnerability_id FROM record_vulnerability
UNION SELECT value FROM record_identifier`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]struct{}{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[strings.ToUpper(strings.TrimSpace(v))] = struct{}{}
	}
	return out, rows.Err()
}

func rejectionItem(r normalize.Rejection) RejectedItem {
	return RejectedItem{ID: r.RecordID, Field: r.Field, Reason: r.Rule}
}

var isoDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

func validDate(d string) bool {
	if !isoDate.MatchString(d) {
		return false
	}
	_, err := time.Parse("2006-01-02", d)
	return err == nil
}

const (
	statusLinked  = "linked"
	statusPending = "pending"
)
