package enrich

import (
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/normalize"
)

// EPSSResult reports one EPSS file sync.
type EPSSResult struct {
	ScoreDate    string         `json:"score_date"`
	ModelVersion string         `json:"model_version,omitempty"`
	Source       string         `json:"source"`    // final URL after redirects
	Rows         int            `json:"rows"`      // valid rows read
	Added        int            `json:"added"`     // epss_history rows inserted (subset of Changed)
	Changed      int            `json:"changed"`   // epss_history rows inserted or modified
	Unchanged    int            `json:"unchanged"` // valid rows identical to what is stored
	Rejected     int            `json:"rejected"`
	Rejections   []RejectedItem `json:"rejections,omitempty"`
}

var urlDateRe = regexp.MustCompile(`epss_scores-(\d{4}-\d{2}-\d{2})\.csv(?:\.gz)?$`)

// SyncEPSS fetches the current EPSS file (following redirects to the dated file) and
// stores its scores under the file's score date.
func (s *Syncer) SyncEPSS(ctx context.Context) (EPSSResult, error) {
	return s.syncEPSS(ctx, s.Cfg.EPSSCurrentURL, "")
}

// SyncEPSSDate fetches the EPSS file for a past date (YYYY-MM-DD) from the history host.
// The file's own score date must match.
func (s *Syncer) SyncEPSSDate(ctx context.Context, date string) (EPSSResult, error) {
	if !validDate(date) {
		return EPSSResult{}, fmt.Errorf("epss: invalid date %q, want YYYY-MM-DD", date)
	}
	return s.syncEPSS(ctx, strings.TrimRight(s.Cfg.EPSSHistoryBase, "/")+"/epss_scores-"+date+".csv.gz", date)
}

func (s *Syncer) syncEPSS(ctx context.Context, loc, wantDate string) (EPSSResult, error) {
	var res EPSSResult
	err := s.runJob(ctx, NameEPSS, func() (any, error) {
		resp, err := s.get(ctx, loc)
		if err != nil {
			return &res, err
		}
		defer resp.Body.Close()
		res.Source = resp.Request.URL.String()
		return &res, s.applyEPSS(ctx, resp.Body, resp.Request.URL, wantDate, &res)
	})
	return res, err
}

// epssStream reads an EPSS CSV one row at a time.
type epssStream struct {
	cr           *csv.Reader
	ModelVersion string
	ScoreDate    string // from the comment line, "" when absent
}

func openEPSS(r io.Reader) (*epssStream, error) {
	br := bufio.NewReaderSize(r, 1<<16)
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, normalize.Format("epss", err)
		}
		br = bufio.NewReaderSize(gz, 1<<16)
	}
	st := &epssStream{}
	if b, err := br.Peek(1); err == nil && b[0] == '#' {
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, normalize.Format("epss", err)
		}
		for _, p := range strings.Split(strings.TrimPrefix(strings.TrimSpace(line), "#"), ",") {
			k, v, ok := strings.Cut(p, ":")
			if !ok {
				continue
			}
			switch strings.TrimSpace(k) {
			case "model_version":
				st.ModelVersion = strings.TrimSpace(v)
			case "score_date":
				v = strings.TrimSpace(v)
				if len(v) >= 10 {
					v = v[:10]
				}
				st.ScoreDate = v
			}
		}
	}
	st.cr = csv.NewReader(br)
	st.cr.FieldsPerRecord = -1
	st.cr.ReuseRecord = true
	header, err := st.cr.Read()
	if err != nil {
		return nil, normalize.Format("epss", err)
	}
	if len(header) != 3 || header[0] != "cve" || header[1] != "epss" || header[2] != "percentile" {
		return nil, normalize.Format("epss", fmt.Errorf("unexpected EPSS header %v", header))
	}
	return st, nil
}

// next returns the next valid row (with Date unset). Malformed rows come back as rej and
// the caller continues. io.EOF ends the stream; any other error aborts.
func (st *epssStream) next() (e model.EPSS, rej *RejectedItem, err error) {
	row, err := st.cr.Read()
	if err == io.EOF {
		return e, nil, io.EOF
	}
	if err != nil {
		var pe *csv.ParseError
		if errors.As(err, &pe) {
			return e, &RejectedItem{ID: fmt.Sprintf("line %d", pe.Line), Field: "row", Reason: pe.Err.Error()}, nil
		}
		return e, nil, normalize.Format("epss", err)
	}
	if len(row) != 3 {
		id := ""
		if len(row) > 0 {
			id = row[0]
		}
		return e, &RejectedItem{ID: id, Field: "row", Reason: fmt.Sprintf("expected 3 fields, got %d", len(row))}, nil
	}
	cve, cerr := normalize.CanonicalCVE(row[0])
	if cerr != nil {
		return e, &RejectedItem{ID: row[0], Field: "cve", Reason: "must match CVE-YYYY-NNNN+"}, nil
	}
	sc, e1 := strconv.ParseFloat(strings.TrimSpace(row[1]), 64)
	pc, e2 := strconv.ParseFloat(strings.TrimSpace(row[2]), 64)
	if e1 != nil || e2 != nil || sc != sc || pc != pc || sc < 0 || sc > 1 || pc < 0 || pc > 1 {
		return e, &RejectedItem{ID: cve, Field: "epss/percentile", Reason: "must be numbers in [0,1]"}, nil
	}
	return model.EPSS{CVE: cve, Score: sc, Percentile: pc}, nil, nil
}

func (s *Syncer) applyEPSS(ctx context.Context, body io.Reader, finalURL *url.URL, wantDate string, res *EPSSResult) error {
	st, err := openEPSS(body)
	if err != nil {
		return err
	}
	date := st.ScoreDate
	if date == "" {
		if m := urlDateRe.FindStringSubmatch(path.Base(finalURL.Path)); m != nil {
			date = m[1]
		}
	}
	if !validDate(date) {
		return normalize.Format("epss", fmt.Errorf("no valid score_date in the file comment or URL (got %q)", date))
	}
	if wantDate != "" && date != wantDate {
		return normalize.Format("epss", fmt.Errorf("file score_date %s does not match requested %s", date, wantDate))
	}
	res.ScoreDate, res.ModelVersion = date, st.ModelVersion

	known, err := knownCVEs(ctx, s.Store.DB)
	if err != nil {
		return err
	}
	now := s.stamp()
	var batch []model.EPSS
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		n, added, err := s.writeEPSSBatch(ctx, batch, date, now, known)
		if err != nil {
			return err
		}
		res.Changed += n
		res.Added += added
		res.Unchanged += len(batch) - n
		batch = batch[:0]
		return nil
	}
	for {
		e, rej, err := st.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if rej != nil {
			res.Rejected++
			s.reject(*rej)
			if len(res.Rejections) < MaxRejectionSamples {
				res.Rejections = append(res.Rejections, *rej)
			}
			continue
		}
		e.Date = date
		res.Rows++
		batch = append(batch, e)
		if len(batch) >= BatchSize {
			if err := flush(); err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	if res.Rows == 0 {
		return normalize.Format("epss", errors.New("file has no valid rows"))
	}
	if res.Changed > 0 {
		d, _ := json.Marshal(res)
		_, err = s.Store.DB.ExecContext(ctx, `INSERT INTO graph_event(entity_id,event_type,event_time,recorded_at,detail) VALUES(?,?,?,?,?)`,
			"epss", "epss_synced", date, now, string(d))
		return err
	}
	return nil
}

// writeEPSSBatch writes one batch in a transaction and returns the number of
// epss_history rows inserted or modified. The epss cache only moves forward in date.
func (s *Syncer) writeEPSSBatch(ctx context.Context, batch []model.EPSS, date, now string, known map[string]struct{}) (int, int, error) {
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	hist, err := tx.PrepareContext(ctx, `INSERT INTO epss_history(cve,score_date,score,percentile,status,recorded_at) VALUES(?,?,?,?,?,?)
ON CONFLICT(cve,score_date) DO UPDATE SET score=excluded.score, percentile=excluded.percentile, recorded_at=excluded.recorded_at,
  status=CASE WHEN excluded.status='linked' THEN 'linked' ELSE epss_history.status END
WHERE epss_history.score IS NOT excluded.score OR epss_history.percentile IS NOT excluded.percentile
  OR (excluded.status='linked' AND epss_history.status<>'linked')`)
	if err != nil {
		return 0, 0, err
	}
	defer hist.Close()
	cache, err := tx.PrepareContext(ctx, `INSERT INTO epss(cve,json,recorded_at) VALUES(?1,?2,?3)
ON CONFLICT(cve) DO UPDATE SET json=excluded.json, recorded_at=excluded.recorded_at
WHERE json_extract(epss.json,'$.date') <= ?4 AND epss.json<>excluded.json`)
	if err != nil {
		return 0, 0, err
	}
	defer cache.Close()
	exists, err := tx.PrepareContext(ctx, `SELECT 1 FROM epss_history WHERE cve=? AND score_date=?`)
	if err != nil {
		return 0, 0, err
	}
	defer exists.Close()
	changed, added := 0, 0
	for _, e := range batch {
		var one int
		eerr := exists.QueryRowContext(ctx, e.CVE, date).Scan(&one)
		if eerr != nil && eerr != sql.ErrNoRows {
			return 0, 0, eerr
		}
		isNew := eerr == sql.ErrNoRows
		status := statusPending
		if _, ok := known[e.CVE]; ok {
			status = statusLinked
		}
		r, err := hist.ExecContext(ctx, e.CVE, date, e.Score, e.Percentile, status, now)
		if err != nil {
			return 0, 0, err
		}
		if n, _ := r.RowsAffected(); n > 0 {
			changed++
			if isNew {
				added++
			}
		}
		b, err := json.Marshal(e)
		if err != nil {
			return 0, 0, err
		}
		if _, err := cache.ExecContext(ctx, e.CVE, string(b), now, date); err != nil {
			return 0, 0, err
		}
	}
	return changed, added, tx.Commit()
}

// LastEPSSDate returns the score date of the last successful EPSS sync, or "".
func (s *Syncer) LastEPSSDate(ctx context.Context) (string, error) {
	var d sql.NullString
	err := s.Store.DB.QueryRowContext(ctx, `SELECT json_extract(detail,'$.score_date') FROM job
WHERE source=? AND status='success' ORDER BY finished_at DESC, id DESC LIMIT 1`, NameEPSS).Scan(&d)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return d.String, err
}
