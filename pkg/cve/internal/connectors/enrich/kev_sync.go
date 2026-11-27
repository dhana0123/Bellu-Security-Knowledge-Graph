package enrich

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/normalize"
)

// KEV status values stored in kev.status besides 'linked' and 'pending'.
const KEVStatusRemoved = "removed"

const maxKEVBytes = 64 << 20

// KEVResult reports one KEV sync.
type KEVResult struct {
	CatalogVersion string         `json:"catalog_version"`
	DateReleased   string         `json:"date_released"`
	Entries        int            `json:"entries"` // valid entries in the feed
	Added          int            `json:"added"`
	Updated        int            `json:"updated"`
	Unchanged      int            `json:"unchanged"`
	Removed        int            `json:"removed"` // newly marked removed in this run
	Rejected       int            `json:"rejected"`
	Rejections     []RejectedItem `json:"rejections,omitempty"`
}

// SyncKEV fetches the CISA KEV catalogue and applies it in one transaction. Entries that
// were in the store but are no longer in the catalogue are marked status='removed'.
// A catalogue with no valid entry is refused, so a broken feed cannot remove everything.
func (s *Syncer) SyncKEV(ctx context.Context) (KEVResult, error) {
	var res KEVResult
	err := s.runJob(ctx, NameKEV, func() (any, error) {
		resp, err := s.get(ctx, s.Cfg.KEVURL)
		if err != nil {
			return &res, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxKEVBytes+1))
		if err != nil {
			return &res, err
		}
		if len(body) > maxKEVBytes {
			return &res, errors.New("kev: feed larger than 64 MiB")
		}
		return &res, s.applyKEV(ctx, body, &res)
	})
	return res, err
}

func (s *Syncer) applyKEV(ctx context.Context, body []byte, res *KEVResult) error {
	var hdr struct {
		CatalogVersion string `json:"catalogVersion"`
		DateReleased   string `json:"dateReleased"`
	}
	if err := json.Unmarshal(body, &hdr); err != nil {
		return normalize.Format("kev", err)
	}
	if hdr.CatalogVersion == "" || hdr.DateReleased == "" {
		return normalize.Format("kev", errors.New("catalogVersion and dateReleased are required"))
	}
	res.CatalogVersion, res.DateReleased = hdr.CatalogVersion, hdr.DateReleased
	entries, rejs, err := ParseKEVReport(bytes.NewReader(body))
	if err != nil {
		return err
	}
	res.Rejected = len(rejs)
	for i, r := range rejs {
		s.reject(rejectionItem(r))
		if i < MaxRejectionSamples {
			res.Rejections = append(res.Rejections, rejectionItem(r))
		}
	}
	feed := make(map[string]model.KEV, len(entries))
	for _, k := range entries {
		feed[k.CVE] = k.Normalize()
	}
	res.Entries = len(feed)
	if len(feed) == 0 {
		return normalize.Format("kev", errors.New("catalogue has no valid entries; refusing to mark everything removed"))
	}

	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	known, err := knownCVEs(ctx, tx)
	if err != nil {
		return err
	}
	type old struct{ json, status string }
	existing := map[string]old{}
	rows, err := tx.QueryContext(ctx, `SELECT cve, json, status FROM kev`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var c string
		var o old
		if err := rows.Scan(&c, &o.json, &o.status); err != nil {
			rows.Close()
			return err
		}
		existing[c] = o
	}
	if err := rows.Close(); err != nil {
		return err
	}

	now := s.stamp()
	event := func(cve, typ, detail string) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO graph_event(entity_id,event_type,event_time,recorded_at,detail) VALUES(?,?,?,?,?)`,
			cve, typ, nil, now, detail)
		return err
	}
	for cve, k := range feed {
		b, err := json.Marshal(k)
		if err != nil {
			return err
		}
		status := statusPending
		if _, ok := known[cve]; ok {
			status = statusLinked
		}
		o, had := existing[cve]
		switch {
		case !had:
			res.Added++
		case o.json == string(b) && o.status == status:
			res.Unchanged++
			continue
		default:
			res.Updated++
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO kev(cve,json,recorded_at,status) VALUES(?,?,?,?)
ON CONFLICT(cve) DO UPDATE SET json=excluded.json, status=excluded.status, recorded_at=excluded.recorded_at`,
			cve, string(b), now, status); err != nil {
			return err
		}
		if err := event(cve, "kev_updated", string(b)); err != nil {
			return err
		}
	}
	for cve, o := range existing {
		if _, in := feed[cve]; in || o.status == KEVStatusRemoved {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE kev SET status=?, recorded_at=? WHERE cve=?`, KEVStatusRemoved, now, cve); err != nil {
			return err
		}
		d, _ := json.Marshal(map[string]string{"catalog_version": hdr.CatalogVersion, "date_released": hdr.DateReleased})
		if err := event(cve, "kev_removed", string(d)); err != nil {
			return err
		}
		res.Removed++
	}
	return tx.Commit()
}

// KEVAsOf is the catalogue identity of the last successful KEV sync.
type KEVAsOf struct {
	CatalogVersion string
	DateReleased   string
	FinishedAt     string
}

// LastKEVAsOf returns the as-of of the most recent successful KEV sync, or ok=false.
func (s *Syncer) LastKEVAsOf(ctx context.Context) (KEVAsOf, bool, error) {
	var detail, fin sql.NullString
	err := s.Store.DB.QueryRowContext(ctx, `SELECT detail, finished_at FROM job WHERE source=? AND status='success'
ORDER BY finished_at DESC, id DESC LIMIT 1`, NameKEV).Scan(&detail, &fin)
	if err == sql.ErrNoRows {
		return KEVAsOf{}, false, nil
	}
	if err != nil {
		return KEVAsOf{}, false, err
	}
	var r KEVResult
	if err := json.Unmarshal([]byte(detail.String), &r); err != nil {
		return KEVAsOf{}, false, fmt.Errorf("kev job detail: %w", err)
	}
	return KEVAsOf{CatalogVersion: r.CatalogVersion, DateReleased: r.DateReleased, FinishedAt: fin.String}, true, nil
}
