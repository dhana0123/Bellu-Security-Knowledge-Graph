package canonical

// Enrichment storage (requirement 6).
//
// Keying choice: weakness_link, patch and exploit_ref are keyed by `vulnerability_id`, but a
// canonical vulnerability row may not exist when a record is ingested (resolution is a
// separate step). The key is therefore the CVE id when the record carries one (the record
// id for NVD, each CVE-shaped alias for OSV/GHSA), otherwise the record id itself. Because a
// canonical vulnerability is identified by its CVE id whenever one exists, readers can look
// enrichment up by the CVE id before and after resolution.
//
// KEV and EPSS entries are `linked` when the CVE is already known (a vulnerability,
// record_vulnerability or source_record identifier exists) and `pending` otherwise.
// Pending entries are stored but never returned as enrichment; LinkPending flips them.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

const (
	statusLinked  = "linked"
	statusPending = "pending"
	maxURLLen     = 2048
)

var (
	cweRe = regexp.MustCompile(`^CWE-\d+$`)
	cveRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
)

// ItemError describes one enrichment item that was rejected; the rest of the record is kept.
type ItemError struct {
	Item   string
	Reason string
}

// EnrichmentView is the enrichment returned for one CVE.
type EnrichmentView struct {
	KEV        *model.KEV
	EPSS       *model.EPSS
	Weaknesses []string
	Patches    []model.Patch
	Exploits   []model.Exploit
}

type execer interface {
	ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

func shortItem(prefix, v string) string {
	if utf8.RuneCountInString(v) > 80 {
		v = string([]rune(v)[:80]) + "..."
	}
	return prefix + v
}

// enrichmentKeys returns the ids under which a record's enrichment is stored.
func enrichmentKeys(rec *model.Record) []string {
	var keys []string
	seen := map[string]bool{}
	for _, id := range append([]string{rec.ID}, rec.Aliases...) {
		id = strings.ToUpper(strings.TrimSpace(id))
		if cveRe.MatchString(id) && !seen[id] {
			seen[id] = true
			keys = append(keys, id)
		}
	}
	if len(keys) == 0 {
		keys = []string{rec.ID}
	}
	return keys
}

// StoreEnrichment stores the weaknesses, patches and exploit references of rec in its own
// transaction and returns the rejected items. UpsertRecord performs the same work inside
// its transaction (discarding the item list), so this is for callers that need the report.
func (s *Store) StoreEnrichment(ctx context.Context, rec *model.Record) ([]ItemError, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	errs, err := s.storeEnrichment(ctx, tx, rec)
	if err != nil {
		return nil, err
	}
	return errs, tx.Commit()
}

func (s *Store) storeEnrichment(ctx context.Context, tx execer, rec *model.Record) ([]ItemError, error) {
	var errs []ItemError
	keys := enrichmentKeys(rec)
	for _, w := range rec.Weaknesses {
		w = strings.TrimSpace(w)
		if !cweRe.MatchString(w) {
			errs = append(errs, ItemError{shortItem("weakness:", w), "malformed CWE id"})
			continue
		}
		for _, k := range keys {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO weakness_link(vulnerability_id,cwe_id) VALUES(?,?)`, k, w); err != nil {
				return nil, err
			}
		}
	}
	for _, p := range rec.Patches() {
		if reason := urlProblem(p.URL); reason != "" {
			errs = append(errs, ItemError{shortItem("patch:", p.URL), reason})
			continue
		}
		for _, k := range keys {
			if _, err := tx.ExecContext(ctx, `INSERT INTO patch(vulnerability_id,url,source,fixed_version) VALUES(?,?,?,?)
ON CONFLICT(vulnerability_id,url,source) DO UPDATE SET fixed_version=COALESCE(NULLIF(excluded.fixed_version,''),patch.fixed_version)`,
				k, p.URL, p.Source, nullIfEmpty(p.FixedVersion)); err != nil {
				return nil, err
			}
		}
	}
	for _, e := range rec.Exploits() {
		if reason := urlProblem(e.URL); reason != "" {
			errs = append(errs, ItemError{shortItem("exploit:", e.URL), reason})
			continue
		}
		for _, k := range keys {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO exploit_ref(vulnerability_id,url,source) VALUES(?,?,?)`, k, e.URL, e.Source); err != nil {
				return nil, err
			}
		}
	}
	return errs, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func urlProblem(u string) string {
	n := utf8.RuneCountInString(u)
	switch {
	case n == 0:
		return "empty URL"
	case n > maxURLLen:
		return "URL longer than 2048 characters"
	}
	return ""
}

// cveKnown reports whether any vulnerability, resolution or source record carries the id.
// Every lookup is an index probe (vulnerability PK, record_vulnerability_v, record_identifier_value).
func cveKnown(ctx context.Context, q execer, cve string) (bool, error) {
	var ok bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM vulnerability WHERE id=?1)
 OR EXISTS(SELECT 1 FROM record_vulnerability WHERE vulnerability_id=?1)
 OR EXISTS(SELECT 1 FROM record_identifier WHERE value=?1)`, cve).Scan(&ok)
	return ok, err
}

func linkStatus(ctx context.Context, q execer, cve string) (string, error) {
	ok, err := cveKnown(ctx, q, cve)
	if err != nil {
		return "", err
	}
	if ok {
		return statusLinked, nil
	}
	return statusPending, nil
}

func (s *Store) upsertKEV(ctx context.Context, k model.KEV) (bool, error) {
	k.CVE = strings.TrimSpace(k.CVE)
	if k.CVE == "" {
		return false, errors.New("kev: empty CVE id")
	}
	if strings.EqualFold(strings.TrimSpace(k.Ransomware), "known") {
		k.Ransomware = "known"
	} else {
		k.Ransomware = "unknown"
	}
	changed, err := s.upsertJSON(ctx, "kev", k.CVE, k)
	if err != nil {
		return false, err
	}
	st, err := linkStatus(ctx, s.DB, k.CVE)
	if err != nil {
		return false, err
	}
	_, err = s.DB.ExecContext(ctx, `UPDATE kev SET status=?, vulnerability_id=(SELECT id FROM vulnerability WHERE id=?) WHERE cve=?`, st, k.CVE, k.CVE)
	return changed, err
}

func (s *Store) upsertEPSS(ctx context.Context, e model.EPSS) (bool, error) {
	e.CVE = strings.TrimSpace(e.CVE)
	e.Date = strings.TrimSpace(e.Date)
	if e.CVE == "" || e.Date == "" {
		return false, errors.New("epss: CVE id and score date are required")
	}
	st, err := linkStatus(ctx, s.DB, e.CVE)
	if err != nil {
		return false, err
	}
	var oldScore, oldPct sql.NullFloat64
	err = s.DB.QueryRowContext(ctx, `SELECT score, percentile FROM epss_history WHERE cve=? AND score_date=?`, e.CVE, e.Date).Scan(&oldScore, &oldPct)
	exists := err == nil
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	changed := !exists || oldScore.Float64 != e.Score || oldPct.Float64 != e.Percentile
	if changed {
		if _, err = s.DB.ExecContext(ctx, `INSERT INTO epss_history(cve,score_date,score,percentile,status,recorded_at) VALUES(?,?,?,?,?,?)
ON CONFLICT(cve,score_date) DO UPDATE SET score=excluded.score, percentile=excluded.percentile, recorded_at=excluded.recorded_at`,
			e.CVE, e.Date, e.Score, e.Percentile, st, s.now()); err != nil {
			return false, err
		}
	}
	// Keep every row of the CVE on the same status and the epss cache on the latest date.
	if _, err = s.DB.ExecContext(ctx, `UPDATE epss_history SET status=?, vulnerability_id=(SELECT id FROM vulnerability WHERE id=?) WHERE cve=?`, st, e.CVE, e.CVE); err != nil {
		return false, err
	}
	latest, err := s.latestEPSS(ctx, e.CVE, false)
	if err != nil || latest == nil {
		return changed, err
	}
	cacheChanged, err := s.upsertJSON(ctx, "epss", e.CVE, *latest)
	return changed || cacheChanged, err
}

// latestEPSS returns the epss_history row with the greatest score_date.
func (s *Store) latestEPSS(ctx context.Context, cve string, linkedOnly bool) (*model.EPSS, error) {
	q := `SELECT score, percentile, score_date FROM epss_history WHERE cve=?`
	if linkedOnly {
		q += ` AND status='linked'`
	}
	q += ` ORDER BY score_date DESC LIMIT 1`
	var sc, pc sql.NullFloat64
	e := model.EPSS{CVE: cve}
	err := s.DB.QueryRowContext(ctx, q, cve).Scan(&sc, &pc, &e.Date)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.Score, e.Percentile = sc.Float64, pc.Float64
	return &e, nil
}

// Enrichment returns the linked KEV entry, the current (latest score_date) linked EPSS
// assessment, and the weaknesses, patches and exploit references stored for the CVE id.
// Pending KEV and EPSS entries are not returned.
func (s *Store) Enrichment(ctx context.Context, cve string) (*EnrichmentView, error) {
	v := &EnrichmentView{}
	var j string
	err := s.DB.QueryRowContext(ctx, `SELECT json FROM kev WHERE cve=? AND status='linked'`, cve).Scan(&j)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if err == nil {
		v.KEV = &model.KEV{}
		if err := json.Unmarshal([]byte(j), v.KEV); err != nil {
			return nil, err
		}
	}
	if v.EPSS, err = s.latestEPSS(ctx, cve, true); err != nil {
		return nil, err
	}
	if v.Weaknesses, err = s.queryStrings(ctx, `SELECT cwe_id FROM weakness_link WHERE vulnerability_id=? ORDER BY cwe_id`, cve); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT url, source, COALESCE(fixed_version,'') FROM patch WHERE vulnerability_id=? ORDER BY url, source`, cve)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p model.Patch
		if err := rows.Scan(&p.URL, &p.Source, &p.FixedVersion); err != nil {
			rows.Close()
			return nil, err
		}
		v.Patches = append(v.Patches, p)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	rows, err = s.DB.QueryContext(ctx, `SELECT url, source FROM exploit_ref WHERE vulnerability_id=? ORDER BY url, source`, cve)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var x model.Exploit
		if err := rows.Scan(&x.URL, &x.Source); err != nil {
			return nil, err
		}
		v.Exploits = append(v.Exploits, x)
	}
	return v, rows.Err()
}

func (s *Store) queryStrings(ctx context.Context, q string, args ...any) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// LinkPending flips pending KEV rows and pending EPSS history rows to linked for every CVE
// that is now known, then fills vulnerability_id on KEV and EPSS rows whose CVE is a resolved
// vulnerability. It is set-based (no per-CVE round trip) and returns the number of rows flipped
// from pending to linked.
func (s *Store) LinkPending(ctx context.Context) (int, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	total := 0
	for _, t := range []string{"kev", "epss_history"} {
		res, err := tx.ExecContext(ctx, `UPDATE `+t+` SET status='linked' WHERE status='pending' AND (
 EXISTS(SELECT 1 FROM vulnerability v WHERE v.id=`+t+`.cve)
 OR EXISTS(SELECT 1 FROM record_vulnerability rv WHERE rv.vulnerability_id=`+t+`.cve)
 OR EXISTS(SELECT 1 FROM record_identifier ri WHERE ri.value=`+t+`.cve))`)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		total += int(n)
	}
	if err := linkEnrichmentIDs(ctx, tx, false); err != nil {
		return 0, err
	}
	return total, tx.Commit()
}

// LinkEnrichmentIDs sets vulnerability_id on KEV and EPSS rows whose CVE is a resolved
// vulnerability. Rows keep their status. Pass clearDangling to also clear ids that no longer
// point at a vulnerability.
func (s *Store) LinkEnrichmentIDs(ctx context.Context, clearDangling bool) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := linkEnrichmentIDs(ctx, tx, clearDangling); err != nil {
		return err
	}
	return tx.Commit()
}

func linkEnrichmentIDs(ctx context.Context, tx *sql.Tx, clearDangling bool) error {
	for _, t := range []string{"kev", "epss_history"} {
		if clearDangling {
			if _, err := tx.ExecContext(ctx, `UPDATE `+t+` SET vulnerability_id=NULL WHERE vulnerability_id IS NOT NULL
 AND NOT EXISTS(SELECT 1 FROM vulnerability v WHERE v.id=`+t+`.vulnerability_id)`); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE `+t+` SET vulnerability_id=cve WHERE vulnerability_id IS NULL
 AND EXISTS(SELECT 1 FROM vulnerability v WHERE v.id=`+t+`.cve)`); err != nil {
			return err
		}
	}
	return nil
}
