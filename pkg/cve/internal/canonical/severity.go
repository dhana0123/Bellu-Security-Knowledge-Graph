package canonical

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/cvss"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// Rating maps a score to the CVSS v3 qualitative scale. A nil score has no rating.
func Rating(score *float64) string {
	if score == nil {
		return ""
	}
	switch s := *score; {
	case s <= 0:
		return "None"
	case s < 4.0:
		return "Low"
	case s < 7.0:
		return "Medium"
	case s < 9.0:
		return "High"
	default:
		return "Critical"
	}
}

// NonNil returns s, or an empty non-nil slice when s is nil.
func NonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// storeSeverities writes one severity_assessment row per (source, record_id, type, vector)
// of rec. Rows are only inserted or updated in place, never deleted, and rows of other
// sources are never touched.
func (s *Store) storeSeverities(ctx context.Context, tx *sql.Tx, rec *model.Record) error {
	for _, sv := range rec.Severities {
		score, validation, reason := sv.Score, sv.Validation, sv.Reason
		if validation == "" {
			score, validation, reason = cvss.Assess(sv.Vector, sv.Score)
		}
		var sc any
		if score != nil {
			sc = *score
		}
		var rating any
		if r := Rating(score); r != "" {
			rating = r
		}
		version := sv.Version
		if version == "" {
			version = cvss.Version(sv.Vector)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO severity_assessment(source,record_id,type,vector,version,score,rating,published_at,ingested_at,validation,reason)
VALUES(?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(source,record_id,type,vector) DO UPDATE SET version=excluded.version, score=excluded.score,
 rating=excluded.rating, published_at=excluded.published_at, ingested_at=excluded.ingested_at,
 validation=excluded.validation, reason=excluded.reason`,
			rec.Source, rec.ID, sv.Type, sv.Vector, version, sc, rating, ts(rec.Published), s.now(), validation, reason); err != nil {
			return err
		}
	}
	return nil
}

// SeverityEntry is one stored assessment attributed to its source.
type SeverityEntry struct {
	Source     string   `json:"source"`
	RecordID   string   `json:"record_id"`
	Type       string   `json:"type"`
	Vector     string   `json:"vector"`
	Version    string   `json:"version"`
	Score      *float64 `json:"score"`
	Rating     string   `json:"rating"`
	Validation string   `json:"validation"`
	Reason     string   `json:"reason,omitempty"`
}

// SeverityReport lists all assessments of a vulnerability and whether they disagree.
type SeverityReport struct {
	Discrepancy bool            `json:"discrepancy"`
	Entries     []SeverityEntry `json:"entries"` // source, version, score and rating of each assessment
}

// BuildSeverityReport flags a discrepancy when two scored entries differ by >= 0.1 or
// carry different ratings. Entries is never nil.
func BuildSeverityReport(entries []SeverityEntry) SeverityReport {
	r := SeverityReport{Entries: NonNil(entries)}
	var scored []SeverityEntry
	for _, e := range r.Entries {
		if e.Score != nil {
			scored = append(scored, e)
		}
	}
	for i := range scored {
		for j := i + 1; j < len(scored); j++ {
			if math.Abs(*scored[i].Score-*scored[j].Score) >= 0.1-1e-9 || scored[i].Rating != scored[j].Rating {
				r.Discrepancy = true
				return r
			}
		}
	}
	return r
}

// Severities returns every assessment of the records attached to a vulnerability.
func (s *Store) Severities(ctx context.Context, vulnID string) ([]SeverityEntry, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT sa.source,sa.record_id,sa.type,sa.vector,COALESCE(sa.version,''),sa.score,COALESCE(sa.rating,''),sa.validation,COALESCE(sa.reason,'')
FROM severity_assessment sa JOIN record_vulnerability rv ON rv.source=sa.source AND rv.external_id=sa.record_id
WHERE rv.vulnerability_id=? ORDER BY sa.source,sa.record_id,sa.type,sa.vector`, vulnID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SeverityEntry{}
	for rows.Next() {
		var e SeverityEntry
		var sc sql.NullFloat64
		if err := rows.Scan(&e.Source, &e.RecordID, &e.Type, &e.Vector, &e.Version, &sc, &e.Rating, &e.Validation, &e.Reason); err != nil {
			return nil, err
		}
		if sc.Valid {
			v := sc.Float64
			e.Score = &v
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SeverityReportFor builds the discrepancy report of a vulnerability.
func (s *Store) SeverityReportFor(ctx context.Context, vulnID string) (SeverityReport, error) {
	es, err := s.Severities(ctx, vulnID)
	if err != nil {
		return SeverityReport{Entries: []SeverityEntry{}}, err
	}
	return BuildSeverityReport(es), nil
}

// SourceRecords returns the source records attached to a vulnerability (never nil).
func (s *Store) SourceRecords(ctx context.Context, vulnID string) ([]model.Record, error) {
	rows, err := s.QueryCached(ctx, `SELECT sr.json FROM source_record sr JOIN record_vulnerability rv
ON rv.source=sr.source AND rv.external_id=sr.external_id WHERE rv.vulnerability_id=? ORDER BY sr.source,sr.external_id`, vulnID)
	if err != nil {
		return []model.Record{}, err
	}
	defer rows.Close()
	out := []model.Record{}
	for rows.Next() {
		var j string
		if err := rows.Scan(&j); err != nil {
			return []model.Record{}, err
		}
		var r model.Record
		if err := json.Unmarshal([]byte(j), &r); err != nil {
			return []model.Record{}, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AffectedPackages returns the affected entries of all source records of a vulnerability (never nil).
func (s *Store) AffectedPackages(ctx context.Context, vulnID string) ([]model.Affected, error) {
	recs, err := s.SourceRecords(ctx, vulnID)
	out := []model.Affected{}
	for _, r := range recs {
		out = append(out, r.Affected...)
	}
	return out, err
}
