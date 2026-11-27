package canonical

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// JobID identifies a row in the job table.
type JobID int64

// Mode is the ingestion mode of a job ("full" or "incremental").
type Mode string

const (
	ModeFull        Mode = "full"
	ModeIncremental Mode = "incremental"
)

// Job statuses.
const (
	JobRunning = "running"
	JobSuccess = "success"
	JobFailed  = "failed"
	// JobPartial: finished with failed records or stopped at a record limit; not a success.
	JobPartial = "partial"
)

// Raw record statuses.
const (
	RawOK     = "ok"
	RawFailed = "failed"
)

// RawRecord is an indexed raw payload with its processing status.
type RawRecord struct {
	Source      string
	ExternalID  string
	PayloadHash string
	PayloadURI  string
	FetchedAt   string
	Status      string
	Error       string
}

// StartJob records a new running job.
func (s *Store) StartJob(ctx context.Context, source string, mode Mode) (JobID, error) {
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO job(source,mode,started_at,status) VALUES(?,?,?,?)`,
		source, string(mode), s.now(), JobRunning)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return JobID(id), err
}

// FinishJob sets the final status and detail of a job.
func (s *Store) FinishJob(ctx context.Context, id JobID, status, detail string) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE job SET finished_at=?, status=?, detail=? WHERE id=?`,
		s.now(), status, detail, int64(id))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("job %d not found", id)
	}
	return nil
}

// LastSuccess returns the end time of the most recent successful job for source.
func (s *Store) LastSuccess(ctx context.Context, source string) (time.Time, bool, error) {
	var fin sql.NullString
	err := s.DB.QueryRowContext(ctx,
		`SELECT finished_at FROM job WHERE source=? AND status=? AND finished_at IS NOT NULL
ORDER BY finished_at DESC, id DESC LIMIT 1`, source, JobSuccess).Scan(&fin)
	if err == sql.ErrNoRows {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", fin.String)
	if err != nil {
		return time.Time{}, false, err
	}
	return t, true, nil
}

// MarkRawFailed flags a raw record as failed, naming the field and rule that rejected it.
func (s *Store) MarkRawFailed(ctx context.Context, source, id, hash, field, rule string) error {
	return s.setRawStatus(ctx, source, id, hash, RawFailed, fmt.Sprintf("field=%s rule=%s", field, rule))
}

// MarkRawOK clears a failed flag on a raw record.
func (s *Store) MarkRawOK(ctx context.Context, source, id, hash string) error {
	return s.setRawStatus(ctx, source, id, hash, RawOK, "")
}

func (s *Store) setRawStatus(ctx context.Context, source, id, hash, status, msg string) error {
	var e any
	if msg != "" {
		e = msg
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE raw_record SET status=?, error=? WHERE source=? AND external_id=? AND payload_hash=?`,
		status, e, source, id, hash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("raw record %s/%s/%s not found", source, id, hash)
	}
	return nil
}

// ListFailedRaw returns raw records with status failed, for reprocessing.
func (s *Store) ListFailedRaw(ctx context.Context) ([]RawRecord, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT source,external_id,payload_hash,payload_uri,fetched_at,status,COALESCE(error,'')
FROM raw_record WHERE status=? ORDER BY source,external_id,payload_hash`, RawFailed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RawRecord
	for rows.Next() {
		var r RawRecord
		if err := rows.Scan(&r.Source, &r.ExternalID, &r.PayloadHash, &r.PayloadURI, &r.FetchedAt, &r.Status, &r.Error); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
