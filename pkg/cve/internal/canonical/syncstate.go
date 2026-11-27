package canonical

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// Sync statuses stored in sync_state.last_status.
const (
	SyncRunning = "running"
	SyncSuccess = "success"
	// SyncPartial: the run finished but some records or units failed (never success).
	SyncPartial = "partial"
	// SyncBounded: the run stopped cleanly at --max-records; the checkpoint was saved.
	SyncBounded = "bounded"
	SyncFailed  = "failed"
)

// Kinds of rows in rejected_record.
const (
	KindRejected = "rejected" // the record was read but failed validation
	KindFailed   = "failed"   // the record or its unit could not be fetched, read or stored
)

// SyncCounts are per-run record counters. Fetched == New+Updated+Unchanged+Rejected+Failed.
type SyncCounts struct {
	Fetched   int64 `json:"fetched"`
	New       int64 `json:"new"`
	Updated   int64 `json:"updated"`
	Unchanged int64 `json:"unchanged"`
	Rejected  int64 `json:"rejected"`
	Failed    int64 `json:"failed"`
}

// Add returns c plus o.
func (c SyncCounts) Add(o SyncCounts) SyncCounts {
	return SyncCounts{c.Fetched + o.Fetched, c.New + o.New, c.Updated + o.Updated,
		c.Unchanged + o.Unchanged, c.Rejected + o.Rejected, c.Failed + o.Failed}
}

// Balanced reports whether the accounting invariant holds.
func (c SyncCounts) Balanced() bool {
	return c.Fetched == c.New+c.Updated+c.Unchanged+c.Rejected+c.Failed
}

// SyncState is the row of sync_state for one source.
type SyncState struct {
	Source        string          `json:"source"`
	LastAttemptAt string          `json:"last_attempt_at,omitempty"`
	LastSuccessAt string          `json:"last_success_at,omitempty"`
	LastStatus    string          `json:"status"`
	LastError     string          `json:"last_error,omitempty"`
	Cursor        json.RawMessage `json:"cursor,omitempty"`
	Totals        SyncCounts      `json:"totals"`
	LastReport    json.RawMessage `json:"last_report,omitempty"`
	LastRunID     int64           `json:"last_run_id,omitempty"`
}

// SyncFinish is what a finished run writes into sync_state.
type SyncFinish struct {
	Status string // one of the Sync* statuses except running
	Error  string
	Counts SyncCounts
	Report json.RawMessage // JSON of the run report
	RunID  int64
}

// BeginSync marks the start of a run: last_attempt_at is set, status becomes running and
// last_error is kept until the run ends. The checkpoint columns are left alone.
func (s *Store) BeginSync(ctx context.Context, source string, runID int64) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sync_state(source,last_attempt_at,last_status,last_run_id) VALUES(?,?,?,?)
ON CONFLICT(source) DO UPDATE SET last_attempt_at=excluded.last_attempt_at, last_status=excluded.last_status,
 last_run_id=excluded.last_run_id`, source, s.now(), SyncRunning, runID)
	return err
}

// FinishSync records the end of a run. Only a success sets last_success_at and clears
// last_error; totals accumulate the run counters of every finished run.
func (s *Store) FinishSync(ctx context.Context, source string, f SyncFinish) error {
	if f.Status == "" || f.Status == SyncRunning {
		return fmt.Errorf("sync_state: invalid final status %q", f.Status)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var totals sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT totals FROM sync_state WHERE source=?`, source).Scan(&totals)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var tot SyncCounts
	if totals.Valid && totals.String != "" {
		if err := json.Unmarshal([]byte(totals.String), &tot); err != nil {
			return fmt.Errorf("sync_state totals for %s: %w", source, err)
		}
	}
	tb, _ := json.Marshal(tot.Add(f.Counts))
	var errText, report any
	if f.Error != "" {
		errText = f.Error
	}
	if len(f.Report) > 0 {
		report = string(f.Report)
	}
	now := s.now()
	var success any
	if f.Status == SyncSuccess {
		success = now
		errText = nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sync_state(source,last_attempt_at,last_success_at,last_status,last_error,totals,last_report,last_run_id)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
ON CONFLICT(source) DO UPDATE SET last_status=excluded.last_status, last_error=excluded.last_error,
 totals=excluded.totals, last_report=excluded.last_report, last_run_id=excluded.last_run_id,
 last_attempt_at=COALESCE(sync_state.last_attempt_at, excluded.last_attempt_at),
 last_success_at=COALESCE(excluded.last_success_at, sync_state.last_success_at)`,
		source, now, success, f.Status, errText, string(tb), report, f.RunID); err != nil {
		return err
	}
	return tx.Commit()
}

// GetSyncState returns the state of source; ok is false when the source never ran.
func (s *Store) GetSyncState(ctx context.Context, source string) (SyncState, bool, error) {
	rows, err := s.ListSyncStates(ctx)
	if err != nil {
		return SyncState{}, false, err
	}
	for _, r := range rows {
		if r.Source == source {
			return r, true, nil
		}
	}
	return SyncState{}, false, nil
}

// ListSyncStates returns every sync_state row ordered by source.
func (s *Store) ListSyncStates(ctx context.Context) ([]SyncState, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT source,last_attempt_at,last_success_at,last_status,last_error,cursor,totals,last_report,last_run_id
FROM sync_state ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SyncState
	for rows.Next() {
		var st SyncState
		var att, suc, status, lerr, cur, tot, rep sql.NullString
		var run sql.NullInt64
		if err := rows.Scan(&st.Source, &att, &suc, &status, &lerr, &cur, &tot, &rep, &run); err != nil {
			return nil, err
		}
		st.LastAttemptAt, st.LastSuccessAt, st.LastStatus, st.LastError = att.String, suc.String, status.String, lerr.String
		st.LastRunID = run.Int64
		if cur.Valid && cur.String != "" {
			st.Cursor = json.RawMessage(cur.String)
		}
		if rep.Valid && rep.String != "" {
			st.LastReport = json.RawMessage(rep.String)
		}
		if tot.Valid && tot.String != "" {
			if err := json.Unmarshal([]byte(tot.String), &st.Totals); err != nil {
				return nil, fmt.Errorf("sync_state totals for %s: %w", st.Source, err)
			}
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// LoadSyncCursor returns the single cursor of source, or (nil, nil) when none is stored.
func (s *Store) LoadSyncCursor(ctx context.Context, source string) (json.RawMessage, error) {
	var c sql.NullString
	err := s.DB.QueryRowContext(ctx, `SELECT cursor FROM sync_state WHERE source=?`, source).Scan(&c)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (!c.Valid || c.String == "")) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(c.String), nil
}

// SaveSyncCursor stores the single cursor of source, creating the row when needed.
func (s *Store) SaveSyncCursor(ctx context.Context, source string, cursor json.RawMessage) error {
	if !json.Valid(cursor) {
		return fmt.Errorf("sync cursor for %s is not valid JSON", source)
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sync_state(source,cursor) VALUES(?,?)
ON CONFLICT(source) DO UPDATE SET cursor=excluded.cursor`, source, string(cursor))
	return err
}

// LoadSyncCheckpoint returns the cursor stored for (source, key), or (nil, nil).
func (s *Store) LoadSyncCheckpoint(ctx context.Context, source, key string) (json.RawMessage, error) {
	var c string
	err := s.DB.QueryRowContext(ctx, `SELECT cursor FROM sync_checkpoint WHERE source=? AND key=?`, source, key).Scan(&c)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(c), nil
}

// SaveSyncCheckpoint replaces the cursor for (source, key).
func (s *Store) SaveSyncCheckpoint(ctx context.Context, source, key string, cursor json.RawMessage) error {
	if !json.Valid(cursor) {
		return fmt.Errorf("sync checkpoint %s/%s is not valid JSON", source, key)
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sync_checkpoint(source,key,cursor,updated_at) VALUES(?,?,?,?)
ON CONFLICT(source,key) DO UPDATE SET cursor=excluded.cursor, updated_at=excluded.updated_at`,
		source, key, string(cursor), s.now())
	return err
}

// ListSyncCheckpoints returns the keyed cursors of source by key.
func (s *Store) ListSyncCheckpoints(ctx context.Context, source string) (map[string]json.RawMessage, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT key,cursor FROM sync_checkpoint WHERE source=? ORDER BY key`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]json.RawMessage{}
	for rows.Next() {
		var k, c string
		if err := rows.Scan(&k, &c); err != nil {
			return nil, err
		}
		out[k] = json.RawMessage(c)
	}
	return out, rows.Err()
}

// Rejected is one row of rejected_record.
type Rejected struct {
	ID          int64  `json:"id"`
	RunID       int64  `json:"run_id"`
	Source      string `json:"source"`
	RecordID    string `json:"record_id"`
	Kind        string `json:"kind"`
	Reason      string `json:"reason"`
	RawRef      string `json:"raw_ref"`
	CreatedAt   string `json:"created_at"`
	LastSeenAt  string `json:"last_seen_at"`
	Occurrences int64  `json:"occurrences"`
}

// RecordRejected persists one rejected or failed record. The same (source, record_id,
// reason, raw_ref) is stored once; a repeat updates run_id, kind, last_seen_at and occurrences.
func (s *Store) RecordRejected(ctx context.Context, r Rejected) error {
	if r.Source == "" || r.Reason == "" {
		return errors.New("rejected_record needs a source and a reason")
	}
	if r.Kind == "" {
		r.Kind = KindRejected
	}
	now := s.now()
	_, err := s.DB.ExecContext(ctx, `INSERT INTO rejected_record(run_id,source,record_id,kind,reason,raw_ref,created_at,last_seen_at,occurrences)
VALUES(?,?,?,?,?,?,?,?,1)
ON CONFLICT(source,record_id,reason,raw_ref) DO UPDATE SET run_id=excluded.run_id, kind=excluded.kind,
 last_seen_at=excluded.last_seen_at, occurrences=rejected_record.occurrences+1`,
		r.RunID, r.Source, r.RecordID, r.Kind, r.Reason, r.RawRef, now, now)
	return err
}

// ClearRejected deletes the rows of a record that has been ingested successfully since.
func (s *Store) ClearRejected(ctx context.Context, source, recordID string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM rejected_record WHERE source=? AND record_id=?`, source, recordID)
	return err
}

// CountRejected returns the number of rejected_record rows of source by kind.
func (s *Store) CountRejected(ctx context.Context, source string) (map[string]int64, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT kind, COUNT(*) FROM rejected_record WHERE source=? GROUP BY kind`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// ListRejected returns the newest rows of source (all sources when empty), at most limit
// (0 means no limit), newest first.
func (s *Store) ListRejected(ctx context.Context, source string, limit int) ([]Rejected, error) {
	q := `SELECT id,run_id,source,record_id,kind,reason,raw_ref,created_at,last_seen_at,occurrences FROM rejected_record`
	var args []any
	if source != "" {
		q += ` WHERE source=?`
		args = append(args, source)
	}
	q += ` ORDER BY last_seen_at DESC, id DESC`
	if limit > 0 {
		q += fmt.Sprintf(` LIMIT %d`, limit)
	}
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rejected
	for rows.Next() {
		var r Rejected
		if err := rows.Scan(&r.ID, &r.RunID, &r.Source, &r.RecordID, &r.Kind, &r.Reason, &r.RawRef, &r.CreatedAt, &r.LastSeenAt, &r.Occurrences); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ClearRejectedSource deletes every rejected_record row of source. Feed syncs (kev, epss)
// use it after a successful run so the table reflects the current feed.
func (s *Store) ClearRejectedSource(ctx context.Context, source string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM rejected_record WHERE source=?`, source)
	return err
}

// ClearFailed deletes the kind=failed rows of source. A run that finished without a single
// failure retried every unit that failed before (checkpoints are only advanced past
// successful work), so those rows no longer describe the data.
func (s *Store) ClearFailed(ctx context.Context, source string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM rejected_record WHERE source=? AND kind=?`, source, KindFailed)
	return err
}
