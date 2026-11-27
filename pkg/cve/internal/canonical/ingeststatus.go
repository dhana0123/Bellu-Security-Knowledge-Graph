package canonical

import (
	"context"
	"encoding/json"
	"strings"
)

// IngestStatus is the read-only view of ingestion health shared by `ingest status` and
// GET /v1/ingest/status: per-source sync state, rejected and failed record counts, and the
// resolution summary. It needs only SELECT access, so a store opened with OpenReadOnly works.

// IngestSources lists the sources `ingest sync --all` runs, in order. Status reports always
// include them, with status never_run until they have run.
var IngestSources = []string{"nvd", "osv", "ghsa", "kev", "epss"}

// RejectedSummary counts the rejected_record rows of one source.
type RejectedSummary struct {
	Total    int64      `json:"total"`
	Rejected int64      `json:"rejected"`
	Failed   int64      `json:"failed"`
	Recent   []Rejected `json:"recent"`
}

// SourceStatus is the state of one source.
type SourceStatus struct {
	Source        string                     `json:"source"`
	Status        string                     `json:"status"`
	LastAttemptAt string                     `json:"last_attempt_at,omitempty"`
	LastSuccessAt string                     `json:"last_success_at,omitempty"`
	LastError     string                     `json:"last_error,omitempty"`
	LastRunID     int64                      `json:"last_run_id,omitempty"`
	Cursor        json.RawMessage            `json:"cursor,omitempty"`
	Checkpoints   map[string]json.RawMessage `json:"checkpoints,omitempty"`
	Totals        SyncCounts                 `json:"totals"`
	LastReport    json.RawMessage            `json:"last_report,omitempty"`
	Rejected      RejectedSummary            `json:"rejected"`
}

// ResolveStatus summarizes the resolution state.
type ResolveStatus struct {
	Vulnerabilities int `json:"vulnerabilities"`
	Collisions      int `json:"collisions"`
	UnresolvedDirty int `json:"records_awaiting_resolve"`
	PendingKEV      int `json:"kev_pending"`
	PendingEPSS     int `json:"epss_pending"`
}

// IngestStatus is the whole report.
type IngestStatus struct {
	Sources    []SourceStatus `json:"sources"`
	Resolution ResolveStatus  `json:"resolution"`
}

// StatusOptions selects what LoadIngestStatus reads.
type StatusOptions struct {
	// Sources lists the sources always shown, in order, even if they never ran. Sources found
	// in sync_state but not listed follow.
	Sources []string
	// Only restricts the report to one source when non-empty.
	Only string
	// Recent is the number of recent rejected or failed rows kept per source (0 keeps none).
	Recent int
}

// LoadIngestStatus reads sync_state, sync_checkpoint, rejected_record and the resolution tables.
func (s *Store) LoadIngestStatus(ctx context.Context, o StatusOptions) (*IngestStatus, error) {
	states, err := s.ListSyncStates(ctx)
	if err != nil {
		return nil, err
	}
	bySource := map[string]SyncState{}
	known := map[string]bool{}
	names := make([]string, 0, len(o.Sources)+len(states))
	for _, n := range o.Sources {
		known[n] = true
		names = append(names, n)
	}
	for _, st := range states {
		bySource[st.Source] = st
		if !known[st.Source] {
			known[st.Source] = true
			names = append(names, st.Source)
		}
	}
	out := &IngestStatus{Sources: []SourceStatus{}}
	if out.Resolution, err = s.LoadResolveStatus(ctx); err != nil {
		return nil, err
	}
	for _, name := range names {
		if o.Only != "" && name != o.Only {
			continue
		}
		ss := SourceStatus{Source: name, Status: "never_run"}
		if st, ok := bySource[name]; ok {
			ss.Status, ss.LastAttemptAt, ss.LastSuccessAt = st.LastStatus, st.LastAttemptAt, st.LastSuccessAt
			ss.LastError, ss.LastRunID, ss.Cursor, ss.Totals, ss.LastReport = st.LastError, st.LastRunID, st.Cursor, st.Totals, st.LastReport
		}
		cps, err := s.ListSyncCheckpoints(ctx, name)
		if err != nil {
			return nil, err
		}
		if len(cps) > 0 {
			ss.Checkpoints = cps
		}
		counts, err := s.CountRejected(ctx, name)
		if err != nil {
			return nil, err
		}
		ss.Rejected = RejectedSummary{Rejected: counts[KindRejected], Failed: counts[KindFailed], Recent: []Rejected{}}
		ss.Rejected.Total = ss.Rejected.Rejected + ss.Rejected.Failed
		if o.Recent > 0 && ss.Rejected.Total > 0 {
			rows, err := s.ListRejected(ctx, name, o.Recent)
			if err != nil {
				return nil, err
			}
			ss.Rejected.Recent = rows
		}
		out.Sources = append(out.Sources, ss)
	}
	return out, nil
}

// LoadResolveStatus counts vulnerabilities, collisions, records awaiting resolve and pending
// KEV and EPSS rows.
func (s *Store) LoadResolveStatus(ctx context.Context) (ResolveStatus, error) {
	var r ResolveStatus
	for _, q := range []struct {
		sql string
		dst *int
	}{
		{`SELECT COUNT(*) FROM vulnerability`, &r.Vulnerabilities},
		{`SELECT COUNT(*) FROM resolve_dirty`, &r.UnresolvedDirty},
		{`SELECT COUNT(*) FROM kev WHERE status='pending'`, &r.PendingKEV},
		{`SELECT COUNT(DISTINCT cve) FROM epss_history WHERE status='pending'`, &r.PendingEPSS},
	} {
		if err := s.DB.QueryRowContext(ctx, q.sql).Scan(q.dst); err != nil {
			return r, err
		}
	}
	var err error
	r.Collisions, err = s.CountCollisions(ctx)
	return r, err
}

// IsMissingSchema reports whether err means the canonical database has not been migrated to
// the version that has the ingest-status tables (for example a store written by an older build
// opened read-only, which never migrates).
func IsMissingSchema(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table")
}
