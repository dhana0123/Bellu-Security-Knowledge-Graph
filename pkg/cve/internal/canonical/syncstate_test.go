package canonical

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/migrations"
)

// A database that already has migrations 0001-0003 and data gets 0004 on the next Open.
func TestMigration0004AppliesOnExistingDB(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "c.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild as a pre-0004 database: drop the new tables and the migration row.
	for _, q := range []string{`DROP TABLE sync_state`, `DROP TABLE sync_checkpoint`, `DROP TABLE rejected_record`,
		`DELETE FROM schema_migrations WHERE version LIKE '0004%'`,
		`INSERT INTO kev(cve,json,recorded_at) VALUES('CVE-2024-0001','{}','2024-01-01T00:00:00.000Z')`} {
		if _, err := s.DB.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version='0004_sync_state.sql'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("0004 applied %d times, err=%v", n, err)
	}
	for _, tbl := range []string{"sync_state", "sync_checkpoint", "rejected_record"} {
		if _, err := s.DB.Exec(`SELECT COUNT(*) FROM ` + tbl); err != nil {
			t.Errorf("table %s: %v", tbl, err)
		}
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM kev`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("existing data lost: n=%d err=%v", n, err)
	}
	if err := s.Migrate(ctx, migrations.FS); err != nil { // idempotent
		t.Fatal(err)
	}
}

func TestSyncStateLifecycle(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, ok, err := s.GetSyncState(ctx, "nvd"); ok || err != nil {
		t.Fatalf("unknown source: ok=%v err=%v", ok, err)
	}
	// A cursor saved before any run creates the row without touching run fields.
	if err := s.SaveSyncCursor(ctx, "nvd", json.RawMessage(`{"next_index":5}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginSync(ctx, "nvd", 7); err != nil {
		t.Fatal(err)
	}
	st, _, _ := s.GetSyncState(ctx, "nvd")
	if st.LastStatus != SyncRunning || st.LastAttemptAt == "" || st.LastSuccessAt != "" || string(st.Cursor) != `{"next_index":5}` {
		t.Fatalf("after begin: %+v", st)
	}
	// Success sets last_success_at and accumulates totals.
	ok1 := SyncCounts{Fetched: 3, New: 2, Unchanged: 1}
	if err := s.FinishSync(ctx, "nvd", SyncFinish{Status: SyncSuccess, Counts: ok1, RunID: 7, Report: json.RawMessage(`{"a":1}`)}); err != nil {
		t.Fatal(err)
	}
	st, _, _ = s.GetSyncState(ctx, "nvd")
	if st.LastStatus != SyncSuccess || st.LastSuccessAt == "" || st.LastError != "" || st.Totals != ok1 || st.LastRunID != 7 || string(st.LastReport) != `{"a":1}` {
		t.Fatalf("after success: %+v", st)
	}
	success := st.LastSuccessAt
	// A failure keeps last_success_at, records the error, and adds to the totals.
	s.BeginSync(ctx, "nvd", 8)
	bad := SyncCounts{Fetched: 1, Failed: 1}
	if err := s.FinishSync(ctx, "nvd", SyncFinish{Status: SyncFailed, Error: "boom", Counts: bad, RunID: 8}); err != nil {
		t.Fatal(err)
	}
	st, _, _ = s.GetSyncState(ctx, "nvd")
	if st.LastStatus != SyncFailed || st.LastError != "boom" || st.LastSuccessAt != success || st.Totals != ok1.Add(bad) || !st.Totals.Balanced() {
		t.Fatalf("after failure: %+v", st)
	}
	if err := s.FinishSync(ctx, "nvd", SyncFinish{Status: SyncRunning}); err == nil {
		t.Fatal("running is not a final status")
	}
	// Keyed checkpoints.
	if err := s.SaveSyncCheckpoint(ctx, "osv", "PyPI", json.RawMessage(`{"x":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSyncCheckpoint(ctx, "osv", "PyPI", json.RawMessage(`{"x":2}`)); err != nil {
		t.Fatal(err)
	}
	if raw, _ := s.LoadSyncCheckpoint(ctx, "osv", "PyPI"); string(raw) != `{"x":2}` {
		t.Fatalf("checkpoint %s", raw)
	}
	if raw, _ := s.LoadSyncCheckpoint(ctx, "osv", "npm"); raw != nil {
		t.Fatalf("missing key returned %s", raw)
	}
	if err := s.SaveSyncCheckpoint(ctx, "osv", "k", json.RawMessage(`not json`)); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}

func TestRejectedRecordIdempotentAndCleared(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := Rejected{RunID: 1, Source: "osv", RecordID: "X-1", Kind: KindRejected, Reason: "field=a rule=b", RawRef: "file:///raw/x"}
	for run := int64(1); run <= 3; run++ {
		r.RunID = run
		if err := s.RecordRejected(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := s.ListRejected(ctx, "osv", 0)
	if len(rows) != 1 || rows[0].Occurrences != 3 || rows[0].RunID != 3 {
		t.Fatalf("rows %+v", rows)
	}
	r.Reason = "other"
	s.RecordRejected(ctx, r)
	r.RecordID, r.Kind, r.RawRef = "", KindFailed, ""
	r.Reason = "ecosystem failed"
	s.RecordRejected(ctx, r)
	c, _ := s.CountRejected(ctx, "osv")
	if c[KindRejected] != 2 || c[KindFailed] != 1 {
		t.Fatalf("counts %v", c)
	}
	s.ClearRejected(ctx, "osv", "X-1")
	c, _ = s.CountRejected(ctx, "osv")
	if c[KindRejected] != 0 || c[KindFailed] != 1 {
		t.Fatalf("after clear %v", c)
	}
	if err := s.RecordRejected(ctx, Rejected{Source: "osv"}); err == nil {
		t.Fatal("empty reason accepted")
	}
}
