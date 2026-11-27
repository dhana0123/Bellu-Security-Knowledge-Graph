package canonical

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

func TestUpsertRecordSmoke(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	rec := &model.Record{Source: "osv", ID: "GHSA-1", Modified: time.Now()}
	changed, err := s.UpsertRecord(ctx, rec)
	if err != nil || !changed {
		t.Fatalf("first upsert: changed=%v err=%v", changed, err)
	}
	changed, err = s.UpsertRecord(ctx, rec)
	if err != nil || changed {
		t.Fatalf("second upsert should be a no-op: changed=%v err=%v", changed, err)
	}
	if _, err := s.UpsertKEV(ctx, model.KEV{CVE: "CVE-2024-1"}); err != nil {
		t.Fatal(err)
	}
	if k, err := s.GetKEV(ctx, "CVE-2024-1"); err != nil || k == nil {
		t.Fatalf("GetKEV: %v %v", k, err)
	}
}

func TestUpsertRecordVersionsAndHistory(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	count := func(q string) int {
		var n int
		if err := s.DB.QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	rec := &model.Record{Source: "osv", ID: "GHSA-1", Summary: "old", Modified: t0}
	if _, err := s.UpsertRecord(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if ch, _ := s.UpsertRecord(ctx, rec); ch {
		t.Fatal("re-upsert changed")
	}
	if count(`SELECT COUNT(*) FROM source_record_version`) != 1 || count(`SELECT COUNT(*) FROM change_history`) != 0 {
		t.Fatal("idempotent re-upsert must add nothing")
	}
	mod := &model.Record{Source: "osv", ID: "GHSA-1", Summary: "new", Modified: t0.Add(time.Hour),
		Weaknesses: []string{"CWE-79"}, Withdrawn: t0.Add(2 * time.Hour)}
	if ch, err := s.UpsertRecord(ctx, mod); err != nil || !ch {
		t.Fatalf("modify: %v %v", ch, err)
	}
	var old, nw, cause string
	if err := s.DB.QueryRow(`SELECT old_value,new_value,cause FROM change_history WHERE fact='osv:GHSA-1#summary'`).Scan(&old, &nw, &cause); err != nil {
		t.Fatal(err)
	}
	if old != "old" || nw != "new" || cause != SourceRecordCause("osv", "GHSA-1") {
		t.Fatalf("history: %q %q %q", old, nw, cause)
	}
	if n := count(`SELECT COUNT(*) FROM change_history`); n != 3 { // summary, weakness, withdrawn
		t.Fatalf("history rows = %d", n)
	}
	var state, js string
	if err := s.DB.QueryRow(`SELECT state FROM source_record_version WHERE version=2`).Scan(&state); err != nil || state != "withdrawn" {
		t.Fatalf("state %q %v", state, err)
	}
	if err := s.DB.QueryRow(`SELECT json FROM source_record_version WHERE version=1`).Scan(&js); err != nil || !strings.Contains(js, `"summary":"old"`) {
		t.Fatalf("v1 not retrievable: %q %v", js, err)
	}
}
