package canonical

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func TestMigrateFreshAndIdempotent(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	count := func() int {
		var n int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(); n != 6 {
		t.Fatalf("applied %d migrations, want 6", n)
	}
	for _, tbl := range []string{"source_record_version", "severity_assessment", "epss_history", "weakness_link",
		"patch", "exploit_ref", "fact_version", "change_history", "job", "candidate_pair"} {
		if _, err := s.DB.Exec(`SELECT COUNT(*) FROM ` + tbl); err != nil {
			t.Errorf("table %s: %v", tbl, err)
		}
	}
	if _, err := s.DB.Exec(`SELECT status, error FROM raw_record`); err != nil {
		t.Error(err)
	}
	if _, err := s.DB.Exec(`SELECT status FROM kev`); err != nil {
		t.Error(err)
	}
	if err := s.Migrate(ctx, migrationsFS()); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 6 {
		t.Fatalf("after re-run %d migrations, want 6", n)
	}
}

func TestChangeHistoryAppendOnly(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.DB.Exec(`INSERT INTO change_history(fact,old_value,new_value,cause,changed_at) VALUES('summary','a','b','x','2024-01-01T00:00:00.000Z')`); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE change_history SET new_value='z'`, `DELETE FROM change_history`} {
		_, err := s.DB.Exec(q)
		if err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: want abort, got %v", q, err)
		}
	}
}

func TestClockInjection(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetClock(fixedClock{time.Date(2024, 5, 6, 7, 8, 9, 123456789, time.UTC)})
	if got := s.now(); got != "2024-05-06T07:08:09.123Z" {
		t.Fatalf("now=%s", got)
	}
}
