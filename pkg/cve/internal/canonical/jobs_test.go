package canonical

import (
	"context"
	"strings"
	"testing"
	"time"
)

type jobClock struct{ t time.Time }

func (c *jobClock) Now() time.Time { return c.t }

func TestJobsLastSuccess(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	clk := &jobClock{time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	s.SetClock(clk)
	if _, ok, _ := s.LastSuccess(ctx, "osv"); ok {
		t.Fatal("expected no success")
	}
	id, err := s.StartJob(ctx, "osv", ModeFull)
	if err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(time.Hour)
	if err := s.FinishJob(ctx, id, JobSuccess, "ok"); err != nil {
		t.Fatal(err)
	}
	id2, _ := s.StartJob(ctx, "osv", ModeIncremental)
	clk.t = clk.t.Add(time.Hour)
	if err := s.FinishJob(ctx, id2, JobFailed, "boom"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.LastSuccess(ctx, "osv")
	if err != nil || !ok || !got.Equal(time.Date(2024, 1, 1, 1, 0, 0, 0, time.UTC)) {
		t.Fatalf("got %v %v %v", got, ok, err)
	}
	if err := s.FinishJob(ctx, 999, JobSuccess, ""); err == nil {
		t.Fatal("expected error for unknown job")
	}
}

func TestRawFailedList(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.RecordRaw(ctx, "nvd", "CVE-1", "h1", "u1"); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.ListFailedRaw(ctx); len(l) != 0 {
		t.Fatalf("unexpected %v", l)
	}
	if err := s.MarkRawFailed(ctx, "nvd", "CVE-1", "h1", "published", "iso8601"); err != nil {
		t.Fatal(err)
	}
	l, err := s.ListFailedRaw(ctx)
	if err != nil || len(l) != 1 || l[0].Status != RawFailed ||
		!strings.Contains(l[0].Error, "published") || !strings.Contains(l[0].Error, "iso8601") {
		t.Fatalf("got %+v %v", l, err)
	}
	if err := s.MarkRawOK(ctx, "nvd", "CVE-1", "h1"); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.ListFailedRaw(ctx); len(l) != 0 {
		t.Fatalf("still failed %v", l)
	}
	if err := s.MarkRawFailed(ctx, "nvd", "nope", "x", "f", "r"); err == nil {
		t.Fatal("expected not found")
	}
}
