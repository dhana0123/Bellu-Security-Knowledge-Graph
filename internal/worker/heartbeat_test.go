package worker

import (
	"path/filepath"
	"testing"
	"time"
)

func TestHeartbeat(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hb")
	now := time.Now()
	if Healthy(p, now, HeartbeatMaxAge) == nil {
		t.Fatal("missing file must be unhealthy")
	}
	if err := Touch(p, now); err != nil {
		t.Fatal(err)
	}
	if err := Healthy(p, now.Add(119*time.Second), HeartbeatMaxAge); err != nil {
		t.Fatalf("119 s old must be healthy: %v", err)
	}
	if Healthy(p, now.Add(121*time.Second), HeartbeatMaxAge) == nil {
		t.Fatal("121 s old must be unhealthy")
	}
}

func TestNextRun(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 11, 21, h, m, 0, 0, time.UTC) }
	cases := []struct {
		now  time.Time
		want time.Time
	}{
		{at(2, 59), at(3, 0)},
		{at(3, 0), at(3, 0).AddDate(0, 0, 1)},
		{at(23, 59), at(3, 0).AddDate(0, 0, 1)},
	}
	for _, c := range cases {
		got, err := NextRun(c.now, "03:00")
		if err != nil || !got.Equal(c.want) {
			t.Errorf("NextRun(%v) = %v %v, want %v", c.now, got, err, c.want)
		}
	}
	if _, err := NextRun(at(1, 0), "25:00"); err == nil {
		t.Fatal("invalid time must fail")
	}
}

func TestMissed(t *testing.T) {
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC) // schedule 03:00, previous run time is 03:00 today
	cases := []struct {
		last time.Time
		want bool
	}{
		{time.Time{}, true},
		{time.Date(2026, 1, 9, 3, 30, 0, 0, time.UTC), true},
		{time.Date(2026, 1, 10, 3, 30, 0, 0, time.UTC), false},
		{time.Date(2026, 1, 10, 3, 0, 0, 0, time.UTC), false},
	}
	for _, c := range cases {
		got, err := Missed(now, "03:00", c.last)
		if err != nil || got != c.want {
			t.Errorf("last %v: got %v err %v, want %v", c.last, got, err, c.want)
		}
	}
}
