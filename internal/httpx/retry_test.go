package httpx

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (f *fakeClock) Now() time.Time { return f.now }
func (f *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	f.sleeps = append(f.sleeps, d)
	f.now = f.now.Add(d)
	return ctx.Err()
}

func TestDelaySchedules(t *testing.T) {
	s := time.Second
	cases := []struct {
		name string
		p    Policy
		want []time.Duration
	}{
		{"download", DownloadPolicy, []time.Duration{1 * s, 2 * s, 4 * s}},
		{"nvd", NVDPolicy, []time.Duration{2 * s, 4 * s, 8 * s, 16 * s, 32 * s, 60 * s, 60 * s}},
		{"osv", OSVPolicy, []time.Duration{1 * s, 2 * s, 4 * s}},
	}
	for _, c := range cases {
		for i, w := range c.want {
			if got := c.p.Delay(i); got != w {
				t.Errorf("%s retry %d: got %v want %v", c.name, i, got, w)
			}
		}
	}
	if got := NVDPolicy.Delay(1000); got != 60*s {
		t.Errorf("large retry index: got %v", got)
	}
}

func TestRetryAfterOverrideCapped(t *testing.T) {
	if got := NVDPolicy.DelayFor(0, 10*time.Second); got != 10*time.Second {
		t.Errorf("got %v", got)
	}
	if got := NVDPolicy.DelayFor(0, 1000*time.Second); got != 300*time.Second {
		t.Errorf("got %v", got)
	}
	if got := NVDPolicy.DelayFor(2, 0); got != 8*time.Second {
		t.Errorf("got %v", got)
	}
}

func TestDoRetriesThenSucceeds(t *testing.T) {
	clk := &fakeClock{}
	calls := 0
	err := Do(context.Background(), DownloadPolicy, clk, func(int) error {
		calls++
		if calls < 3 {
			return Retryable(errors.New("boom"))
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	if len(clk.sleeps) != 2 || clk.sleeps[0] != time.Second || clk.sleeps[1] != 2*time.Second {
		t.Fatalf("sleeps %v", clk.sleeps)
	}
}

func TestDoExhaustsRetries(t *testing.T) {
	clk := &fakeClock{}
	calls := 0
	base := errors.New("down")
	err := Do(context.Background(), DownloadPolicy, clk, func(int) error {
		calls++
		return Retryable(base)
	})
	if !errors.Is(err, base) {
		t.Fatalf("err=%v", err)
	}
	if calls != 4 {
		t.Fatalf("calls=%d want 4", calls)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	for i, w := range want {
		if clk.sleeps[i] != w {
			t.Fatalf("sleeps %v", clk.sleeps)
		}
	}
}

func TestDoNonRetryableStopsImmediately(t *testing.T) {
	clk := &fakeClock{}
	calls := 0
	err := Do(context.Background(), NVDPolicy, clk, func(int) error {
		calls++
		return errors.New("fatal")
	})
	if err == nil || calls != 1 || len(clk.sleeps) != 0 {
		t.Fatalf("err=%v calls=%d sleeps=%v", err, calls, clk.sleeps)
	}
}

func TestDoUsesRetryAfter(t *testing.T) {
	clk := &fakeClock{}
	calls := 0
	_ = Do(context.Background(), NVDPolicy, clk, func(int) error {
		calls++
		if calls == 1 {
			return &RetryableError{Err: errors.New("429"), RetryAfter: 900 * time.Second}
		}
		return nil
	})
	if len(clk.sleeps) != 1 || clk.sleeps[0] != 300*time.Second {
		t.Fatalf("sleeps %v", clk.sleeps)
	}
}

func TestDoContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := Do(ctx, DownloadPolicy, &fakeClock{}, func(int) error { calls++; return nil })
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := ParseRetryAfter("7", now); got != 7*time.Second {
		t.Errorf("seconds: %v", got)
	}
	if got := ParseRetryAfter("", now); got != 0 {
		t.Errorf("empty: %v", got)
	}
	if got := ParseRetryAfter("-3", now); got != 0 {
		t.Errorf("negative: %v", got)
	}
	if got := ParseRetryAfter("garbage", now); got != 0 {
		t.Errorf("garbage: %v", got)
	}
	date := now.Add(30 * time.Second).Format("Mon, 02 Jan 2006 15:04:05 GMT")
	if got := ParseRetryAfter(date, now); got != 30*time.Second {
		t.Errorf("date: %v", got)
	}
}

func TestIsRetryableStatus(t *testing.T) {
	for _, c := range []int{403, 429, 500, 503} {
		if !IsRetryableStatus(c) {
			t.Errorf("%d should retry", c)
		}
	}
	for _, c := range []int{200, 301, 400, 404} {
		if IsRetryableStatus(c) {
			t.Errorf("%d should not retry", c)
		}
	}
}
