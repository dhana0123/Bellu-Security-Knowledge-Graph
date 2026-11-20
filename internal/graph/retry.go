package graph

import (
	"context"
	"time"
)

// RetryPolicy describes exponential backoff. Delay for retry k (0-based) is
// min(Initial<<k, Max). At most Retries retries follow the first attempt.
type RetryPolicy struct {
	Retries int
	Initial time.Duration
	Max     time.Duration
}

// BatchPolicy is the Graph_Store batch policy: 5 retries at 1, 2, 4, 8, 16 s (cap 30 s).
var BatchPolicy = RetryPolicy{Retries: 5, Initial: time.Second, Max: 30 * time.Second}

// Delay returns the wait before retry number k (0-based).
func (p RetryPolicy) Delay(k int) time.Duration {
	d := p.Initial
	for i := 0; i < k; i++ {
		d *= 2
		if d >= p.Max {
			return p.Max
		}
	}
	if d > p.Max {
		return p.Max
	}
	return d
}

// SleepFunc waits for d or until ctx ends. Tests inject a fake.
type SleepFunc func(ctx context.Context, d time.Duration) error

// RealSleep sleeps using a timer.
func RealSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Retry runs fn, retrying only ClassTransient errors per the policy. The
// returned error is the last error from fn (or the context error).
func Retry(ctx context.Context, p RetryPolicy, sleep SleepFunc, fn func(ctx context.Context) error) error {
	if sleep == nil {
		sleep = RealSleep
	}
	var err error
	for attempt := 0; ; attempt++ {
		if cerr := ctx.Err(); cerr != nil {
			if err != nil {
				return err
			}
			return cerr
		}
		err = fn(ctx)
		if err == nil || Classify(err) != ClassTransient || attempt >= p.Retries {
			return err
		}
		if serr := sleep(ctx, p.Delay(attempt)); serr != nil {
			return err
		}
	}
}
