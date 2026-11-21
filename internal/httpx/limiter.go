package httpx

import (
	"context"
	"sync"
	"time"
)

// RollingLimiter allows at most N calls in any rolling Window. NVD uses 50 per
// 30 s with an API key and 5 per 30 s without (Requirement 5.6, 5.7).
type RollingLimiter struct {
	N      int
	Window time.Duration

	clock Clock
	mu    sync.Mutex
	times []time.Time // start times of the calls inside the window, ascending
}

// NewRollingLimiter returns a limiter. A nil clock means RealClock. An N below
// 1 is treated as 1.
func NewRollingLimiter(n int, window time.Duration, clock Clock) *RollingLimiter {
	if n < 1 {
		n = 1
	}
	if clock == nil {
		clock = RealClock{}
	}
	return &RollingLimiter{N: n, Window: window, clock: clock}
}

// Wait blocks until a call is allowed and records it. It returns the context
// error when ctx ends first; no call is recorded in that case.
func (l *RollingLimiter) Wait(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		wait := l.reserve()
		if wait <= 0 {
			return nil
		}
		if err := l.clock.Sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// reserve records a call and returns 0 when one is allowed now, or returns the
// time to wait until the oldest call leaves the window.
func (l *RollingLimiter) reserve() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	cut := 0
	for cut < len(l.times) && !l.times[cut].After(now.Add(-l.Window)) {
		cut++
	}
	l.times = l.times[cut:]
	if len(l.times) < l.N {
		l.times = append(l.times, now)
		return 0
	}
	return l.times[0].Add(l.Window).Sub(now)
}
