package httpx

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"
)

// MaxRetryAfter is the upper bound applied to a server supplied Retry-After.
const MaxRetryAfter = 300 * time.Second

// Policy describes an exponential backoff schedule.
// The delay before retry k (k starts at 0) is Base*2^k, capped at Cap.
// A zero Cap means no cap. A zero MaxRetryAfter means MaxRetryAfter (300 s).
type Policy struct {
	Retries       int           // retries after the first attempt
	Base          time.Duration // delay before the first retry
	Cap           time.Duration // upper bound for computed delays
	MaxRetryAfter time.Duration // upper bound for Retry-After overrides
}

// Ready-made schedules from the design (Property 32).
var (
	// DownloadPolicy is used by the baseline download: 1, 2, 4 s, 3 retries.
	DownloadPolicy = Policy{Retries: 3, Base: time.Second}
	// NVDPolicy: 2 s doubling, cap 60 s, 5 retries.
	NVDPolicy = Policy{Retries: 5, Base: 2 * time.Second, Cap: 60 * time.Second}
	// OSVPolicy is used by OSV and GHSA: 1 s doubling, 3 retries.
	OSVPolicy = Policy{Retries: 3, Base: time.Second}
)

// Delay returns the backoff delay before retry number retry (0-based).
func (p Policy) Delay(retry int) time.Duration {
	if retry < 0 || p.Base <= 0 {
		return 0
	}
	d := p.Base
	for i := 0; i < retry; i++ {
		if p.Cap > 0 && d >= p.Cap {
			break
		}
		if d > time.Duration(1<<62)/2 {
			d = time.Duration(1 << 62)
			break
		}
		d *= 2
	}
	if p.Cap > 0 && d > p.Cap {
		d = p.Cap
	}
	return d
}

// DelayFor returns the delay before retry number retry. A positive
// retryAfter replaces the computed delay, limited to the policy maximum.
func (p Policy) DelayFor(retry int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		limit := p.MaxRetryAfter
		if limit <= 0 {
			limit = MaxRetryAfter
		}
		if retryAfter > limit {
			return limit
		}
		return retryAfter
	}
	return p.Delay(retry)
}

// Clock abstracts waiting so tests do not sleep.
type Clock interface {
	Now() time.Time
	// Sleep waits for d or until ctx ends, returning ctx.Err() in that case.
	Sleep(ctx context.Context, d time.Duration) error
}

// RealClock is the wall clock.
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }

func (RealClock) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// RetryableError marks an error as worth retrying. RetryAfter, when positive,
// overrides the computed backoff delay.
type RetryableError struct {
	Err        error
	RetryAfter time.Duration
}

func (e *RetryableError) Error() string {
	if e.Err == nil {
		return "retryable error"
	}
	return e.Err.Error()
}

func (e *RetryableError) Unwrap() error { return e.Err }

// Retryable wraps err as retryable with no Retry-After override.
func Retryable(err error) error { return &RetryableError{Err: err} }

// Do calls fn until it succeeds, returns a non-retryable error, the context
// ends, or the retries are exhausted. fn receives the 0-based attempt number.
// Only errors wrapping *RetryableError are retried. When retries run out the
// last error is returned. A nil clock means RealClock.
func Do(ctx context.Context, p Policy, clock Clock, fn func(attempt int) error) error {
	if clock == nil {
		clock = RealClock{}
	}
	var err error
	for attempt := 0; ; attempt++ {
		if cerr := ctx.Err(); cerr != nil {
			if err != nil {
				return err
			}
			return cerr
		}
		err = fn(attempt)
		if err == nil {
			return nil
		}
		var re *RetryableError
		if !errors.As(err, &re) || attempt >= p.Retries {
			return err
		}
		if serr := clock.Sleep(ctx, p.DelayFor(attempt, re.RetryAfter)); serr != nil {
			return err
		}
	}
}

// IsRetryableStatus reports whether an HTTP status should be retried
// (403, 429, and 5xx, as used for NVD; 403 is NVD's rate limit signal).
func IsRetryableStatus(code int) bool {
	return code == http.StatusForbidden || code == http.StatusTooManyRequests || code >= 500
}

// ParseRetryAfter reads a Retry-After header value, either delay seconds or
// an HTTP date. It returns 0 when the value is missing, invalid, or in the past.
func ParseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs <= 0 {
			return 0
		}
		if secs > int64(MaxRetryAfter/time.Second)*1000 {
			return MaxRetryAfter * 1000
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}
