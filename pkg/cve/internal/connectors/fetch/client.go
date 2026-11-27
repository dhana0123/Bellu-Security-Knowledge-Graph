package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Clock supplies the current time; injected for deterministic tests.
type Clock interface{ Now() time.Time }

// Sleeper blocks for d or until ctx is done.
type Sleeper func(ctx context.Context, d time.Duration) error

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func realSleep(ctx context.Context, d time.Duration) error {
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

// Source names with built-in rate defaults.
const SourceNVD = "nvd"

// Rate limits.
const (
	NVDIntervalNoKey   = 6 * time.Second
	NVDIntervalWithKey = 700 * time.Millisecond
	BulkInterval       = time.Second
	MaxInterval        = 60 * time.Second // minimum configurable rate: 1 request per 60 s
)

// DefaultInterval returns the per-source minimum spacing between requests.
func DefaultInterval(source string, hasKey bool) time.Duration {
	if source == SourceNVD {
		if hasKey {
			return NVDIntervalWithKey
		}
		return NVDIntervalNoKey
	}
	return BulkInterval
}

// RetryPolicy configures retries of failed requests.
type RetryPolicy struct {
	InitialDelay time.Duration // default 1s
	MaxAttempts  int           // default 5, valid 1..10
}

// DefaultRetryPolicy returns the default policy (1 s, 5 attempts).
func DefaultRetryPolicy() RetryPolicy { return RetryPolicy{InitialDelay: time.Second, MaxAttempts: 5} }

// Validate checks MaxAttempts in 1..10 and a positive InitialDelay.
func (p RetryPolicy) Validate() error {
	if p.MaxAttempts < 1 || p.MaxAttempts > 10 {
		return fmt.Errorf("retry max attempts %d out of range 1..10", p.MaxAttempts)
	}
	if p.InitialDelay <= 0 {
		return fmt.Errorf("retry initial delay %s must be positive", p.InitialDelay)
	}
	return nil
}

// Delay is the wait after the given failed attempt (1-based): InitialDelay << (attempt-1).
func (p RetryPolicy) Delay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 40 {
		attempt = 40
	}
	return p.InitialDelay << uint(attempt-1)
}

// FailedRequestError reports a request that failed after all attempts.
type FailedRequestError struct {
	Source   string
	Request  string // "METHOD URL"
	Err      error
	Attempts int
}

func (e *FailedRequestError) Error() string {
	return fmt.Sprintf("%s: %s failed after %d attempt(s): %v", e.Source, e.Request, e.Attempts, e.Err)
}
func (e *FailedRequestError) Unwrap() error { return e.Err }

// limiter spaces requests at least interval apart.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	clock    Clock
	last     time.Time
	started  bool
}

func (l *limiter) wait(ctx context.Context, sleep Sleeper) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.started {
		if d := l.interval - l.clock.Now().Sub(l.last); d > 0 {
			if err := sleep(ctx, d); err != nil {
				return err
			}
		}
	}
	l.last = l.clock.Now()
	l.started = true
	return nil
}

// Client performs HTTP requests with per-source rate limiting and retry.
type Client struct {
	Source string
	HTTP   *http.Client
	Retry  RetryPolicy

	lim   *limiter
	clock Clock
	sleep Sleeper
}

// NewClient builds a client for source with default retry and rate limit.
func NewClient(source string, hasKey bool) *Client {
	return &Client{
		Source: source,
		HTTP:   client,
		Retry:  DefaultRetryPolicy(),
		clock:  wallClock{},
		sleep:  realSleep,
		lim:    &limiter{interval: DefaultInterval(source, hasKey), clock: wallClock{}},
	}
}

// SetClock and SetSleeper inject time sources (nil restores real ones).
func (c *Client) SetClock(k Clock) {
	if k == nil {
		k = wallClock{}
	}
	c.clock = k
	c.lim.mu.Lock()
	c.lim.clock = k
	c.lim.mu.Unlock()
}

func (c *Client) SetSleeper(s Sleeper) {
	if s == nil {
		s = realSleep
	}
	c.sleep = s
}

// SetInterval sets the minimum spacing between requests; it must be in (0, 60s].
func (c *Client) SetInterval(d time.Duration) error {
	if d <= 0 || d > MaxInterval {
		return fmt.Errorf("rate interval %s out of range (0, %s]", d, MaxInterval)
	}
	c.lim.mu.Lock()
	c.lim.interval = d
	c.lim.mu.Unlock()
	return nil
}

func (c *Client) retryable(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500 ||
		(status == http.StatusForbidden && c.Source == SourceNVD)
}

func parseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n < 0 {
			return 0
		}
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// Do sends req, retrying on 429, 5xx, NVD 403 and transport errors. On success
// (or a non-retryable status) the response is returned and the caller closes the body.
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if err := c.Retry.Validate(); err != nil {
		return nil, &FailedRequestError{Source: c.Source, Request: req.Method + " " + req.URL.String(), Err: err}
	}
	desc := req.Method + " " + req.URL.String()
	var lastErr error
	for attempt := 1; attempt <= c.Retry.MaxAttempts; attempt++ {
		if err := c.lim.wait(ctx, c.sleep); err != nil {
			return nil, &FailedRequestError{Source: c.Source, Request: desc, Err: err, Attempts: attempt - 1}
		}
		r := req.Clone(ctx)
		if req.GetBody != nil {
			b, err := req.GetBody()
			if err != nil {
				return nil, &FailedRequestError{Source: c.Source, Request: desc, Err: err, Attempts: attempt - 1}
			}
			r.Body = b
		}
		resp, err := c.HTTP.Do(r)
		var retryAfter time.Duration
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return nil, &FailedRequestError{Source: c.Source, Request: desc, Err: ctx.Err(), Attempts: attempt}
			}
			lastErr = err
		case c.retryable(resp.StatusCode):
			lastErr = fmt.Errorf("unexpected status %s", resp.Status)
			retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), c.clock.Now())
			io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
		default:
			return resp, nil
		}
		if attempt == c.Retry.MaxAttempts {
			break
		}
		d := c.Retry.Delay(attempt)
		if retryAfter > d {
			d = retryAfter
		}
		if err := c.sleep(ctx, d); err != nil {
			return nil, &FailedRequestError{Source: c.Source, Request: desc, Err: errors.Join(lastErr, err), Attempts: attempt}
		}
	}
	return nil, &FailedRequestError{Source: c.Source, Request: desc, Err: lastErr, Attempts: c.Retry.MaxAttempts}
}
