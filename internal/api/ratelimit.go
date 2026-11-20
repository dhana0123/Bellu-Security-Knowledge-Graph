package api

import (
	"sync"
	"time"
)

// DefaultRateLimit is the default number of requests per key per window.
const DefaultRateLimit = 120

// RateWindow is the fixed window length.
const RateWindow = 60 * time.Second

type rateWindow struct {
	start time.Time
	count int
}

// KeyRateLimiter is a fixed-window, per-key, in-memory request limiter.
type KeyRateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	now     func() time.Time
	windows map[string]*rateWindow
	lastGC  time.Time
}

// NewKeyRateLimiter creates a limiter allowing limit requests per 60 s window.
// A limit below 1 uses DefaultRateLimit. A nil clock uses time.Now.
func NewKeyRateLimiter(limit int, now func() time.Time) *KeyRateLimiter {
	if limit < 1 {
		limit = DefaultRateLimit
	}
	if now == nil {
		now = time.Now
	}
	return &KeyRateLimiter{
		limit:   limit,
		window:  RateWindow,
		now:     now,
		windows: make(map[string]*rateWindow),
	}
}

// Allow records a request for key. When the key is over its limit it returns
// false and a retry delay that is a whole number of seconds, at least 1 s.
func (l *KeyRateLimiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.evict(now)

	w, ok := l.windows[key]
	if !ok || !now.Before(w.start.Add(l.window)) {
		l.windows[key] = &rateWindow{start: now, count: 1}
		return true, 0
	}
	if w.count < l.limit {
		w.count++
		return true, 0
	}
	remaining := w.start.Add(l.window).Sub(now)
	secs := (remaining + time.Second - 1) / time.Second // round up
	if secs < 1 {
		secs = 1
	}
	return false, secs * time.Second
}

// evict drops expired windows. It scans at most once per window length, so
// memory is bounded by the keys seen in about two windows.
func (l *KeyRateLimiter) evict(now time.Time) {
	if now.Sub(l.lastGC) < l.window {
		return
	}
	l.lastGC = now
	for k, w := range l.windows {
		if !now.Before(w.start.Add(l.window)) {
			delete(l.windows, k)
		}
	}
}

// size returns the number of tracked keys (for tests).
func (l *KeyRateLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.windows)
}
