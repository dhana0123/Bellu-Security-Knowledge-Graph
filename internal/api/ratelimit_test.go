package api

import (
	"fmt"
	"testing"
	"time"

	"pgregory.net/rapid"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newFake() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func TestRateLimitBlocksOverLimit(t *testing.T) {
	c := newFake()
	l := NewKeyRateLimiter(3, c.now)
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("request %d rejected", i)
		}
	}
	c.t = c.t.Add(10*time.Second + 500*time.Millisecond)
	ok, ra := l.Allow("a")
	if ok || ra != 50*time.Second {
		t.Fatalf("ok=%v retry=%v, want false 50s", ok, ra)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("other key must not be limited")
	}
}

func TestRateLimitResetsAfterWindow(t *testing.T) {
	c := newFake()
	l := NewKeyRateLimiter(1, c.now)
	l.Allow("a")
	c.t = c.t.Add(RateWindow)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("new window should allow")
	}
}

func TestRateLimitDefaultAndRetryMinimum(t *testing.T) {
	c := newFake()
	l := NewKeyRateLimiter(0, c.now)
	for i := 0; i < DefaultRateLimit; i++ {
		l.Allow("a")
	}
	c.t = c.t.Add(RateWindow - time.Millisecond)
	ok, ra := l.Allow("a")
	if ok || ra != time.Second {
		t.Fatalf("ok=%v retry=%v, want false 1s", ok, ra)
	}
}

func TestRateLimitEvictsStaleKeys(t *testing.T) {
	c := newFake()
	l := NewKeyRateLimiter(5, c.now)
	for i := 0; i < 1000; i++ {
		l.Allow(fmt.Sprintf("k%d", i))
	}
	c.t = c.t.Add(2 * RateWindow)
	l.Allow("fresh")
	if n := l.size(); n != 1 {
		t.Fatalf("size=%d, want 1", n)
	}
}

// Feature: bellu-security-knowledge-graph, Property 39: Per-key rate limit
// **Validates: Requirements 18.10**
//
// Each key has a fixed 60 s window that opens at its first request after the
// previous window ended. Within one window at most N requests are accepted,
// the (N+1)th and later are rejected with Retry-After equal to the time left
// in that window rounded up to whole seconds (at least 1), and keys do not
// affect each other.
func TestPropertyPerKeyRateLimit(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		limit := rapid.IntRange(1, 20).Draw(t, "limit")
		c := newFake()
		l := NewKeyRateLimiter(limit, c.now)
		keys := []string{"a", "b", "c"}
		type win struct {
			start time.Time
			count int
		}
		model := map[string]*win{}
		n := rapid.IntRange(1, 300).Draw(t, "n")
		for i := 0; i < n; i++ {
			c.t = c.t.Add(time.Duration(rapid.IntRange(0, 8000).Draw(t, "gap")) * time.Millisecond)
			k := rapid.SampledFrom(keys).Draw(t, "key")
			ok, ra := l.Allow(k)
			w := model[k]
			if w == nil || !c.t.Before(w.start.Add(RateWindow)) {
				// first request of a new window must be accepted
				if !ok {
					t.Fatalf("key %s: first request of a window rejected", k)
				}
				model[k] = &win{start: c.t, count: 1}
				continue
			}
			if ok {
				w.count++
				if w.count > limit {
					t.Fatalf("key %s: accepted %d > limit %d in one window", k, w.count, limit)
				}
				continue
			}
			if w.count != limit {
				t.Fatalf("key %s: rejected after only %d of %d accepted", k, w.count, limit)
			}
			if ra < time.Second || ra%time.Second != 0 {
				t.Fatalf("retry-after %v not whole seconds >= 1", ra)
			}
			left := w.start.Add(RateWindow).Sub(c.t)
			want := (left + time.Second - 1) / time.Second * time.Second
			if ra != want {
				t.Fatalf("retry-after %v, want %v (window left %v)", ra, want, left)
			}
		}
	})
}
