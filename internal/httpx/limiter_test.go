package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type stepClock struct{ now time.Time }

func (c *stepClock) Now() time.Time { return c.now }
func (c *stepClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.now = c.now.Add(d)
	return nil
}

func TestRollingLimiterNeverExceedsN(t *testing.T) {
	clk := &stepClock{now: time.Unix(1000, 0)}
	l := NewRollingLimiter(5, 30*time.Second, clk)
	var at []time.Time
	for i := 0; i < 23; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
		at = append(at, clk.now)
	}
	for i := range at {
		n := 0
		for j := range at {
			if !at[j].Before(at[i]) && at[j].Sub(at[i]) < 30*time.Second {
				n++
			}
		}
		if n > 5 {
			t.Fatalf("%d calls within 30 s starting at call %d", n, i)
		}
	}
	if got := at[5].Sub(at[0]); got != 30*time.Second {
		t.Fatalf("sixth call waited %v, want 30s", got)
	}
}

func TestRollingLimiterContext(t *testing.T) {
	clk := &stepClock{now: time.Unix(0, 0)}
	l := NewRollingLimiter(1, time.Second, clk)
	if err := l.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Wait(ctx); err == nil {
		t.Fatal("want context error")
	}
}

func TestAllowListBlocksRequestAndRedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("blocked host was contacted")
	}))
	defer other.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(other.URL, "127.0.0.1", "localhost", 1), http.StatusFound)
	}))
	defer first.Close()
	c := NewAllowList("127.0.0.1").NewClient(0)
	_, err := c.Get(first.URL)
	if err == nil || !strings.Contains(err.Error(), "localhost") {
		t.Fatalf("redirect error = %v, want it to name localhost", err)
	}
	_, err = NewAllowList("example.com").NewClient(0).Get(first.URL)
	if err == nil || !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("request error = %v, want it to name 127.0.0.1", err)
	}
}
