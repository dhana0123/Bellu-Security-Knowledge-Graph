package fetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) Now() time.Time { return f.t }

// harness wires a fake clock whose sleeper advances time and records sleeps.
func harness(source string, srv *httptest.Server) (*Client, *[]time.Duration) {
	fc := &fakeClock{t: time.Unix(1000, 0)}
	var slept []time.Duration
	c := NewClient(source, false)
	c.SetClock(fc)
	c.SetSleeper(func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		fc.t = fc.t.Add(d)
		return nil
	})
	return c, &slept
}

func get(t *testing.T, c *Client, url string) (*http.Response, error) {
	req, _ := http.NewRequest("GET", url, nil)
	return c.Do(context.Background(), req)
}

func TestDelay(t *testing.T) {
	p := DefaultRetryPolicy()
	for i, want := range []time.Duration{1, 2, 4, 8, 16} {
		if got := p.Delay(i + 1); got != want*time.Second {
			t.Fatalf("attempt %d: %s", i+1, got)
		}
	}
	for _, n := range []int{0, 11} {
		if (RetryPolicy{InitialDelay: time.Second, MaxAttempts: n}).Validate() == nil {
			t.Fatalf("MaxAttempts %d should be invalid", n)
		}
	}
}

func TestRetryThenSuccess(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 {
			w.WriteHeader(503)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c, slept := harness("osv", srv)
	resp, err := get(t, c, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if n != 3 {
		t.Fatalf("calls=%d", n)
	}
	// rate limiter (1s) is already satisfied by the retry delay (1s, 2s)
	if len(*slept) < 2 || (*slept)[0] != time.Second || (*slept)[1] != 2*time.Second {
		t.Fatalf("sleeps=%v", *slept)
	}
}

func TestRetryAfterHonored(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.Header().Set("Retry-After", strconv.Itoa(30))
			w.WriteHeader(429)
			return
		}
	}))
	defer srv.Close()
	c, slept := harness("osv", srv)
	resp, err := get(t, c, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if (*slept)[0] != 30*time.Second {
		t.Fatalf("sleeps=%v", *slept)
	}
}

func TestFailedRequestError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	c, _ := harness("osv", srv)
	c.Retry.MaxAttempts = 3
	_, err := get(t, c, srv.URL)
	var fe *FailedRequestError
	if !errors.As(err, &fe) || fe.Attempts != 3 || fe.Source != "osv" || fe.Err == nil {
		t.Fatalf("err=%v", err)
	}
}

func TestNVD403RetriedOthersNot(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.WriteHeader(403)
		}
	}))
	defer srv.Close()
	c, _ := harness("nvd", srv)
	resp, err := get(t, c, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if n != 2 {
		t.Fatalf("nvd calls=%d", n)
	}

	n = 0
	c2, _ := harness("osv", srv)
	resp, err = get(t, c2, srv.URL)
	if err != nil || resp.StatusCode != 403 || n != 1 {
		t.Fatalf("osv: err=%v n=%d", err, n)
	}
	resp.Body.Close()
}

func TestRateLimiterSpacing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c, slept := harness("nvd", srv)
	for i := 0; i < 2; i++ {
		resp, err := get(t, c, srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if len(*slept) != 1 || (*slept)[0] != 6*time.Second {
		t.Fatalf("sleeps=%v", *slept)
	}
}

func TestIntervalDefaultsAndBounds(t *testing.T) {
	if DefaultInterval("nvd", false) != 6*time.Second || DefaultInterval("nvd", true) != 700*time.Millisecond ||
		DefaultInterval("kev", false) != time.Second {
		t.Fatal("defaults")
	}
	c := NewClient("osv", false)
	if c.SetInterval(61*time.Second) == nil || c.SetInterval(0) == nil || c.SetInterval(60*time.Second) != nil {
		t.Fatal("bounds")
	}
}
