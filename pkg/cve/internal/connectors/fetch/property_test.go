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

	"pgregory.net/rapid"
)

// Feature: bellu-security-knowledge-graph, Property 4: Retry backoff schedule
// Validates: Requirements 1.7, 1.8, 1.12
func TestPropertyRetryBackoffSchedule(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		initial := time.Duration(rapid.IntRange(1, 5000).Draw(rt, "initialMs")) * time.Millisecond
		maxAttempts := rapid.IntRange(1, 10).Draw(rt, "maxAttempts")
		status := rapid.SampledFrom([]int{429, 500, 502, 503, 504}).Draw(rt, "status")
		// Retry-After in whole seconds per response; 0 means header absent.
		retryAfter := rapid.SliceOfN(rapid.IntRange(0, 30), maxAttempts, maxAttempts).Draw(rt, "retryAfter")

		var n int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			i := int(atomic.AddInt32(&n, 1)) - 1
			if i < len(retryAfter) && retryAfter[i] > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter[i]))
			}
			w.WriteHeader(status)
		}))
		defer srv.Close()

		c, slept := harness("src", srv)
		// Keep the rate limiter out of the observed delays.
		if err := c.SetInterval(time.Nanosecond); err != nil {
			rt.Fatal(err)
		}
		c.Retry = RetryPolicy{InitialDelay: initial, MaxAttempts: maxAttempts}

		req, _ := http.NewRequest("GET", srv.URL+"/x", nil)
		resp, err := c.Do(context.Background(), req)
		if resp != nil {
			resp.Body.Close()
			rt.Fatalf("expected failure, got response")
		}
		if got := int(atomic.LoadInt32(&n)); got != maxAttempts {
			rt.Fatalf("requests = %d, want %d", got, maxAttempts)
		}
		if len(*slept) != maxAttempts-1 {
			rt.Fatalf("sleeps = %d, want %d", len(*slept), maxAttempts-1)
		}
		for k := 2; k <= maxAttempts; k++ {
			want := initial << uint(k-2)
			if ra := time.Duration(retryAfter[k-2]) * time.Second; ra > want {
				want = ra
			}
			if got := (*slept)[k-2]; got != want {
				rt.Fatalf("delay before attempt %d = %s, want %s", k, got, want)
			}
		}
		var fe *FailedRequestError
		if !errors.As(err, &fe) {
			rt.Fatalf("error %v is not *FailedRequestError", err)
		}
		if fe.Source != "src" || fe.Request != "GET "+srv.URL+"/x" || fe.Attempts != maxAttempts || fe.Err == nil {
			rt.Fatalf("bad failure record: %+v", fe)
		}
	})
}
