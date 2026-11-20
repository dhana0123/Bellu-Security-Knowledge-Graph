package httpx

import (
	"context"
	"errors"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Feature: bellu-security-knowledge-graph, Property 32: Backoff schedules
// (baseline download: 1, 2, 4 s, 3 retries, Retry-After capped at 300 s)
// **Validates: Requirements 3.5**
func TestPropertyDownloadBackoff(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Delay schedule for any attempt index.
		k := rapid.IntRange(0, 3).Draw(rt, "k")
		if got, want := DownloadPolicy.Delay(k), time.Second<<k; got != want {
			rt.Fatalf("Delay(%d)=%v want %v", k, got, want)
		}

		// Retry-After override is min(ra, 300 s).
		ra := time.Duration(rapid.Int64Range(1, 100000).Draw(rt, "ra")) * time.Second
		want := ra
		if want > 300*time.Second {
			want = 300 * time.Second
		}
		if got := DownloadPolicy.DelayFor(k, ra); got != want {
			rt.Fatalf("DelayFor(%d,%v)=%v want %v", k, ra, got, want)
		}

		// Attempts never exceed retries+1, with the documented sleeps.
		failures := rapid.IntRange(0, 10).Draw(rt, "failures")
		clock := &fakeClock{}
		calls := 0
		err := Do(context.Background(), DownloadPolicy, clock, func(int) error {
			calls++
			if calls <= failures {
				return Retryable(errors.New("x"))
			}
			return nil
		})
		if failures <= 3 {
			if err != nil || calls != failures+1 {
				rt.Fatalf("failures=%d err=%v calls=%d", failures, err, calls)
			}
		} else if err == nil || calls != 4 {
			rt.Fatalf("failures=%d err=%v calls=%d, want 4 calls and error", failures, err, calls)
		}
		for i, d := range clock.sleeps {
			if d != time.Second<<i {
				rt.Fatalf("sleep %d = %v", i, d)
			}
		}
		if len(clock.sleeps) != calls-1 {
			rt.Fatalf("sleeps=%d calls=%d", len(clock.sleeps), calls)
		}
	})
}
