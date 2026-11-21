package httpx

import (
	"context"
	"errors"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Feature: bellu-security-knowledge-graph, Property 32: Backoff schedules
// (CWE download: 2 and 4 s, 3 attempts, Retry-After capped at 300 s)
// **Validates: Requirements 4**
func TestPropertyCWEBackoff(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Delay schedule for any attempt index.
		k := rapid.IntRange(0, 2).Draw(rt, "k")
		if got, want := CWEPolicy.Delay(k), 2*time.Second<<k; got != want {
			rt.Fatalf("Delay(%d)=%v want %v", k, got, want)
		}

		// Retry-After override is min(ra, 300 s).
		ra := time.Duration(rapid.Int64Range(1, 100000).Draw(rt, "ra")) * time.Second
		want := ra
		if want > 300*time.Second {
			want = 300 * time.Second
		}
		if got := CWEPolicy.DelayFor(k, ra); got != want {
			rt.Fatalf("DelayFor(%d,%v)=%v want %v", k, ra, got, want)
		}

		// Attempts never exceed retries+1, with the documented sleeps.
		failures := rapid.IntRange(0, 10).Draw(rt, "failures")
		clock := &fakeClock{}
		calls := 0
		err := Do(context.Background(), CWEPolicy, clock, func(int) error {
			calls++
			if calls <= failures {
				return Retryable(errors.New("x"))
			}
			return nil
		})
		if failures <= 2 {
			if err != nil || calls != failures+1 {
				rt.Fatalf("failures=%d err=%v calls=%d", failures, err, calls)
			}
		} else if err == nil || calls != 3 {
			rt.Fatalf("failures=%d err=%v calls=%d, want 3 calls and error", failures, err, calls)
		}
		for i, d := range clock.sleeps {
			if d != 2*time.Second<<i {
				rt.Fatalf("sleep %d = %v", i, d)
			}
		}
		if len(clock.sleeps) != calls-1 {
			rt.Fatalf("sleeps=%d calls=%d", len(clock.sleeps), calls)
		}
	})
}
