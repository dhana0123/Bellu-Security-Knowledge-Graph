package checkpoint

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeadLetterID(t *testing.T) {
	if got := DeadLetterID("nvd", "CVE-2024-1", KindFailed); got != "nvd:CVE-2024-1:failed" {
		t.Fatal(got)
	}
}

func TestTruncatePayload(t *testing.T) {
	if n := len(TruncatePayload([]byte(strings.Repeat("a", MaxPayload+5)))); n != MaxPayload {
		t.Fatal(n)
	}
	if n := len(TruncatePayload([]byte("ab"))); n != 2 {
		t.Fatal(n)
	}
}

func TestAddWarningCap(t *testing.T) {
	var c Counters
	for i := 0; i < 150; i++ {
		c.AddWarning("x")
	}
	if c.Warnings != 150 || len(c.WarningIDs) != MaxWarningIDs {
		t.Fatal(c.Warnings, len(c.WarningIDs))
	}
}

func TestFinalStatus(t *testing.T) {
	if FinalStatus(Counters{}) != StatusSucceeded || FinalStatus(Counters{Failed: 1}) != StatusSucceededWithErrors {
		t.Fatal("bad status")
	}
}

func TestHoldLoopCancelsOnRenewFailure(t *testing.T) {
	var n atomic.Int32
	ctx, stop := holdLoop(context.Background(), 5*time.Millisecond, func(context.Context) error {
		if n.Add(1) >= 2 {
			return errors.New("lost")
		}
		return nil
	})
	defer stop()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("context not cancelled")
	}
}

func TestHoldLoopStop(t *testing.T) {
	_, stop := holdLoop(context.Background(), time.Hour, func(context.Context) error { return nil })
	stop()
	stop()
}

func TestUpstreamFromProps(t *testing.T) {
	at := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	got, gotAt := upstreamFromProps(map[string]any{
		"source": "nvd", "version": "v", "upstream_cves": int64(10), "upstream_cvesNotRejected": int64(9),
		"upstream_bad": "x", "upstream_": int64(1), "upstreamAt": at,
	})
	if len(got) != 2 || got["cves"] != 10 || got["cvesNotRejected"] != 9 || !gotAt.Equal(at) {
		t.Fatalf("%v %v", got, gotAt)
	}
	if m, a := upstreamFromProps(nil); m != nil || !a.IsZero() {
		t.Fatalf("%v %v", m, a)
	}
	if m, _ := upstreamFromProps(map[string]any{"source": "x"}); m != nil {
		t.Fatalf("%v", m)
	}
}
