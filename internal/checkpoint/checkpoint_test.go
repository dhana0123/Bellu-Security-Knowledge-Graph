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
