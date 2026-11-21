package worker

import (
	"context"
	"time"
)

// NextRun returns the next occurrence of the HH:MM time (UTC) strictly after
// now. hhmm must be valid (config validates it).
func NextRun(now time.Time, hhmm string) (time.Time, error) {
	t, err := time.Parse("15:04", hhmm)
	if err != nil {
		return time.Time{}, err
	}
	now = now.UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), 0, 0, time.UTC)
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next, nil
}

// Daily runs fn at hhmm UTC every 24 hours until ctx is done. With runNow set
// it runs once immediately first (a restart after a missed time). An error
// from fn is passed to onErr and does not stop the loop.
func Daily(ctx context.Context, hhmm string, runNow bool, fn func(context.Context) error, onErr func(error)) error {
	if runNow {
		if err := fn(ctx); err != nil && onErr != nil {
			onErr(err)
		}
	}
	for {
		next, err := NextRun(time.Now(), hhmm)
		if err != nil {
			return err
		}
		if err := sleepTimer(ctx, time.Until(next)); err != nil {
			return err
		}
		if err := fn(ctx); err != nil && onErr != nil {
			onErr(err)
		}
	}
}

// Missed reports whether the most recent scheduled time (hhmm UTC, at or
// before now) passed without a successful run: lastSuccess is before it, or
// zero. A Worker that starts in that case runs the sync once immediately.
func Missed(now time.Time, hhmm string, lastSuccess time.Time) (bool, error) {
	next, err := NextRun(now, hhmm)
	if err != nil {
		return false, err
	}
	prev := next.AddDate(0, 0, -1)
	return lastSuccess.Before(prev), nil
}
