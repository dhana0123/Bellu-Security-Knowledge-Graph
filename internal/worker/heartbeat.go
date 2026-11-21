package worker

import (
	"context"
	"fmt"
	"os"
	"time"
)

// HeartbeatPath is the file the Worker touches while it is alive.
const HeartbeatPath = "/tmp/bskg-worker.heartbeat"

// HeartbeatInterval is how often the Worker touches the file.
const HeartbeatInterval = 30 * time.Second

// HeartbeatMaxAge is the age above which the health check fails.
const HeartbeatMaxAge = 2 * time.Minute

// Touch creates or updates the heartbeat file.
func Touch(path string, now time.Time) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chtimes(path, now, now)
}

// Healthy reports an error unless the heartbeat file was touched less than
// maxAge before now.
func Healthy(path string, now time.Time, maxAge time.Duration) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("worker heartbeat: %w", err)
	}
	if age := now.Sub(fi.ModTime()); age >= maxAge {
		return fmt.Errorf("worker heartbeat is %s old (limit %s)", age.Round(time.Second), maxAge)
	}
	return nil
}

// KeepAlive touches the heartbeat file now and then every interval until ctx
// is done.
func KeepAlive(ctx context.Context, path string, interval time.Duration) {
	_ = Touch(path, time.Now())
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			_ = Touch(path, now)
		}
	}
}
