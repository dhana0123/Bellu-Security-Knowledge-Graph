package config

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// ParseSlogLevel maps debug, info, warn, and error (case-insensitive) to a slog level.
func ParseSlogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("invalid log level (want debug, info, warn, or error)")
}

// NewJSONLogger returns a logger that writes one JSON object per line with
// time, level, and msg, omitting entries below the given level. It sends
// nothing anywhere except w.
func NewJSONLogger(w io.Writer, level string) (*slog.Logger, error) {
	lv, err := ParseSlogLevel(level)
	if err != nil {
		return nil, err
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lv})), nil
}
