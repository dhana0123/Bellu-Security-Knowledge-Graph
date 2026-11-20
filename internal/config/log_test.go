package config

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func TestNewJSONLoggerInvalidLevel(t *testing.T) {
	if _, err := NewJSONLogger(&bytes.Buffer{}, "verbose"); err == nil {
		t.Fatal("expected error")
	}
}

func TestNewJSONLoggerFiltersAndFormats(t *testing.T) {
	var b bytes.Buffer
	l, err := NewJSONLogger(&b, "WARN")
	if err != nil {
		t.Fatal(err)
	}
	l.Info("hidden")
	l.Warn("shown\n\"q\"")
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d lines: %q", len(lines), b.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"time", "level", "msg"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing %s", k)
		}
	}
}

// Feature: bellu-security-knowledge-graph, Property 44: Log format and level filtering
// **Validates: Requirements 20.12, 20.13, 20.14**
func TestPropertyLogFormatAndLevel(t *testing.T) {
	names := []string{"debug", "info", "warn", "error"}
	rapid.Check(t, func(t *rapid.T) {
		cfg := rapid.IntRange(0, 3).Draw(t, "cfg")
		lvl := rapid.IntRange(0, 3).Draw(t, "lvl")
		msg := rapid.String().Draw(t, "msg")
		var b bytes.Buffer
		l, err := NewJSONLogger(&b, names[cfg])
		if err != nil {
			t.Fatal(err)
		}
		switch lvl {
		case 0:
			l.Debug(msg)
		case 1:
			l.Info(msg)
		case 2:
			l.Warn(msg)
		case 3:
			l.Error(msg)
		}
		if (b.Len() > 0) != (lvl >= cfg) {
			t.Fatalf("cfg=%d lvl=%d out=%q", cfg, lvl, b.String())
		}
		if b.Len() > 0 {
			out := b.String()
			if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
				t.Fatalf("not one line: %q", out)
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(out), &m); err != nil {
				t.Fatal(err)
			}
			for _, k := range []string{"time", "level", "msg"} {
				if _, ok := m[k]; !ok {
					t.Fatalf("missing %s", k)
				}
			}
		}
	})
}
