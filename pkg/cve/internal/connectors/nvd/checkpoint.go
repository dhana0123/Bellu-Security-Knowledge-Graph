package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors"
)

// Checkpointer persists the NVD cursor as an opaque JSON document. Implementations
// back it with memory, a file or the canonical database (sync_state). Load returns
// (nil, nil) when nothing has been saved yet.
type Checkpointer interface {
	Load(ctx context.Context) (json.RawMessage, error)
	Save(ctx context.Context, cursor json.RawMessage) error
}

// Cursor is the persisted progress of one NVD run. A run covers [RunStart, RunEnd]
// split into windows of at most MaxWindow. WindowStart identifies the window in
// progress and NextIndex is the next startIndex to request in it. Complete is set
// when every window has been read; RunEnd is then the high-water mark for the next
// incremental run.
type Cursor struct {
	Version     int             `json:"version"`
	Mode        connectors.Mode `json:"mode"`
	RunStart    time.Time       `json:"run_start"`
	RunEnd      time.Time       `json:"run_end"`
	WindowStart time.Time       `json:"window_start"`
	WindowEnd   time.Time       `json:"window_end"`
	NextIndex   int             `json:"next_index"`
	Complete    bool            `json:"complete"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

const cursorVersion = 1

// MemoryCheckpoint keeps the cursor in memory.
type MemoryCheckpoint struct {
	mu  sync.Mutex
	cur json.RawMessage
}

func (m *MemoryCheckpoint) Load(context.Context) (json.RawMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append(json.RawMessage(nil), m.cur...), nil
}

func (m *MemoryCheckpoint) Save(_ context.Context, c json.RawMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cur = append(json.RawMessage(nil), c...)
	return nil
}

// FileCheckpoint stores the cursor in a JSON file, replaced atomically on each save.
type FileCheckpoint struct{ Path string }

func (f FileCheckpoint) Load(context.Context) (json.RawMessage, error) {
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (f FileCheckpoint) Save(_ context.Context, c json.RawMessage) error {
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".nvd-cursor-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(c); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}

func loadCursor(ctx context.Context, cp Checkpointer) (*Cursor, error) {
	raw, err := cp.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("nvd: load checkpoint: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var c Cursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("nvd: corrupt checkpoint: %w", err)
	}
	if c.Version != cursorVersion {
		return nil, fmt.Errorf("nvd: unsupported checkpoint version %d", c.Version)
	}
	return &c, nil
}

func saveCursor(ctx context.Context, cp Checkpointer, c *Cursor, now time.Time) error {
	c.Version = cursorVersion
	c.UpdatedAt = now.UTC()
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	// Saving must succeed even if ctx was cancelled just after a page completed.
	if err := cp.Save(context.WithoutCancel(ctx), b); err != nil {
		return fmt.Errorf("nvd: save checkpoint: %w", err)
	}
	return nil
}
