package osv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Checkpointer persists one opaque JSON cursor per ecosystem. Implementations may
// be backed by memory, files or a database table (sync_state).
type Checkpointer interface {
	// Load returns the stored cursor for key, or (nil, nil) when none exists.
	Load(ctx context.Context, key string) (json.RawMessage, error)
	// Save replaces the cursor for key. It must be durable when it returns.
	Save(ctx context.Context, key string, cursor json.RawMessage) error
}

// Cursor is the per-ecosystem checkpoint stored (as JSON) through a Checkpointer.
type Cursor struct {
	// Completed is the newest record modification time covered by a finished run.
	// Incremental runs fetch only records modified strictly after it.
	Completed time.Time `json:"completed,omitzero"`
	// FullPass is the number of the last full pass this ecosystem completed. A full
	// pass is complete once every selected ecosystem has reached the highest number;
	// only then does the next full run start pass number+1 (see fullTarget).
	FullPass int `json:"full_pass,omitempty"`
	// Partial is set while an all.zip pass is unfinished and lets it resume.
	Partial *ZipProgress `json:"partial,omitempty"`
}

// ZipProgress records how far an interrupted all.zip pass got.
type ZipProgress struct {
	// Ident identifies the downloaded archive (generation/etag plus size). Progress
	// is only reused when the archive on resume has the same Ident.
	Ident string `json:"ident"`
	// Done is the number of zip entries fully handled, in archive order.
	Done int `json:"done"`
	// MaxModified is the newest modified time seen among those entries.
	MaxModified time.Time `json:"max_modified,omitzero"`
}

// MemoryCheckpoints is an in-memory Checkpointer.
type MemoryCheckpoints struct {
	mu sync.Mutex
	m  map[string]json.RawMessage
}

// NewMemoryCheckpoints returns an empty in-memory store.
func NewMemoryCheckpoints() *MemoryCheckpoints {
	return &MemoryCheckpoints{m: map[string]json.RawMessage{}}
}

func (c *MemoryCheckpoints) Load(_ context.Context, key string) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[key]
	if !ok {
		return nil, nil
	}
	return append(json.RawMessage(nil), v...), nil
}

func (c *MemoryCheckpoints) Save(_ context.Context, key string, cursor json.RawMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = append(json.RawMessage(nil), cursor...)
	return nil
}

// FileCheckpoints stores one JSON file per ecosystem in a directory.
type FileCheckpoints struct{ Dir string }

// NewFileCheckpoints returns a file-backed store rooted at dir (created on first Save).
func NewFileCheckpoints(dir string) *FileCheckpoints { return &FileCheckpoints{Dir: dir} }

func (c *FileCheckpoints) path(key string) string {
	return filepath.Join(c.Dir, "osv-"+url.QueryEscape(key)+".json")
}

func (c *FileCheckpoints) Load(_ context.Context, key string) (json.RawMessage, error) {
	b, err := os.ReadFile(c.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Save writes atomically (temp file, fsync, rename).
func (c *FileCheckpoints) Save(_ context.Context, key string, cursor json.RawMessage) error {
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(c.Dir, ".osv-cursor-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(cursor)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(tmp)
		return werr
	}
	if err := os.Rename(tmp, c.path(key)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func loadCursor(ctx context.Context, cp Checkpointer, eco string) (Cursor, error) {
	var cur Cursor
	raw, err := cp.Load(ctx, eco)
	if err != nil {
		return cur, fmt.Errorf("load checkpoint: %w", err)
	}
	if len(raw) == 0 {
		return cur, nil
	}
	if err := json.Unmarshal(raw, &cur); err != nil {
		return Cursor{}, fmt.Errorf("decode checkpoint: %w", err)
	}
	return cur, nil
}

func saveCursor(ctx context.Context, cp Checkpointer, eco string, cur Cursor) error {
	raw, err := json.Marshal(cur)
	if err != nil {
		return err
	}
	if err := cp.Save(ctx, eco, raw); err != nil {
		return fmt.Errorf("save checkpoint: %w", err)
	}
	return nil
}
