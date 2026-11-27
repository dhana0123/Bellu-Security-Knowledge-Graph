// Package rawstore keeps the unmodified source payloads, addressed by content hash,
// so the canonical store and graph can always be rebuilt from them.
package rawstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// PutResult describes the outcome of a Put.
type PutResult struct {
	Hash      string    // sha256 hex over stored bytes
	URI       string    // file:// URI of the payload
	Duplicate bool      // same (source, hash) already present
	FetchedAt time.Time // retrieval time of the FIRST copy, UTC, ms precision
}

// Meta is the sidecar metadata stored next to each payload.
type Meta struct {
	Source    string    `json:"source"`
	ID        string    `json:"id"`
	FetchedAt time.Time `json:"fetched_at"`
	SHA256    string    `json:"sha256"`
}

type Store interface {
	// Put stores payload (idempotent) and returns its sha256, URI and duplicate state.
	Put(ctx context.Context, source, id string, payload []byte) (PutResult, error)
	// Get returns the stored payload and its metadata.
	Get(ctx context.Context, source, hash string) ([]byte, Meta, error)
}

func Hash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

var (
	safe    = regexp.MustCompile(`^[a-z0-9_.:-]{1,64}$`)
	hashRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	dotOnly = regexp.MustCompile(`^\.+$`)
)

func validSource(s string) bool { return safe.MatchString(s) && !dotOnly.MatchString(s) }

// FS is a filesystem-backed store: <root>/<source>/<hash[:2]>/<hash>.json
// with a sidecar <hash>.meta.json.
type FS struct{ Root string }

var _ Store = FS{}

func (f FS) paths(source, h string) (dir, payload, meta string) {
	dir = filepath.Join(f.Root, source, h[:2])
	return dir, filepath.Join(dir, h+".json"), filepath.Join(dir, h+".meta.json")
}

func writeAtomic(dir, path string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("write raw payload: %v %v", werr, cerr)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

func readMeta(path string) (Meta, error) {
	var m Meta
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("parse %s: %w", path, err)
	}
	return m, nil
}

func (f FS) Put(ctx context.Context, source, id string, payload []byte) (PutResult, error) {
	if !validSource(source) {
		return PutResult{}, fmt.Errorf("invalid source name %q", source)
	}
	if err := ctx.Err(); err != nil {
		return PutResult{}, err
	}
	h := Hash(payload)
	dir, path, metaPath := f.paths(source, h)
	uri := "file://" + path
	if _, err := os.Stat(path); err == nil {
		res := PutResult{Hash: h, URI: uri, Duplicate: true}
		if m, err := readMeta(metaPath); err == nil {
			res.FetchedAt = m.FetchedAt.UTC().Truncate(time.Millisecond)
		} else if fi, serr := os.Stat(path); serr == nil {
			res.FetchedAt = fi.ModTime().UTC().Truncate(time.Millisecond)
		}
		return res, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return PutResult{}, err
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	mb, err := json.Marshal(Meta{Source: source, ID: id, FetchedAt: now, SHA256: h})
	if err != nil {
		return PutResult{}, err
	}
	// Sidecar first so a visible payload always has metadata.
	if err := writeAtomic(dir, metaPath, mb); err != nil {
		return PutResult{}, err
	}
	if err := writeAtomic(dir, path, payload); err != nil {
		return PutResult{}, err
	}
	return PutResult{Hash: h, URI: uri, FetchedAt: now}, nil
}

func (f FS) Get(ctx context.Context, source, hash string) ([]byte, Meta, error) {
	if !validSource(source) {
		return nil, Meta{}, fmt.Errorf("invalid source name %q", source)
	}
	if !hashRe.MatchString(hash) {
		return nil, Meta{}, fmt.Errorf("invalid hash %q", hash)
	}
	if err := ctx.Err(); err != nil {
		return nil, Meta{}, err
	}
	_, path, metaPath := f.paths(source, hash)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, Meta{}, err
	}
	m, err := readMeta(metaPath)
	if err != nil {
		return nil, Meta{}, err
	}
	return b, m, nil
}
