package rawstore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: bellu-security-knowledge-graph, Property 1: Raw store fidelity and de-duplication
// Validates: Requirements 1.1, 1.2
func TestPropertyRawStoreFidelityAndDedup(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		fs := FS{Root: t.TempDir()}
		ctx := context.Background()
		source := rapid.StringMatching(`[a-z0-9_.:-]{1,64}`).
			Filter(func(s string) bool { return strings.Trim(s, ".") != "" }).Draw(rt, "source")
		payload := rapid.SliceOf(rapid.Byte()).Draw(rt, "payload")
		n := rapid.IntRange(2, 5).Draw(rt, "puts")

		first, err := fs.Put(ctx, source, "id", payload)
		if err != nil {
			rt.Fatal(err)
		}
		if first.Duplicate {
			rt.Fatal("first put reported duplicate")
		}
		if first.Hash != Hash(payload) {
			rt.Fatal("hash mismatch")
		}
		disk, err := os.ReadFile(filepath.Join(fs.Root, source, first.Hash[:2], first.Hash+".json"))
		if err != nil || !bytes.Equal(disk, payload) {
			rt.Fatalf("stored bytes differ: %v", err)
		}
		for i := 1; i < n; i++ {
			r, err := fs.Put(ctx, source, "id", payload)
			if err != nil {
				rt.Fatal(err)
			}
			if !r.Duplicate || r.Hash != first.Hash || !r.FetchedAt.Equal(first.FetchedAt) {
				rt.Fatalf("later put %+v vs first %+v", r, first)
			}
		}
		count := 0
		_ = filepath.Walk(fs.Root, func(p string, fi os.FileInfo, err error) error {
			if err == nil && !fi.IsDir() && strings.HasSuffix(p, ".json") && !strings.HasSuffix(p, ".meta.json") {
				count++
			}
			return nil
		})
		if count != 1 {
			rt.Fatalf("payload copies = %d", count)
		}
	})
}
