package rawstore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPutGetFidelity(t *testing.T) {
	fs := FS{Root: t.TempDir()}
	payload := []byte("{\"a\": 1,\r\n  \"b\":\t[ ]}\x00\xff")
	res, err := fs.Put(context.Background(), "osv", "CVE-1", payload)
	if err != nil {
		t.Fatal(err)
	}
	if res.Duplicate || res.Hash != Hash(payload) || res.FetchedAt.IsZero() {
		t.Fatalf("unexpected result %+v", res)
	}
	want := filepath.Join(fs.Root, "osv", res.Hash[:2], res.Hash+".json")
	if res.URI != "file://"+want {
		t.Fatalf("uri %q", res.URI)
	}
	disk, _ := os.ReadFile(want)
	if !bytes.Equal(disk, payload) {
		t.Fatal("stored bytes differ")
	}
	got, meta, err := fs.Get(context.Background(), "osv", res.Hash)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("get: %v", err)
	}
	if meta.Source != "osv" || meta.ID != "CVE-1" || meta.SHA256 != res.Hash || !meta.FetchedAt.Equal(res.FetchedAt) {
		t.Fatalf("meta %+v", meta)
	}
}

func TestDuplicateKeepsOriginalFetchedAt(t *testing.T) {
	fs := FS{Root: t.TempDir()}
	ctx := context.Background()
	first, err := fs.Put(ctx, "nvd", "a", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	for i := 0; i < 3; i++ {
		r, err := fs.Put(ctx, "nvd", "b", []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		if !r.Duplicate || !r.FetchedAt.Equal(first.FetchedAt) || r.Hash != first.Hash {
			t.Fatalf("dup %+v first %+v", r, first)
		}
	}
	_, meta, _ := fs.Get(ctx, "nvd", first.Hash)
	if meta.ID != "a" {
		t.Fatalf("sidecar overwritten: %+v", meta)
	}
	files, _ := os.ReadDir(filepath.Dir(first.URI[len("file://"):]))
	if len(files) != 2 {
		t.Fatalf("want payload+sidecar only, got %d entries", len(files))
	}
}

func TestInvalidSourceRejected(t *testing.T) {
	fs := FS{Root: t.TempDir()}
	for _, s := range []string{"", "..", ".", "../x", "a/b", "UP", "a b"} {
		if _, err := fs.Put(context.Background(), s, "id", []byte("x")); err == nil {
			t.Errorf("source %q accepted", s)
		}
		if _, _, err := fs.Get(context.Background(), s, Hash([]byte("x"))); err == nil {
			t.Errorf("get source %q accepted", s)
		}
	}
	if _, _, err := fs.Get(context.Background(), "osv", "../../etc"); err == nil {
		t.Error("bad hash accepted")
	}
}
