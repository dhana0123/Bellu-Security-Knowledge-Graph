package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/httpx"
)

type fakeClock struct{ slept []time.Duration }

func (c *fakeClock) Now() time.Time { return time.Unix(1000, 0) }
func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.slept = append(c.slept, d)
	return nil
}

var pol = httpx.Policy{Retries: 2, Base: time.Second}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func entries(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestDownloadStreamsAndHashes(t *testing.T) {
	body := []byte(strings.Repeat("0123456789abcdef", 1<<16)) // 1 MiB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		for off := 0; off < len(body); off += 4096 { // no Content-Length: chunked
			_, _ = w.Write(body[off : off+4096])
		}
	}))
	defer srv.Close()
	dir := filepath.Join(t.TempDir(), "nested", "cache")
	res, err := DownloadToCache(context.Background(), srv.Client(), srv.URL, dir, "all.zip", pol, &fakeClock{})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(res.Path)
	if res.Path != filepath.Join(dir, "all.zip") || res.Size != int64(len(body)) || res.SHA256 != sum(body) || string(got) != string(body) || res.ETag != `"v1"` {
		t.Fatalf("result %+v", res)
	}
	if es := entries(t, dir); len(es) != 1 || es[0] != "all.zip" {
		t.Fatalf("cache holds %v", es)
	}
}

func TestDownloadRetriesThenSucceeds(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch n.Add(1) {
		case 1:
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.WriteHeader(http.StatusBadGateway)
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	clk := &fakeClock{}
	dir := t.TempDir()
	res, err := DownloadToCache(context.Background(), srv.Client(), srv.URL, dir, "f", pol, clk)
	if err != nil || res.Size != 2 || n.Load() != 3 {
		t.Fatalf("res %+v err %v attempts %d", res, err, n.Load())
	}
	if len(clk.slept) != 2 || clk.slept[0] != 7*time.Second || clk.slept[1] != 2*time.Second {
		t.Fatalf("waits %v", clk.slept)
	}
}

func TestDownloadPermanentStatusKeepsOldFile(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{}
	_, err := DownloadToCache(context.Background(), srv.Client(), srv.URL+"/x?token=secret", dir, "f", pol, clk)
	if err == nil || !strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "secret") || len(clk.slept) != 0 {
		t.Fatalf("err %v slept %v", err, clk.slept)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "f")); string(b) != "old" {
		t.Fatal("old file was replaced")
	}
	if es := entries(t, dir); len(es) != 1 {
		t.Fatalf("leftovers %v", es)
	}
}

func TestDownloadTruncatedBodyLeavesNoFile(t *testing.T) {
	var n atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			buf := make([]byte, 4096)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort"))
			_ = c.Close()
		}
	}()
	dir := t.TempDir()
	_, err = DownloadToCache(context.Background(), http.DefaultClient, "http://"+ln.Addr().String(), dir, "f", pol, &fakeClock{})
	if err == nil || n.Load() != 3 {
		t.Fatalf("err %v attempts %d", err, n.Load())
	}
	if es := entries(t, dir); len(es) != 0 {
		t.Fatalf("leftovers %v", es)
	}
}

func TestDownloadHeadersLimitAndNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer t" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer srv.Close()
	dir := t.TempDir()
	h := http.Header{"Authorization": {"Bearer t"}}
	if _, err := DownloadWith(context.Background(), srv.Client(), srv.URL, dir, "a", pol, &fakeClock{}, Options{Header: h, MaxBytes: 10}); err == nil {
		t.Fatal("limit not enforced")
	}
	if es := entries(t, dir); len(es) != 0 {
		t.Fatalf("leftovers %v", es)
	}
	if res, err := DownloadWith(context.Background(), srv.Client(), srv.URL, dir, "a", pol, &fakeClock{}, Options{Header: h, MaxBytes: 100}); err != nil || res.Size != 100 {
		t.Fatalf("%+v %v", res, err)
	}
	for _, name := range []string{"", ".", "..", "a/b", `a\b`, "x.part", "../x"} {
		if _, err := DownloadToCache(context.Background(), srv.Client(), srv.URL, dir, name, pol, nil); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
}

func TestDownloadHostNotAllowedIsNotRetried(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	client := httpx.NewAllowList("example.org").NewClient(0)
	clk := &fakeClock{}
	_, err := DownloadToCache(context.Background(), client, srv.URL, t.TempDir(), "f", pol, clk)
	var denied *httpx.HostNotAllowedError
	if !errors.As(err, &denied) || len(clk.slept) != 0 {
		t.Fatalf("err %v slept %v", err, clk.slept)
	}
}

func TestDownloadStopsOnCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DownloadToCache(ctx, srv.Client(), srv.URL, t.TempDir(), "f", pol, &fakeClock{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}

func TestDownloadNetworkErrorHidesQuery(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens: connection refused
	_, err := DownloadToCache(context.Background(), http.DefaultClient, "http://"+addr+"/f?token=secret", t.TempDir(), "f", httpx.Policy{}, &fakeClock{})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("err %v", err)
	}
}
