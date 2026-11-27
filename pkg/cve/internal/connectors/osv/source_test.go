package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors"
)

func collect(t *testing.T, s *Source, m connectors.Mode, since time.Time) (ids []string, errs int) {
	for it, err := range s.Fetch(context.Background(), m, since) {
		if err != nil {
			errs++
			continue
		}
		ids = append(ids, it.ID)
	}
	return
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSourceFullAndIncremental(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.json", `{"id":"a-1","modified":"2024-01-01T00:00:00Z"}`)
	write(t, dir, "b.json", `{"id":"b-1","modified":"2024-06-01T00:00:00Z"}`)
	write(t, dir, "bad.json", `{nope`)
	s := NewGHSA(dir)
	if s.Name() != "ghsa" || NewOSV(dir).Name() != "osv" {
		t.Fatal("names")
	}
	ids, errs := collect(t, s, connectors.Full, time.Time{})
	if len(ids) != 2 || errs != 1 || ids[0] != "A-1" {
		t.Fatalf("full: %v %d", ids, errs)
	}
	since := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	ids, _ = collect(t, s, connectors.Incremental, since)
	if len(ids) != 1 || ids[0] != "B-1" {
		t.Fatalf("incremental: %v", ids)
	}
	ids, _ = collect(t, s, connectors.Incremental, time.Time{})
	if len(ids) != 2 {
		t.Fatalf("zero since: %v", ids)
	}
}

func TestSourceFixturesAndHTTP(t *testing.T) {
	fx := filepath.Join("..", "..", "..", "tests", "fixtures", "osv")
	ids, errs := collect(t, NewOSV(fx), connectors.Full, time.Time{})
	if len(ids) != 2 || errs != 0 {
		t.Fatalf("fixtures: %v %d", ids, errs)
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(fx)))
	defer srv.Close()
	ids, errs = collect(t, NewOSV(srv.URL+"/PYSEC-2020-1.json"), connectors.Full, time.Time{})
	if len(ids) != 1 || errs != 0 {
		t.Fatalf("http: %v %d", ids, errs)
	}
}

func TestSourceMissingLocation(t *testing.T) {
	if _, errs := collect(t, NewOSV(filepath.Join(t.TempDir(), "none")), connectors.Full, time.Time{}); errs != 1 {
		t.Fatalf("errs=%d", errs)
	}
}
