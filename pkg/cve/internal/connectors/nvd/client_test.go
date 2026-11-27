package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors"
)

func TestWindowsGapFree(t *testing.T) {
	since := FullStart
	end := time.Date(2024, 3, 7, 5, 0, 0, 0, time.UTC)
	ws := Windows(since, end, MaxWindow)
	if len(ws) == 0 || !ws[0].Start.Equal(since) || !ws[len(ws)-1].End.Equal(end) {
		t.Fatalf("bad coverage: %v", ws)
	}
	for i, w := range ws {
		if w.End.Sub(w.Start) > MaxWindow || !w.End.After(w.Start) {
			t.Fatalf("window %d span invalid: %v", i, w)
		}
		if i > 0 && !w.Start.Equal(ws[i-1].End) {
			t.Fatalf("gap at %d", i)
		}
	}
	if Windows(end, since, MaxWindow) != nil || Windows(since, since, MaxWindow) != nil {
		t.Fatal("empty range must yield no windows")
	}
}

type rec struct {
	mu    sync.Mutex
	reqs  []map[string]string
	keys  []string
	total int
}

func (r *rec) handler(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	r.mu.Lock()
	r.reqs = append(r.reqs, map[string]string{"start": q.Get("startIndex"), "per": q.Get("resultsPerPage"), "from": q.Get("lastModStartDate")})
	r.keys = append(r.keys, req.Header.Get("apiKey"))
	r.mu.Unlock()
	si, _ := strconv.Atoi(q.Get("startIndex"))
	// serve at most 2 items per page to exercise paging
	resp := Response{StartIndex: si, TotalResults: r.total}
	for i := si; i < si+2 && i < r.total; i++ {
		resp.Vulnerabilities = append(resp.Vulnerabilities, json.RawMessage(fmt.Sprintf(`{"cve":{"id":"CVE-2024-%04d"}}`, i)))
	}
	json.NewEncoder(w).Encode(resp)
}

func newTestClient(url, key string, now time.Time) *Client {
	c := NewClient(url, key)
	c.HTTP.SetSleeper(func(context.Context, time.Duration) error { return nil })
	c.Now = func() time.Time { return now }
	return c
}

func TestFetchPagesAndAPIKey(t *testing.T) {
	r := &rec{total: 5}
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()
	now := time.Date(2024, 1, 10, 0, 0, 0, 0, time.UTC)
	c := newTestClient(srv.URL, "secret", now)
	since := now.Add(-24 * time.Hour)
	var ids []string
	for it, err := range c.Fetch(context.Background(), connectors.Incremental, since) {
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, it.ID)
	}
	if len(ids) != 5 || ids[4] != "CVE-2024-0004" {
		t.Fatalf("ids = %v", ids)
	}
	if len(r.reqs) != 3 || r.reqs[1]["start"] != "2" || r.reqs[2]["start"] != "4" {
		t.Fatalf("paging reqs = %v", r.reqs)
	}
	for i, k := range r.keys {
		if k != "secret" || r.reqs[i]["per"] != "2000" {
			t.Fatalf("req %d key=%q per=%q", i, k, r.reqs[i]["per"])
		}
	}
}

func TestIncrementalFallsBackToFull(t *testing.T) {
	r := &rec{total: 1}
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()
	now := time.Date(1999, 6, 1, 0, 0, 0, 0, time.UTC)
	c := newTestClient(srv.URL, "", now)
	for _, err := range c.Fetch(context.Background(), connectors.Incremental, time.Time{}) {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(r.reqs) == 0 || r.reqs[0]["from"] != "1999-01-01T00:00:00.000Z" {
		t.Fatalf("reqs = %v", r.reqs)
	}
	if r.keys[0] != "" {
		t.Fatal("apiKey header must be absent without key")
	}
}
