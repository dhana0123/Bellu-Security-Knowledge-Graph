package nvd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors"
)

// Feature: bellu-security-knowledge-graph, Property 3: Incremental window and paging coverage.
// **Validates: Requirements 1.3, 1.4, 1.5, 1.6**

func genTime(t *rapid.T, label string, lo, hi int64) time.Time {
	return time.Unix(rapid.Int64Range(lo, hi).Draw(t, label), 0).UTC()
}

func TestPropertyWindowsCoverInterval(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		since := genTime(t, "since", 0, 2_000_000_000)
		span := rapid.Int64Range(1, 40*365*86400).Draw(t, "span")
		end := since.Add(time.Duration(span) * time.Second)
		ws := Windows(since, end, MaxWindow)
		if len(ws) == 0 {
			t.Fatalf("no windows for %v..%v", since, end)
		}
		if !ws[0].Start.Equal(since) || !ws[len(ws)-1].End.Equal(end) {
			t.Fatalf("coverage mismatch: %v..%v got %v", since, end, ws)
		}
		for i, w := range ws {
			if !w.End.After(w.Start) || w.End.Sub(w.Start) > MaxWindow {
				t.Fatalf("window %d invalid: %v", i, w)
			}
			if i > 0 && !w.Start.Equal(ws[i-1].End) {
				t.Fatalf("gap before window %d", i)
			}
		}
		if Windows(end, since, MaxWindow) != nil {
			t.Fatal("reversed range must be empty")
		}
	})
}

type pagedServer struct {
	mu       sync.Mutex
	total    int
	pageSize int
	starts   []int
	froms    []string
	ends     []string
}

func (s *pagedServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	si, _ := strconv.Atoi(q.Get("startIndex"))
	s.mu.Lock()
	s.starts = append(s.starts, si)
	s.froms = append(s.froms, q.Get("lastModStartDate"))
	s.ends = append(s.ends, q.Get("lastModEndDate"))
	s.mu.Unlock()
	resp := Response{StartIndex: si, TotalResults: s.total, ResultsPerPage: s.pageSize}
	for i := si; i < si+s.pageSize && i < s.total; i++ {
		resp.Vulnerabilities = append(resp.Vulnerabilities, json.RawMessage(fmt.Sprintf(`{"cve":{"id":"CVE-2024-%05d"}}`, i)))
	}
	json.NewEncoder(w).Encode(resp)
}

func TestPropertyFetchPagingExactlyOnce(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		total := rapid.IntRange(0, 60).Draw(t, "total")
		page := rapid.IntRange(1, 25).Draw(t, "pageSize")
		ps := &pagedServer{total: total, pageSize: page}
		srv := httptest.NewServer(ps)
		defer srv.Close()

		now := time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)
		since := now.Add(-time.Duration(rapid.IntRange(1, 100*24).Draw(t, "hours")) * time.Hour) // single window
		c := newTestClient(srv.URL, "", now)
		seen := map[string]int{}
		for it, err := range c.Fetch(t.Context(), connectors.Incremental, since) {
			if err != nil {
				t.Fatal(err)
			}
			seen[it.ID]++
		}
		if len(seen) != total {
			t.Fatalf("got %d distinct ids, want %d", len(seen), total)
		}
		for id, n := range seen {
			if n != 1 {
				t.Fatalf("%s yielded %d times", id, n)
			}
		}
		wantReqs := (total + page - 1) / page
		if wantReqs == 0 {
			wantReqs = 1
		}
		if len(ps.starts) != wantReqs {
			t.Fatalf("requests = %v, want %d (total %d page %d)", ps.starts, wantReqs, total, page)
		}
		for i, s := range ps.starts {
			if s != i*page {
				t.Fatalf("request %d startIndex=%d want %d", i, s, i*page)
			}
			if s >= total && total > 0 {
				t.Fatalf("request at startIndex %d >= totalResults %d", s, total)
			}
		}
	})
}

func TestPropertyIncrementalWindows(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ps := &pagedServer{total: 0, pageSize: 1}
		srv := httptest.NewServer(ps)
		defer srv.Close()

		now := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(rapid.Int64Range(0, 30*365*86400).Draw(t, "nowOff")) * time.Second)
		c := newTestClient(srv.URL, "", now)

		var since time.Time
		zero := rapid.Bool().Draw(t, "zeroSince")
		expectStart := FullStart
		if !zero {
			since = FullStart.Add(time.Duration(rapid.Int64Range(0, 30*365*86400).Draw(t, "sinceOff")) * time.Second)
			expectStart = since
		}
		for _, err := range c.Fetch(t.Context(), connectors.Incremental, since) {
			if err != nil {
				t.Fatal(err)
			}
		}
		want := Windows(expectStart, now, MaxWindow)
		if len(ps.froms) != len(want) {
			t.Fatalf("requests=%d want windows=%d", len(ps.froms), len(want))
		}
		for i, w := range want {
			if ps.froms[i] != w.Start.Format(dateLayout) || ps.ends[i] != w.End.Format(dateLayout) {
				t.Fatalf("window %d: got %s..%s want %v", i, ps.froms[i], ps.ends[i], w)
			}
		}
		if len(want) > 0 && ps.froms[0] != expectStart.Format(dateLayout) {
			t.Fatalf("first window starts %s, want %s", ps.froms[0], expectStart)
		}
	})
}
