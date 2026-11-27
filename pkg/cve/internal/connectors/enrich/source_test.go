package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/connectors"
)

func TestKEVAndEPSSSources(t *testing.T) {
	fx := filepath.Join("..", "..", "..", "tests", "fixtures")
	srv := httptest.NewServer(http.FileServer(http.Dir(fx)))
	defer srv.Close()
	cases := []struct {
		s    *Source
		name string
	}{
		{NewKEV(filepath.Join(fx, "kev", "known_exploited_vulnerabilities.json")), "kev"},
		{NewEPSS(srv.URL + "/epss/epss_scores.csv"), "epss"},
	}
	for _, c := range cases {
		if c.s.Name() != c.name {
			t.Fatalf("name %s", c.s.Name())
		}
		for _, m := range []connectors.Mode{connectors.Full, connectors.Incremental} {
			n := 0
			for it, err := range c.s.Fetch(context.Background(), m, time.Now()) {
				if err != nil || it.ID != c.name || len(it.Payload) == 0 {
					t.Fatalf("%s: %v %v", c.name, it.ID, err)
				}
				n++
			}
			if n != 1 {
				t.Fatalf("%s mode %d: %d items", c.name, m, n)
			}
		}
	}
}

func TestSourceRejectsBadPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("not json")) }))
	defer srv.Close()
	for _, err := range NewKEV(srv.URL).Fetch(context.Background(), connectors.Full, time.Time{}) {
		if err == nil {
			t.Fatal("expected error")
		}
	}
}
