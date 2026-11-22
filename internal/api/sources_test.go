package api

import (
	"context"
	"testing"
)

func TestSourcesEndpoint(t *testing.T) {
	e := entityEnv(t, func(context.Context, string, map[string]any) ([]Row, error) { return nil, nil })
	if rec := e.do("/v1/sources", ""); rec.Code != 401 {
		t.Fatalf("unauthenticated status = %d, want 401", rec.Code)
	}
	code, body := getJSON(t, e, "/v1/sources")
	if code != 200 {
		t.Fatalf("status = %d", code)
	}
	list, _ := body["sources"].([]any)
	if len(list) != 10 {
		t.Fatalf("sources = %v", body["sources"])
	}
	for i, want := range []string{"cwe", "nvd", "exploitdb", "attack", "atlas", "capec", "kev", "epss", "osv", "ghsa"} {
		m := list[i].(map[string]any)
		if m["name"] != want || m["license"] == "" || m["attribution"] == "" {
			t.Errorf("entry %d = %v", i, m)
		}
	}
	if _, ok := body["graph"].(map[string]any); !ok {
		t.Error("missing graph envelope")
	}
}
