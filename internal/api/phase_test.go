package api

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestVulnerabilityFoundByAlias(t *testing.T) {
	const adv = "GHSA-c2f3-4gh5-wxmp"
	var byID []any
	var aliases any
	e := entityEnv(t, func(_ context.Context, q string, p map[string]any) ([]Row, error) {
		switch q {
		case cypherVulnerabilityByID:
			byID = append(byID, p["id"])
			if p["id"] == "CVE-2021-1001" {
				return []Row{{"props": map[string]any{"cveID": "CVE-2021-1001", "aliases": []any{adv}}}}, nil
			}
			return nil, nil
		case cypherVulnerabilityByAlias:
			aliases = p["aliases"]
			return []Row{{"cveID": "CVE-2021-1001"}}, nil
		}
		t.Fatalf("unexpected query %s", q)
		return nil, nil
	})
	code, body := getJSON(t, e, "/v1/vulnerabilities/GHSA-C2F3-4GH5-WXMP")
	if code != 200 {
		t.Fatalf("code=%d body=%v", code, body)
	}
	if v := body["vulnerability"].(map[string]any); v["cveID"] != "CVE-2021-1001" {
		t.Fatalf("vulnerability %v", v)
	}
	if len(byID) != 2 || byID[0] != adv || byID[1] != "CVE-2021-1001" {
		t.Fatalf("detail ids %v", byID)
	}
	if l, _ := aliases.([]string); len(l) == 0 || l[0] != adv {
		t.Fatalf("alias candidates %v", aliases)
	}
}

func TestVulnerabilityAliasMissIs404(t *testing.T) {
	e := entityEnv(t, func(context.Context, string, map[string]any) ([]Row, error) { return nil, nil })
	code, body := getJSON(t, e, "/v1/vulnerabilities/ghsa-c2f3-4gh5-wxmp")
	eb, _ := body["error"].(map[string]any)
	if code != 404 || eb["message"] != "Vulnerability GHSA-c2f3-4gh5-wxmp not found" {
		t.Fatalf("code=%d body=%v", code, body)
	}
}

func TestComputeStatsPhase(t *testing.T) {
	var seen []string
	run := func(_ context.Context, q string, _ map[string]any) ([]Row, error) {
		seen = append(seen, q)
		return []Row{{"n": int64(0)}}, nil
	}
	has := func(sub string) bool {
		for _, q := range seen {
			if strings.Contains(q, sub) {
				return true
			}
		}
		return false
	}
	if _, err := computeStats(context.Background(), run, time.Now(), 1); err != nil {
		t.Fatal(err)
	}
	if has("(n:Package)") || has("AttackPattern") || has("AFFECTS_PACKAGE") {
		t.Fatalf("phase 1 counted a later phase: %v", seen)
	}
	seen = nil
	res, err := computeStats(context.Background(), run, time.Now(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if !has("(n:Package)") || !has("AFFECTS_PACKAGE") || has("AttackPattern") || has("ADAPTED_FROM") {
		t.Fatalf("phase 2 queries: %v", seen)
	}
	if len(res.Labels) == 0 {
		t.Fatal("no labels")
	}
	seen = nil
	if _, err := computeStats(context.Background(), run, time.Now(), 3); err != nil {
		t.Fatal(err)
	}
	if !has("(n:AtlasTechnique)") || !has("ADAPTED_FROM") {
		t.Fatalf("phase 3 queries: %v", seen)
	}
}

func TestMaxPhaseFollowsMigrationsAtCacheTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	version := int64(3)
	calls := 0
	q := func(context.Context, string, map[string]any) ([]Row, error) {
		calls++
		return []Row{{"version": version}}, nil
	}
	s := New(Config{Now: func() time.Time { return now }, Phase: MigrationPhase(q)})
	ctx := context.Background()
	if got := s.maxPhase(ctx); got != 1 {
		t.Fatalf("V003 gives phase %d, want 1", got)
	}
	version = 201
	if got := s.maxPhase(ctx); got != 1 || calls != 1 {
		t.Fatalf("cached value expected, got %d after %d calls", got, calls)
	}
	now = now.Add(MetaCacheTTL + time.Millisecond)
	if got := s.maxPhase(ctx); got != 3 || calls != 2 {
		t.Fatalf("V201 gives phase %d after %d calls, want 3", got, calls)
	}
	version = 101
	now = now.Add(MetaCacheTTL + time.Millisecond)
	if got := s.maxPhase(ctx); got != 2 {
		t.Fatalf("V101 gives phase %d, want 2", got)
	}
	// Without a Phase function the configured value is used.
	if got := New(Config{MaxPhase: 2}).maxPhase(ctx); got != 2 {
		t.Fatalf("static phase %d", got)
	}
}
