package api

import (
	"context"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/checkpoint"
)

// phaseEnv is an entity env whose schema phase is fixed at phase.
func phaseEnv(t *testing.T, phase int, q queryFunc) *env {
	t.Helper()
	e := entityEnv(t, q)
	e.srv.cfg.MaxPhase, e.srv.phaseVal = phase, phase
	return e
}

func TestVulnerabilityDetailLinks(t *testing.T) {
	var asked []string
	var limits []any
	q := func(_ context.Context, q string, p map[string]any) ([]Row, error) {
		asked = append(asked, q)
		switch q {
		case cypherVulnerabilityByID:
			return []Row{{"props": map[string]any{"cveID": "CVE-2021-44228", "kev": true, "epssScore": 0.97}}}, nil
		case cypherVulnerabilityPackages:
			limits = append(limits, p["limit"])
			if p["id"] != "CVE-2021-44228" {
				t.Errorf("id = %v", p["id"])
			}
			return []Row{
				{"purl": "pkg:maven/org.apache/log4j", "ecosystem": "Maven", "name": "org.apache:log4j", "introduced": "2.0", "fixed": "2.15.0", "lastAffected": nil, "affectedRanges": []any{"[2.0,2.15.0)"}},
				{"purl": "pkg:npm/x", "ecosystem": nil, "name": nil, "introduced": nil, "fixed": nil, "lastAffected": nil, "affectedRanges": nil},
			}, nil
		case cypherVulnerabilityAttackPatterns:
			return []Row{{"capecID": "CAPEC-66", "name": "SQL Injection", "viaWeakness": "CWE-89"}}, nil
		case cypherVulnerabilityTechniques:
			return []Row{{"attackID": "T1190", "name": "Exploit Public-Facing Application", "viaAttackPattern": "CAPEC-66"}}, nil
		}
		t.Fatalf("unexpected query %s", q)
		return nil, nil
	}
	e := phaseEnv(t, 3, q)
	code, body := getJSON(t, e, "/v1/vulnerabilities/CVE-2021-44228")
	if code != 200 {
		t.Fatalf("%d %v", code, body)
	}
	if v := body["vulnerability"].(map[string]any); v["kev"] != true || v["epssScore"] != 0.97 {
		t.Fatalf("vulnerability %v", v)
	}
	pk := body["packages"].([]any)
	if len(pk) != 2 {
		t.Fatalf("packages %v", pk)
	}
	p0, p1 := pk[0].(map[string]any), pk[1].(map[string]any)
	if p0["purl"] != "pkg:maven/org.apache/log4j" || p0["fixed"] != "2.15.0" || p0["lastAffected"] != nil || len(p0["affectedRanges"].([]any)) != 1 {
		t.Fatalf("package 0 %v", p0)
	}
	for _, k := range []string{"ecosystem", "name", "introduced", "fixed", "lastAffected"} {
		if v, ok := p1[k]; !ok || v != nil {
			t.Errorf("package 1 %s = %v (present %v), want null", k, v, ok)
		}
	}
	if r, ok := p1["affectedRanges"].([]any); !ok || len(r) != 0 {
		t.Errorf("affectedRanges = %#v", p1["affectedRanges"])
	}
	if ap := body["attackPatterns"].([]any)[0].(map[string]any); ap["capecID"] != "CAPEC-66" || ap["viaWeakness"] != "CWE-89" || ap["name"] != "SQL Injection" {
		t.Fatalf("attackPatterns %v", ap)
	}
	if te := body["techniques"].([]any)[0].(map[string]any); te["attackID"] != "T1190" || te["viaAttackPattern"] != "CAPEC-66" {
		t.Fatalf("techniques %v", te)
	}
	if limits[0] != maxLinked {
		t.Fatalf("limit %v", limits[0])
	}
}

func TestVulnerabilityDetailLinksPhaseGated(t *testing.T) {
	for phase, want := range map[int][]string{
		1: {cypherVulnerabilityByID},
		2: {cypherVulnerabilityByID, cypherVulnerabilityPackages},
	} {
		var asked []string
		e := phaseEnv(t, phase, func(_ context.Context, q string, _ map[string]any) ([]Row, error) {
			asked = append(asked, q)
			if q == cypherVulnerabilityByID {
				return []Row{{"props": map[string]any{"cveID": "CVE-2021-1"}}}, nil
			}
			return nil, nil
		})
		code, body := getJSON(t, e, "/v1/vulnerabilities/CVE-2021-1")
		if code != 200 || strings.Join(asked, "|") != strings.Join(want, "|") {
			t.Errorf("phase %d: code=%d asked %d queries", phase, code, len(asked))
		}
		for _, k := range []string{"packages", "attackPatterns", "techniques"} {
			if l, ok := body[k].([]any); !ok || len(l) != 0 {
				t.Errorf("phase %d: %s = %#v, want empty list", phase, k, body[k])
			}
		}
	}
}

func TestPackageRoute(t *testing.T) {
	var gotID any
	e := phaseEnv(t, 2, func(_ context.Context, q string, p map[string]any) ([]Row, error) {
		switch q {
		case cypherPackageByPurl:
			gotID = p["id"]
			if p["id"] != "pkg:npm/%40angular/core" {
				return nil, nil
			}
			return []Row{{"props": map[string]any{"purl": "pkg:npm/%40angular/core", "ecosystem": "npm"},
				"repositories": []any{map[string]any{"url": "https://github.com/angular/angular", "host": "github.com"}}}}, nil
		case cypherPackageVulns:
			return []Row{{"cveID": "CVE-2021-1", "publishedDate": nil, "v3baseScore": 7.5}}, nil
		}
		t.Fatalf("unexpected query")
		return nil, nil
	})
	enc := url.PathEscape("pkg:npm/%40angular/core")
	code, body := getJSON(t, e, "/v1/packages/"+strings.ReplaceAll(enc, "/", "%2F"))
	if code != 200 || gotID != "pkg:npm/%40angular/core" {
		t.Fatalf("code=%d id=%v body=%v", code, gotID, body)
	}
	if body["package"].(map[string]any)["ecosystem"] != "npm" || len(body["vulnerabilities"].([]any)) != 1 ||
		body["repositories"].([]any)[0].(map[string]any)["host"] != "github.com" || body["graph"] == nil {
		t.Fatalf("body %v", body)
	}
	code, body = getJSON(t, e, "/v1/packages/pkg%3Apypi%2Fnope")
	if er, _ := body["error"].(map[string]any); code != 404 || er["message"] != "Package pkg:pypi/nope not found" {
		t.Fatalf("404 body %v", body)
	}
}

func TestAttackEntityRoutes(t *testing.T) {
	e := phaseEnv(t, 3, func(_ context.Context, q string, p map[string]any) ([]Row, error) {
		switch q {
		case cypherAttackPatternByID:
			if p["id"] != "CAPEC-66" {
				return nil, nil
			}
			return []Row{{"props": map[string]any{"capecID": "CAPEC-66", "name": "SQLi"},
				"weaknesses": []any{map[string]any{"cweID": "CWE-89", "cweName": "SQL Injection"}},
				"techniques": []any{map[string]any{"attackID": "T1190", "name": "Exploit"}}}}, nil
		case cypherTechniqueByID:
			if p["id"] != "T1059.001" {
				return nil, nil
			}
			return []Row{{"props": map[string]any{"attackID": "T1059.001"},
				"attackPatterns":  []any{map[string]any{"capecID": "CAPEC-1", "name": "a"}},
				"atlasTechniques": []any{map[string]any{"atlasID": "AML.T0000", "name": "b"}}}}, nil
		case cypherAtlasTechniqueByID:
			if p["id"] != "AML.T0000.001" {
				return nil, nil
			}
			return []Row{{"props": map[string]any{"atlasID": "AML.T0000.001"}, "techniques": nil}}, nil
		}
		t.Fatalf("unexpected query")
		return nil, nil
	})
	_, b := getJSON(t, e, "/v1/attack-patterns/capec-0066")
	if b["attackPattern"].(map[string]any)["capecID"] != "CAPEC-66" ||
		b["weaknesses"].([]any)[0].(map[string]any)["cweName"] != "SQL Injection" ||
		b["techniques"].([]any)[0].(map[string]any)["attackID"] != "T1190" {
		t.Fatalf("attack pattern %v", b)
	}
	_, b = getJSON(t, e, "/v1/techniques/t1059.001")
	if b["technique"] == nil || len(b["attackPatterns"].([]any)) != 1 || b["atlasTechniques"].([]any)[0].(map[string]any)["atlasID"] != "AML.T0000" {
		t.Fatalf("technique %v", b)
	}
	_, b = getJSON(t, e, "/v1/atlas-techniques/aml.t0000.001")
	if b["atlasTechnique"] == nil || len(b["techniques"].([]any)) != 0 {
		t.Fatalf("atlas %v", b)
	}
	for path, want := range map[string]string{
		"/v1/attack-patterns/CAPEC-9":  "AttackPattern CAPEC-9 not found",
		"/v1/techniques/T9999":         "Technique T9999 not found",
		"/v1/atlas-techniques/AML.T99": "AtlasTechnique AML.T99 not found",
	} {
		code, body := getJSON(t, e, path)
		er, _ := body["error"].(map[string]any)
		if code != 404 || er["message"] != want || er["code"] != "not_found" {
			t.Errorf("%s: %d %v", path, code, body)
		}
	}
}

func TestEntityRoutesFollowPhase(t *testing.T) {
	q := func(context.Context, string, map[string]any) ([]Row, error) {
		t.Fatal("no query may run for a route of a phase that is not applied")
		return nil, nil
	}
	for phase, paths := range map[int][]string{
		1: {"/v1/packages/pkg%3Anpm%2Fx", "/v1/attack-patterns/CAPEC-1", "/v1/techniques/T1190", "/v1/atlas-techniques/AML.T0000"},
		2: {"/v1/attack-patterns/CAPEC-1", "/v1/techniques/T1190", "/v1/atlas-techniques/AML.T0000"},
	} {
		e := phaseEnv(t, phase, q)
		for _, p := range paths {
			code, body := getJSON(t, e, p)
			if er, _ := body["error"].(map[string]any); code != 404 || er["message"] != "no such route" {
				t.Errorf("phase %d %s: %d %v", phase, p, code, body)
			}
		}
	}
}

func TestSearchNewFilters(t *testing.T) {
	var got map[string]any
	var gotQ string
	q := func(_ context.Context, query string, p map[string]any) ([]Row, error) {
		gotQ, got = query, p
		return []Row{{"cveID": "CVE-2021-1", "kev": true, "epssScore": 0.5, "sortKey": float64(1)}}, nil
	}
	e := phaseEnv(t, 2, q)
	code, body := getJSON(t, e, "/v1/vulnerabilities?kev=true&epssMin=0.1&epssMax=1&ecosystem=PyPI")
	if code != 200 || gotQ != cypherSearch {
		t.Fatalf("%d %v", code, body)
	}
	if got["kev"] != true || got["epssMin"] != 0.1 || got["epssMax"] != 1.0 || got["ecosystem"] != "PyPI" {
		t.Fatalf("params %v", got)
	}
	it := body["items"].([]any)[0].(map[string]any)
	if it["kev"] != true || it["epssScore"] != 0.5 {
		t.Fatalf("item %v", it)
	}
	getJSON(t, e, "/v1/vulnerabilities")
	if got["epssMin"] != nil || got["epssMax"] != nil || got["ecosystem"] != nil || got["kev"] != nil {
		t.Fatalf("defaults %v", got)
	}
	for _, c := range []struct{ qs, param string }{
		{"epssMin=-0.1", "epssMin"}, {"epssMin=1.1", "epssMin"}, {"epssMax=2", "epssMax"}, {"epssMax=abc", "epssMax"},
		{"epssMin=0.9&epssMax=0.1", "epssMin"}, {"ecosystem=" + strings.Repeat("a", 101), "ecosystem"},
	} {
		code, body := getJSON(t, e, "/v1/vulnerabilities?"+c.qs)
		if er, _ := body["error"].(map[string]any); code != 400 || er["parameter"] != c.param {
			t.Errorf("%s: %d %v", c.qs, code, body)
		}
	}
}

func TestSearchEcosystemBeforePhase2IsEmpty(t *testing.T) {
	e := phaseEnv(t, 1, func(context.Context, string, map[string]any) ([]Row, error) {
		t.Fatal("no query expected")
		return nil, nil
	})
	code, body := getJSON(t, e, "/v1/vulnerabilities?ecosystem=npm")
	if items, ok := body["items"].([]any); code != 200 || !ok || len(items) != 0 {
		t.Fatalf("%d %v", code, body)
	}
}

func TestSearchCursorBoundToNewFilters(t *testing.T) {
	q := func(context.Context, string, map[string]any) ([]Row, error) { return searchRows(3), nil }
	e := phaseEnv(t, 2, q)
	_, body := getJSON(t, e, "/v1/vulnerabilities?limit=2&epssMin=0.2&ecosystem=npm")
	cur, _ := body["nextCursor"].(string)
	if cur == "" {
		t.Fatalf("no cursor: %v", body)
	}
	if code, _ := getJSON(t, e, "/v1/vulnerabilities?limit=2&epssMin=0.2&ecosystem=npm&cursor="+url.QueryEscape(cur)); code != 200 {
		t.Fatalf("same filters: %d", code)
	}
	for _, qs := range []string{"epssMin=0.3&ecosystem=npm", "epssMin=0.2&ecosystem=PyPI", "epssMin=0.2&epssMax=0.9&ecosystem=npm", "epssMin=0.2"} {
		code, body := getJSON(t, e, "/v1/vulnerabilities?limit=2&cursor="+url.QueryEscape(cur)+"&"+qs)
		if er, _ := body["error"].(map[string]any); code != 400 || er["parameter"] != "cursor" {
			t.Errorf("%s: %d %v", qs, code, body)
		}
	}
}

func TestSearchQueriesCarryNewFilters(t *testing.T) {
	for _, q := range []string{cypherSearch, cypherSearchText} {
		for _, want := range []string{"$epssMin", "$epssMax", "$ecosystem", "AFFECTS_PACKAGE", "v.epssScore AS epssScore", "v.kev AS kev"} {
			if !strings.Contains(q, want) {
				t.Errorf("search query lacks %s", want)
			}
		}
	}
}

func TestStatsKevEpssAndSourceCoverage(t *testing.T) {
	var calls atomic.Int32
	base := statsFake(&calls)
	q := func(ctx context.Context, query string, p map[string]any) ([]Row, error) {
		switch query {
		case cypherStatsKevCount:
			return []Row{{"n": int64(11)}}, nil
		case cypherStatsEpssHigh:
			return []Row{{"n": int64(5)}}, nil
		case cypherCoverageKEV:
			return []Row{{"entries": int64(1)}}, nil
		case cypherCoverageEPSS:
			return []Row{{"rows": int64(2)}}, nil
		case cypherCoverageOSV:
			return []Row{{"advisories": int64(3)}}, nil
		case cypherCoverageGHSA:
			return []Row{{"advisories": int64(4)}}, nil
		case cypherCoverageAttack:
			return []Row{{"techniques": int64(5)}}, nil
		case cypherCoverageAtlas:
			return []Row{{"techniques": int64(6)}}, nil
		case cypherCoverageCAPEC:
			return []Row{{"attackPatterns": int64(7)}}, nil
		}
		return base(ctx, query, p)
	}
	src := func(_ context.Context, names []string) ([]checkpoint.SourceStatus, error) {
		var out []checkpoint.SourceStatus
		for _, n := range names {
			out = append(out, checkpoint.SourceStatus{Source: n})
		}
		return out, nil
	}
	all := []string{"kev", "epss", "osv", "ghsa", "attack", "atlas", "capec"}
	run := func(phase int) map[string]any {
		e := opsEnv(t, q, src, nil)
		e.srv.cfg.Sources = all
		e.srv.cfg.MaxPhase, e.srv.phaseVal = phase, phase
		code, body := getJSON(t, e, "/v1/stats")
		if code != 200 {
			t.Fatalf("%d %v", code, body)
		}
		return body
	}
	body := run(3)
	if body["kevCount"] != float64(11) || body["epssHigh"] != float64(5) {
		t.Fatalf("kevCount/epssHigh %v %v", body["kevCount"], body["epssHigh"])
	}
	want := map[string][2]any{
		"kev": {"entries", 1}, "epss": {"rows", 2}, "osv": {"advisories", 3}, "ghsa": {"advisories", 4},
		"attack": {"techniques", 5}, "atlas": {"techniques", 6}, "capec": {"attackPatterns", 7},
	}
	cov := body["coverage"].([]any)
	if len(cov) != len(all) {
		t.Fatalf("coverage %v", cov)
	}
	for _, c := range cov {
		m := c.(map[string]any)
		w := want[m["source"].(string)]
		ig := m["inGraph"].(map[string]any)
		if len(ig) != 1 || ig[w[0].(string)] != float64(w[1].(int)) {
			t.Errorf("%v inGraph %v", m["source"], ig)
		}
	}
	// Phase 2: attack, atlas and capec counts are not run.
	for _, c := range run(2)["coverage"].([]any) {
		m := c.(map[string]any)
		ig := m["inGraph"].(map[string]any)
		switch m["source"] {
		case "attack", "atlas", "capec":
			if len(ig) != 0 {
				t.Errorf("%v counted at phase 2: %v", m["source"], ig)
			}
		default:
			if len(ig) != 1 {
				t.Errorf("%v inGraph %v", m["source"], ig)
			}
		}
	}
}

func TestNodeKeyCoversNewLabels(t *testing.T) {
	k := keyExpr("n")
	for _, w := range []string{"WHEN 'Package' THEN n.purl", "WHEN 'AttackPattern' THEN n.capecID", "WHEN 'Technique' THEN n.attackID", "WHEN 'AtlasTechnique' THEN n.atlasID"} {
		if !strings.Contains(k, w) {
			t.Errorf("keyExpr lacks %q", w)
		}
	}
}

func TestNeighborhoodAcceptsNewTypesByPhase(t *testing.T) {
	cases := []struct {
		phase int
		qs    string
		ok    bool
	}{
		{1, "type=Package&id=pkg:npm/x", false},
		{2, "type=Package&id=pkg:npm/x&relTypes=AFFECTS_PACKAGE,HOSTED_IN", true},
		{2, "type=Technique&id=T1190", false},
		{2, "type=Package&id=pkg:npm/x&relTypes=MAPS_TO_TECHNIQUE", false},
		{3, "type=AttackPattern&id=CAPEC-66&nodeTypes=Weakness,Technique&relTypes=RELATED_ATTACK_PATTERN,MAPS_TO_TECHNIQUE", true},
		{3, "type=AtlasTechnique&id=AML.T0000&relTypes=ADAPTED_FROM", true},
		{3, "type=Technique&id=T1190", true},
	}
	for _, c := range cases {
		e := opsEnv(t, func(context.Context, string, map[string]any) ([]Row, error) { return nil, nil }, nil, nil)
		e.srv.cfg.MaxPhase, e.srv.phaseVal = c.phase, c.phase
		code, body := getJSON(t, e, "/v1/graph/neighborhood?"+c.qs)
		if c.ok && code == 400 || !c.ok && code != 400 {
			t.Errorf("phase %d %s: %d %v", c.phase, c.qs, code, body)
		}
	}
}
