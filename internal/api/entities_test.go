package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func entityEnv(t *testing.T, q queryFunc) *env {
	t.Helper()
	e := newEnv(t, 1000, nil)
	Routes(e.srv, q, []byte("test-secret"))
	return e
}

func getJSON(t *testing.T, e *env, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer bskg_good")
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad json: %v: %s", err, rec.Body.String())
	}
	return rec.Code, out
}

func TestVulnerabilityDetail(t *testing.T) {
	var gotID any
	e := entityEnv(t, func(_ context.Context, q string, p map[string]any) ([]Row, error) {
		if q != cypherVulnerabilityByID {
			t.Fatalf("unexpected query")
		}
		gotID = p["id"]
		return []Row{{
			"props": map[string]any{
				"cveID": "CVE-2021-44228", "publishedDate": neo4j.Date{},
				"sources":   []any{"osv", "nvd", "osv"},
				"p_osv_run": "R1", "p_osv_at": "2024-01-01", "p_osv_ref": "abc",
				"p_nvd_run": "R2", "p_nvd_removed": true,
			},
			"weaknesses":   []any{"CWE-917"},
			"exploits":     []any{map[string]any{"eid": "50592", "authors": []any{"x"}}},
			"products":     []any{map[string]any{"productName": "log4j", "vendors": []any{"apache"}}},
			"domains":      []any{"nvd.nist.gov"},
			"repositories": []any{map[string]any{"url": "https://github.com/apache/logging-log4j2", "host": "github.com"}},
			"fixCommits":   []any{map[string]any{"sha": strings.Repeat("a", 40), "repoUrl": "https://github.com/apache/logging-log4j2", "url": "https://github.com/apache/logging-log4j2/commit/" + strings.Repeat("a", 40)}},
		}}, nil
	})
	code, body := getJSON(t, e, "/v1/vulnerabilities/%20cve-2021-44228")
	if code != 200 || gotID != "CVE-2021-44228" {
		t.Fatalf("code=%d id=%v body=%v", code, gotID, body)
	}
	v := body["vulnerability"].(map[string]any)
	for k := range v {
		if strings.HasPrefix(k, "p_") || k == "sources" {
			t.Fatalf("internal key %q leaked", k)
		}
	}
	if _, ok := v["kev"]; ok {
		t.Fatal("kev should be absent")
	}
	src := body["sources"].([]any)
	if len(src) != 2 || src[0] != "nvd" || src[1] != "osv" {
		t.Fatalf("sources = %v", src)
	}
	prov := body["provenance"].([]any)
	vk := prov[1].(map[string]any)
	if vk["source"] != "osv" || vk["runId"] != "R1" || vk["recordId"] != "abc" || vk["fetchedAt"] != "2024-01-01" {
		t.Fatalf("provenance = %v", prov)
	}
	for _, k := range []string{"weaknesses", "exploits", "products", "domains", "repositories", "fixCommits", "graph"} {
		if body[k] == nil {
			t.Fatalf("missing %s", k)
		}
	}
	if r := body["repositories"].([]any); len(r) != 1 || r[0].(map[string]any)["host"] != "github.com" {
		t.Fatalf("repositories = %v", body["repositories"])
	}
	if f := body["fixCommits"].([]any); len(f) != 1 || f[0].(map[string]any)["sha"] != strings.Repeat("a", 40) {
		t.Fatalf("fixCommits = %v", body["fixCommits"])
	}
}
func TestVulnerabilityDetailEmptyGitLists(t *testing.T) {
	e := entityEnv(t, func(context.Context, string, map[string]any) ([]Row, error) {
		return []Row{{"props": map[string]any{"cveID": "CVE-2020-0001"}}}, nil
	})
	_, body := getJSON(t, e, "/v1/vulnerabilities/CVE-2020-0001")
	for _, k := range []string{"repositories", "fixCommits"} {
		if l, ok := body[k].([]any); !ok || len(l) != 0 {
			t.Errorf("%s = %#v, want empty list", k, body[k])
		}
	}
}

func TestEntityNotFound(t *testing.T) {
	e := entityEnv(t, func(context.Context, string, map[string]any) ([]Row, error) { return nil, nil })
	for path, want := range map[string]string{
		"/v1/vulnerabilities/CVE-2020-0001": "Vulnerability CVE-2020-0001 not found",
		"/v1/vulnerabilities/junk":          "Vulnerability JUNK not found",
		"/v1/weaknesses/cwe-79":             "Weakness CWE-79 not found",
		"/v1/products/Foo":                  "Product Foo not found",
		"/v1/vendors/Bar":                   "Vendor Bar not found",
		"/v1/exploits/123":                  "Exploit 123 not found",
	} {
		code, body := getJSON(t, e, path)
		eb, _ := body["error"].(map[string]any)
		if code != 404 || eb["message"] != want || eb["code"] != "not_found" || body["graph"] == nil {
			t.Errorf("%s: code=%d body=%v", path, code, body)
		}
	}
}

func TestProductCaseInsensitive(t *testing.T) {
	e := entityEnv(t, func(_ context.Context, q string, p map[string]any) ([]Row, error) {
		switch q {
		case cypherProductExact:
			return nil, nil
		case cypherProductFold:
			if p["lower"] != "openssl" {
				t.Fatalf("lower = %v", p["lower"])
			}
			return []Row{{"key": "OpenSSL"}}, nil
		case cypherProductByKey:
			if p["name"] != "OpenSSL" {
				t.Fatalf("name = %v", p["name"])
			}
			return []Row{{"props": map[string]any{"productName": "OpenSSL"}, "vendors": []any{"openssl"}}}, nil
		}
		t.Fatal("unexpected query")
		return nil, nil
	})
	code, body := getJSON(t, e, "/v1/products/OPENSSL")
	if code != 200 || body["product"].(map[string]any)["productName"] != "OpenSSL" {
		t.Fatalf("code=%d body=%v", code, body)
	}
}

func TestVendorWeaknessAndExploitShapes(t *testing.T) {
	e := entityEnv(t, func(_ context.Context, q string, _ map[string]any) ([]Row, error) {
		switch q {
		case cypherVendorExact:
			return []Row{{"key": "apache"}}, nil
		case cypherVendorByKey:
			return []Row{{"props": map[string]any{"vendorName": "apache"}, "products": []any{"log4j"}}}, nil
		case cypherWeaknessByID:
			return []Row{{"props": map[string]any{"cweID": "CWE-79", "sources": []any{"osv"}}}}, nil
		case cypherExploitByID:
			return []Row{{
				"props":           map[string]any{"eid": "1", "platform": "linux", "code": "SECRET", "exploitPublishDate": neo4j.Date{}},
				"authors":         []any{"a"},
				"vulnerabilities": []any{"CVE-2021-44228"},
			}}, nil
		}
		return nil, nil
	})
	if code, b := getJSON(t, e, "/v1/vendors/apache"); code != 200 || b["products"].([]any)[0] != "log4j" {
		t.Fatalf("vendor %d %v", code, b)
	}
	if code, b := getJSON(t, e, "/v1/weaknesses/cwe-79"); code != 200 || b["sources"].([]any)[0] != "osv" {
		t.Fatalf("weakness %d %v", code, b)
	}
	code, b := getJSON(t, e, "/v1/exploits/1")
	ex := b["exploit"].(map[string]any)
	if code != 200 || ex["platform"] != "linux" || ex["code"] != nil || b["authors"].([]any)[0] != "a" {
		t.Fatalf("exploit %d %v", code, b)
	}
}

func TestEntityGraphError(t *testing.T) {
	e := entityEnv(t, func(context.Context, string, map[string]any) ([]Row, error) {
		return nil, context.DeadlineExceeded
	})
	if code, _ := getJSON(t, e, "/v1/exploits/1"); code != http.StatusGatewayTimeout {
		t.Fatalf("code = %d", code)
	}
}
