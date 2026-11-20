package api

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func searchRows(n int) []Row {
	rows := make([]Row, n)
	for i := range rows {
		rows[i] = Row{
			"cveID": fmt.Sprintf("CVE-2021-%04d", 9000-i), "sortKey": neo4j.DateOf(time.Date(2021, 5, 1, 0, 0, 0, 0, time.UTC)),
		}
	}
	return rows
}

func TestSearchValidation(t *testing.T) {
	e := entityEnv(t, func(context.Context, string, map[string]any) ([]Row, error) { return nil, nil })
	bad := map[string]string{
		"limit=0": "limit", "limit=501": "limit", "limit=abc": "limit",
		"publishedFrom=yesterday": "publishedFrom", "publishedTo=2021-13-01": "publishedTo",
		"publishedFrom=2022-01-01&publishedTo=2021-01-01": "publishedFrom",
		"cvssV3Min=-1": "cvssV3Min", "cvssV3Max=10.5": "cvssV3Max", "cvssV3Min=NaN": "cvssV3Min",
		"cvssV3Min=8&cvssV3Max=2": "cvssV3Min",
		"exploitability=2":        "exploitability", "kev=maybe": "kev", "cwe=79": "cwe",
		"includeRejected=1": "includeRejected", "q=" + strings.Repeat("a", 501): "q",
		"cursor=garbage": "cursor",
	}
	for qs, param := range bad {
		code, body := getJSON(t, e, "/v1/vulnerabilities?"+qs)
		er, _ := body["error"].(map[string]any)
		if code != 400 || er["parameter"] != param {
			t.Errorf("%s: code=%d body=%v", qs, code, body)
		}
	}
	good := []string{"limit=1", "limit=500", "publishedFrom=2021-01-01&publishedTo=2021-12-31T10:00:00Z",
		"cvssV3Min=0&cvssV3Max=10", "exploitability=0", "kev=true", "cwe=cwe-79", "includeRejected=true",
		"q=" + strings.Repeat("a", 500)}
	for _, qs := range good {
		if code, body := getJSON(t, e, "/v1/vulnerabilities?"+qs); code != 200 {
			t.Errorf("%s: code=%d %v", qs, code, body)
		}
	}
}

func TestSearchFiltersAndParams(t *testing.T) {
	var gotQ string
	var got map[string]any
	e := entityEnv(t, func(_ context.Context, q string, p map[string]any) ([]Row, error) {
		gotQ, got = q, p
		return nil, nil
	})
	code, _ := getJSON(t, e, "/v1/vulnerabilities?publishedFrom=2021-01-01&cvssV3Min=7&cvssV3Max=9.5&exploitability=1&kev=false&cwe=cwe-79&includeRejected=true&limit=10")
	if code != 200 || gotQ != cypherSearch {
		t.Fatalf("code=%d query mismatch", code)
	}
	if got["cvssV3Min"] != 7.0 || got["cvssV3Max"] != 9.5 || got["exploitability"] != int64(1) ||
		got["kev"] != false || got["cwe"] != "CWE-79" || got["includeRejected"] != true ||
		got["limit"] != 11 || got["publishedFrom"] == nil || got["publishedTo"] != nil || got["afterID"] != nil {
		t.Fatalf("params = %v", got)
	}
	getJSON(t, e, "/v1/vulnerabilities?q=log4j+AND+a%2Bb")
	if gotQ != cypherSearchText || got["q"] != `log4j AND "AND" AND a\+b` {
		t.Fatalf("text query %v %q", got["q"], gotQ)
	}
}

func TestCursorOnlyWhenMoreRowsAndRoundTrip(t *testing.T) {
	var last map[string]any
	e := entityEnv(t, func(_ context.Context, q string, p map[string]any) ([]Row, error) {
		last = p
		return searchRows(3), nil // limit=2 -> limit+1 rows returned
	})
	code, body := getJSON(t, e, "/v1/vulnerabilities?limit=2&kev=true")
	items := body["items"].([]any)
	cur, _ := body["nextCursor"].(string)
	if code != 200 || len(items) != 2 || cur == "" || last["limit"] != 3 {
		t.Fatalf("code=%d items=%d cursor=%q", code, len(items), cur)
	}
	// Follow the cursor: afterID/afterKey come from the last returned row.
	getJSON(t, e, "/v1/vulnerabilities?limit=2&kev=true&cursor="+cur)
	if last["afterID"] != "CVE-2021-8999" {
		t.Fatalf("afterID = %v", last["afterID"])
	}
	if d, ok := last["afterKey"].(neo4j.Date); !ok || d.Time().Format("2006-01-02") != "2021-05-01" {
		t.Fatalf("afterKey = %v", last["afterKey"])
	}
	// Exactly limit rows: no cursor.
	e2 := entityEnv(t, func(context.Context, string, map[string]any) ([]Row, error) { return searchRows(2), nil })
	_, body = getJSON(t, e2, "/v1/vulnerabilities?limit=2")
	if _, has := body["nextCursor"]; has {
		t.Fatal("cursor present without more rows")
	}
}

func TestCursorRejections(t *testing.T) {
	secret := []byte("test-secret")
	now := time.Date(2025, 1, 10, 12, 0, 0, 0, time.UTC)
	h := hashFilters("a")
	c := encodeCursor(secret, cursorPayload{ID: "x", SortKey: 1.5, FilterHash: h, IssuedAt: now.Unix()})
	p, err := decodeCursor(secret, c, h, now)
	if err != nil || p.ID != "x" || p.SortKey != 1.5 {
		t.Fatalf("round trip: %v %+v", err, p)
	}
	tampered := []byte(c)
	tampered[2] ^= 1
	cases := map[string]struct {
		cur  string
		hash string
		now  time.Time
		key  []byte
	}{
		"tampered":     {string(tampered), h, now, secret},
		"other filter": {c, hashFilters("b"), now, secret},
		"expired":      {c, h, now.Add(24*time.Hour + time.Second), secret},
		"wrong secret": {c, h, now, []byte("other")},
	}
	for name, tc := range cases {
		if _, err := decodeCursor(tc.key, tc.cur, tc.hash, tc.now); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Through HTTP: a cursor for other filters yields 400 naming cursor.
	e := entityEnv(t, func(context.Context, string, map[string]any) ([]Row, error) { return searchRows(3), nil })
	_, body := getJSON(t, e, "/v1/vulnerabilities?limit=2&kev=true")
	cur := body["nextCursor"].(string)
	code, body := getJSON(t, e, "/v1/vulnerabilities?limit=2&kev=false&cursor="+cur)
	if er, _ := body["error"].(map[string]any); code != 400 || er["parameter"] != "cursor" {
		t.Fatalf("code=%d %v", code, body)
	}
}

func TestEntityLists(t *testing.T) {

	var params []map[string]any
	e := entityEnv(t, func(_ context.Context, q string, p map[string]any) ([]Row, error) {
		params = append(params, p)
		switch q {
		case cypherWeaknessByID:
			return []Row{{"props": map[string]any{}}}, nil
		case cypherProductExact, cypherVendorExact:
			return []Row{{"key": "Log4j"}}, nil
		}
		return []Row{{"cveID": "CVE-1-1"}, {"cveID": "CVE-1-2"}}, nil
	})
	for _, path := range []string{"/v1/weaknesses/cwe-79/vulnerabilities", "/v1/products/log4j/vulnerabilities", "/v1/vendors/apache/vulnerabilities"} {
		code, body := getJSON(t, e, path+"?limit=1")
		if code != 200 || len(body["items"].([]any)) != 1 || body["nextCursor"] == nil {
			t.Fatalf("%s: %d %v", path, code, body)
		}
		cur := body["nextCursor"].(string)
		getJSON(t, e, path+"?limit=1&cursor="+cur)
		if params[len(params)-1]["after"] != "CVE-1-1" {
			t.Fatalf("%s: after = %v", path, params[len(params)-1]["after"])
		}
		// A cursor from one list is rejected on another entity.
		if code, _ := getJSON(t, e, "/v1/weaknesses/CWE-1/vulnerabilities?cursor="+cur); code != 400 {
			t.Fatalf("cross-list cursor accepted: %d", code)
		}
	}
	if code, _ := getJSON(t, e, "/v1/weaknesses/CWE-1/vulnerabilities?limit=0"); code != 400 {
		t.Fatal("limit=0 accepted")
	}
}
