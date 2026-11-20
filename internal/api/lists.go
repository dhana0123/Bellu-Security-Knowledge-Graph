package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

const (
	defaultLimit = 50
	maxLimit     = 500
	maxQueryLen  = 500
	cursorMaxAge = 24 * time.Hour
	cursorSkew   = 5 * time.Minute
)

var cweRe = regexp.MustCompile(`^CWE-\d{1,9}$`)

// cursorPayload is the signed content of a paging cursor. SortKey is the
// exact sort key of the last returned row: an ISO date (search without q), a
// float score (search with q), or empty (lists, which order by cveID only).
type cursorPayload struct {
	V          int    `json:"v"`
	SortKey    any    `json:"sortKey,omitempty"`
	ID         string `json:"id"`
	FilterHash string `json:"filterHash"`
	IssuedAt   int64  `json:"issuedAt"`
}

var errBadCursor = errors.New("invalid cursor")

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func signCursor(secret, body []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return m.Sum(nil)
}

// encodeCursor returns base64url(JSON) + "." + base64url(HMAC-SHA256).
func encodeCursor(secret []byte, p cursorPayload) string {
	p.V = 1
	body, _ := json.Marshal(p)
	return b64(body) + "." + b64(signCursor(secret, body))
}

// decodeCursor verifies the MAC, the filter hash, and the 24 h age.
func decodeCursor(secret []byte, s, filterHash string, now time.Time) (cursorPayload, error) {
	var p cursorPayload
	bodyS, macS, ok := strings.Cut(s, ".")
	if !ok {
		return p, errBadCursor
	}
	body, err1 := base64.RawURLEncoding.DecodeString(bodyS)
	mac, err2 := base64.RawURLEncoding.DecodeString(macS)
	if err1 != nil || err2 != nil || !hmac.Equal(mac, signCursor(secret, body)) {
		return p, errBadCursor
	}
	if json.Unmarshal(body, &p) != nil || p.V != 1 || p.FilterHash != filterHash {
		return p, errBadCursor
	}
	issued := time.Unix(p.IssuedAt, 0)
	if now.Sub(issued) > cursorMaxAge || issued.Sub(now) > cursorSkew {
		return p, errBadCursor
	}
	return p, nil
}

func hashFilters(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(h[:])
}

// paramError names the invalid request parameter.
type paramError struct{ param, msg string }

func (p *paramError) Error() string { return p.param + ": " + p.msg }

func bad(param, msg string) error { return &paramError{param, msg} }

func (e *Entities) badParam(w http.ResponseWriter, r *http.Request, err error) {
	var pe *paramError
	if errors.As(err, &pe) {
		e.s.WriteError(w, r, http.StatusBadRequest, ErrorBody{
			Code: "invalid_parameter", Message: pe.msg, Parameter: pe.param,
		})
		return
	}
	e.s.WriteError(w, r, http.StatusBadRequest, ErrorBody{Code: "invalid_parameter", Message: "invalid request"})
}

func parseLimit(v url.Values) (int, error) {
	s := v.Get("limit")
	if s == "" {
		return defaultLimit, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > maxLimit {
		return 0, bad("limit", "must be an integer from 1 to 500")
	}
	return n, nil
}

func parseBool(v url.Values, name string) (*bool, error) {
	s, ok := v[name]
	if !ok || s[0] == "" {
		return nil, nil
	}
	switch strings.ToLower(s[0]) {
	case "true":
		t := true
		return &t, nil
	case "false":
		f := false
		return &f, nil
	}
	return nil, bad(name, "must be true or false")
}

// parseDate accepts YYYY-MM-DD or an RFC 3339 timestamp (reduced to its UTC date).
func parseDate(name, s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		t = t.UTC()
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC), nil
	}
	return time.Time{}, bad(name, "must be an ISO 8601 date or UTC timestamp")
}

func parseScore(v url.Values, name string) (*float64, error) {
	s := v.Get(name)
	if s == "" {
		return nil, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || f < 0 || f > 10 {
		return nil, bad(name, "must be a number from 0.0 to 10.0")
	}
	return &f, nil
}

// luceneEscape turns free text into a safe Lucene query: every special
// character is backslash-escaped and terms are joined with AND. Reserved
// words are quoted so they cannot act as operators.
func luceneEscape(q string) string {
	const special = `+-&|!(){}[]^"~*?:\/`
	terms := strings.Fields(q)
	out := make([]string, 0, len(terms))
	for _, t := range terms {
		var b strings.Builder
		for _, r := range t {
			if strings.ContainsRune(special, r) {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
		s := b.String()
		switch s {
		case "AND", "OR", "NOT", "TO":
			s = `"` + s + `"`
		}
		out = append(out, s)
	}
	return strings.Join(out, " AND ")
}

func dateParam(t *time.Time) any {
	if t == nil {
		return nil
	}
	return neo4j.DateOf(*t)
}

func fmtPtr[T any](p *T) string {
	if p == nil {
		return "-"
	}
	return fmt.Sprint(*p)
}

// listState is the validated paging input shared by all list endpoints.
type listState struct {
	limit  int
	cursor *cursorPayload
}

func (e *Entities) paging(r *http.Request, filterHash string) (listState, error) {
	v := r.URL.Query()
	lim, err := parseLimit(v)
	if err != nil {
		return listState{}, err
	}
	st := listState{limit: lim}
	if c := v.Get("cursor"); c != "" {
		p, err := decodeCursor(e.secret, c, filterHash, e.s.cfg.Now())
		if err != nil {
			return st, bad("cursor", "cursor is invalid, modified, expired, or issued for different filters")
		}
		st.cursor = &p
	}
	return st, nil
}

func (e *Entities) nextCursor(st listState, rows []Row, hash string) (string, []Row) {
	if len(rows) <= st.limit {
		return "", rows
	}
	rows = rows[:st.limit]
	last := rows[len(rows)-1]
	id, _ := last["cveID"].(string)
	p := cursorPayload{ID: id, FilterHash: hash, IssuedAt: e.s.cfg.Now().Unix()}
	if k, ok := last["sortKey"]; ok {
		p.SortKey = jsonValue(k)
	}
	return encodeCursor(e.secret, p), rows
}

func (e *Entities) writeList(w http.ResponseWriter, r *http.Request, st listState, rows []Row, hash string) {
	cur, rows := e.nextCursor(st, rows, hash)
	items := make([]any, len(rows))
	for i, row := range rows {
		m := make(map[string]any, len(row))
		for k, v := range row {
			if k != "sortKey" {
				m[k] = jsonValue(v)
			}
		}
		items[i] = m
	}
	body := map[string]any{"items": items, "limit": st.limit}
	if cur != "" {
		body["nextCursor"] = cur
	}
	e.s.WriteJSON(w, r, http.StatusOK, body)
}

// listFor serves the per-entity vulnerability lists (ordered by cveID ASC).
func (e *Entities) listFor(w http.ResponseWriter, r *http.Request, kind, key, query string) {
	incl, err := parseBool(r.URL.Query(), "includeRejected")
	if err == nil {
		var st listState
		hash := hashFilters(kind, key, fmtPtr(incl))
		if st, err = e.paging(r, hash); err == nil {
			params := map[string]any{
				"includeRejected": incl != nil && *incl, "limit": st.limit + 1, "after": nil,
			}
			if st.cursor != nil {
				params["after"] = st.cursor.ID
			}
			params[kindParam(kind)] = key
			rows, ok := e.run(w, r, query, params)
			if ok {
				e.writeList(w, r, st, rows, hash)
			}
			return
		}
	}
	e.badParam(w, r, err)
}

func kindParam(kind string) string {
	if kind == "weakness" {
		return "id"
	}
	return "name"
}

func (e *Entities) weaknessVulns(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(strings.TrimSpace(r.PathValue("cweID")))
	rows, ok := e.run(w, r, cypherWeaknessByID, map[string]any{"id": id})
	if !ok {
		return
	}
	if len(rows) == 0 {
		e.notFound(w, r, "Weakness", id)
		return
	}
	e.listFor(w, r, "weakness", id, cypherWeaknessVulns)
}

func (e *Entities) productVulns(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	key, ok := e.resolveName(w, r, "Product", cypherProductExact, cypherProductFold, name)
	if !ok {
		return
	}
	e.listFor(w, r, "product", key, cypherProductVulns)
}

func (e *Entities) vendorVulns(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	key, ok := e.resolveName(w, r, "Vendor", cypherVendorExact, cypherVendorFold, name)
	if !ok {
		return
	}
	e.listFor(w, r, "vendor", key, cypherVendorVulns)
}

// search serves GET /v1/vulnerabilities.
func (e *Entities) search(w http.ResponseWriter, r *http.Request) {
	params, hash, st, text, err := e.parseSearch(r)
	if err != nil {
		e.badParam(w, r, err)
		return
	}
	query := cypherSearch
	if text {
		query = cypherSearchText
	}
	params["limit"] = st.limit + 1
	params["afterID"], params["afterKey"] = nil, nil
	if c := st.cursor; c != nil {
		params["afterID"] = c.ID
		if text {
			f, ok := c.SortKey.(float64)
			if !ok {
				e.badParam(w, r, bad("cursor", "cursor is invalid"))
				return
			}
			params["afterKey"] = f
		} else {
			s, _ := c.SortKey.(string)
			t, perr := time.Parse("2006-01-02", s)
			if perr != nil {
				e.badParam(w, r, bad("cursor", "cursor is invalid"))
				return
			}
			params["afterKey"] = neo4j.DateOf(t)
		}
	}
	rows, ok := e.run(w, r, query, params)
	if ok {
		e.writeList(w, r, st, rows, hash)
	}
}

func (e *Entities) parseSearch(r *http.Request) (map[string]any, string, listState, bool, error) {
	v := r.URL.Query()
	var st listState
	p := map[string]any{
		"q": nil, "publishedFrom": nil, "publishedTo": nil, "cvssV3Min": nil, "cvssV3Max": nil,
		"exploitability": nil, "kev": nil, "cwe": nil, "includeRejected": false,
	}
	text := false
	if q := strings.TrimSpace(v.Get("q")); q != "" {
		if utf8.RuneCountInString(v.Get("q")) > maxQueryLen {
			return nil, "", st, false, bad("q", "must be at most 500 characters")
		}
		p["q"], text = luceneEscape(q), true
	} else if utf8.RuneCountInString(v.Get("q")) > maxQueryLen {
		return nil, "", st, false, bad("q", "must be at most 500 characters")
	}
	var from, to *time.Time
	for _, d := range []struct {
		name string
		dst  **time.Time
	}{{"publishedFrom", &from}, {"publishedTo", &to}} {
		if s := v.Get(d.name); s != "" {
			t, err := parseDate(d.name, s)
			if err != nil {
				return nil, "", st, false, err
			}
			*d.dst = &t
		}
	}
	if from != nil && to != nil && from.After(*to) {
		return nil, "", st, false, bad("publishedFrom", "must not be after publishedTo")
	}
	p["publishedFrom"], p["publishedTo"] = dateParam(from), dateParam(to)
	min, err := parseScore(v, "cvssV3Min")
	if err != nil {
		return nil, "", st, false, err
	}
	max, err := parseScore(v, "cvssV3Max")
	if err != nil {
		return nil, "", st, false, err
	}
	if min != nil && max != nil && *min > *max {
		return nil, "", st, false, bad("cvssV3Min", "must not exceed cvssV3Max")
	}
	if min != nil {
		p["cvssV3Min"] = *min
	}
	if max != nil {
		p["cvssV3Max"] = *max
	}
	if s := v.Get("exploitability"); s != "" {
		if s != "0" && s != "1" {
			return nil, "", st, false, bad("exploitability", "must be 0 or 1")
		}
		p["exploitability"] = int64(s[0] - '0')
	}
	kev, err := parseBool(v, "kev")
	if err != nil {
		return nil, "", st, false, err
	}
	if kev != nil {
		p["kev"] = *kev
	}
	cwe := strings.ToUpper(strings.TrimSpace(v.Get("cwe")))
	if cwe != "" {
		if !cweRe.MatchString(cwe) {
			return nil, "", st, false, bad("cwe", "must look like CWE-79")
		}
		p["cwe"] = cwe
	}
	incl, err := parseBool(v, "includeRejected")
	if err != nil {
		return nil, "", st, false, err
	}
	p["includeRejected"] = incl != nil && *incl
	qs, _ := p["q"].(string)
	hash := hashFilters("search", qs, fmtT(from), fmtT(to), fmtPtr(min), fmtPtr(max),
		fmt.Sprint(p["exploitability"]), fmtPtr(kev), cwe, fmt.Sprint(p["includeRejected"]))
	st, err = e.paging(r, hash)
	if err != nil {
		return nil, "", st, false, err
	}
	return p, hash, st, text, nil
}

func fmtT(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format("2006-01-02")
}
