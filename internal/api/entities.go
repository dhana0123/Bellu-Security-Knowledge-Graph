package api

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/resolve"
)

// queryFunc runs one constant query and returns its rows. Production code uses
// runRead over a graph.Client; tests pass a fake.
type queryFunc func(ctx context.Context, query string, params map[string]any) ([]Row, error)

// ReadQueries returns the production queryFunc backed by read transactions.
func ReadQueries(g *graph.Client) func(ctx context.Context, query string, params map[string]any) ([]Row, error) {
	return func(ctx context.Context, q string, p map[string]any) ([]Row, error) {
		return runRead(ctx, g, q, p)
	}
}

// Entities serves the entity lookup endpoints.
type Entities struct {
	s      *Server
	q      queryFunc
	secret []byte // HMAC key for paging cursors
}

// Routes registers the entity and list endpoints on s. q runs the constant
// queries. cursorSecret signs paging cursors.
func Routes(s *Server, q func(ctx context.Context, query string, params map[string]any) ([]Row, error), cursorSecret []byte) {
	e := &Entities{s: s, q: q, secret: cursorSecret}
	s.Handle("GET /vulnerabilities", e.search)
	s.Handle("GET /weaknesses/{cweID}/vulnerabilities", e.weaknessVulns)
	s.Handle("GET /products/{name}/vulnerabilities", e.productVulns)
	s.Handle("GET /vendors/{name}/vulnerabilities", e.vendorVulns)
	s.Handle("GET /vulnerabilities/{id}", e.vulnerability)
	s.Handle("GET /weaknesses/{cweID}", e.weakness)
	s.Handle("GET /products/{name}", e.product)
	s.Handle("GET /vendors/{name}", e.vendor)
	s.Handle("GET /exploits/{eid}", e.exploit)
	s.Handle("GET /sources", e.sourcesHandler)
	// Entities of the later schema phases answer 404 until their phase is applied.
	s.HandleFromPhase(2, "GET /packages/{purl}", e.pkg)
	s.HandleFromPhase(3, "GET /attack-patterns/{capecID}", e.attackPattern)
	s.HandleFromPhase(3, "GET /techniques/{attackID}", e.technique)
	s.HandleFromPhase(3, "GET /atlas-techniques/{atlasID}", e.atlasTechnique)
}

var (
	provKey = regexp.MustCompile(`^p_([a-z][a-z0-9]{0,15})_(run|at|ref|removed)$`)
)

// jsonValue converts driver values (dates, times, nested maps) to JSON-safe ones.
func jsonValue(v any) any {
	switch x := v.(type) {
	case neo4j.Date:
		return x.Time().Format("2006-01-02")
	case neo4j.LocalDateTime:
		return x.Time().Format("2006-01-02T15:04:05.000")
	case time.Time:
		return x.UTC().Format("2006-01-02T15:04:05.000Z07:00")
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = jsonValue(e)
		}
		return out
	case []string:
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = jsonValue(e)
		}
		return out
	default:
		return v
	}
}

// splitProps separates public properties from provenance and internal keys.
// It returns the public properties and the de-duplicated, sorted sources and
// the per-source provenance entries.
func splitProps(props map[string]any) (map[string]any, []string, []map[string]any) {
	pub := map[string]any{}
	prov := map[string]map[string]any{}
	seen := map[string]bool{}
	if l, ok := props["sources"].([]any); ok {
		for _, s := range l {
			if str, ok := s.(string); ok {
				seen[str] = true
			}
		}
	}
	for k, v := range props {
		if k == "sources" || strings.HasPrefix(k, "bskg") {
			continue
		}
		if m := provKey.FindStringSubmatch(k); m != nil {
			src, field := m[1], m[2]
			seen[src] = true
			if field == "removed" {
				continue
			}
			if prov[src] == nil {
				prov[src] = map[string]any{"source": src}
			}
			name := map[string]string{"run": "runId", "at": "fetchedAt", "ref": "recordId"}[field]
			prov[src][name] = jsonValue(v)
			continue
		}
		pub[k] = jsonValue(v)
	}
	sources := make([]string, 0, len(seen))
	for s := range seen {
		sources = append(sources, s)
	}
	sort.Strings(sources)
	provList := make([]map[string]any, 0, len(sources))
	for _, s := range sources {
		p := prov[s]
		if p == nil {
			p = map[string]any{"source": s}
		}
		provList = append(provList, p)
	}
	return pub, sources, provList
}

func (e *Entities) run(w http.ResponseWriter, r *http.Request, query string, params map[string]any) ([]Row, bool) {
	ctx, cancel := e.s.QueryContext(r)
	defer cancel()
	rows, err := e.q(ctx, query, params)
	if err != nil {
		e.s.WriteGraphError(w, r, err)
		return nil, false
	}
	return rows, true
}

func (e *Entities) notFound(w http.ResponseWriter, r *http.Request, typ, id string) {
	e.s.WriteError(w, r, http.StatusNotFound, ErrorBody{
		Code: "not_found", Message: typ + " " + id + " not found",
	})
}

func asProps(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

func asList(v any) []any {
	l, _ := v.([]any)
	if l == nil {
		return []any{}
	}
	return jsonValue(l).([]any)
}

func (e *Entities) vulnerability(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.PathValue("id"))
	ids, display := vulnerabilityIDCandidates(raw)
	if len(ids) == 0 {
		e.notFound(w, r, "Vulnerability", display)
		return
	}
	id := ids[0]
	rows, ok := e.run(w, r, cypherVulnerabilityByID, map[string]any{"id": id})
	if !ok {
		return
	}
	if len(rows) == 0 {
		// No node has this cveID: look for a node that lists it as an alias.
		found, ok := e.resolveAlias(w, r, ids)
		if !ok {
			return
		}
		if found == "" {
			e.notFound(w, r, "Vulnerability", display)
			return
		}
		if rows, ok = e.run(w, r, cypherVulnerabilityByID, map[string]any{"id": found}); !ok {
			return
		}
		if len(rows) == 0 {
			e.notFound(w, r, "Vulnerability", display)
			return
		}
	}
	row := rows[0]
	props, sources, prov := splitProps(asProps(row["props"]))
	cve, _ := props["cveID"].(string)
	if cve == "" {
		cve = id
	}
	packages, attackPatterns, techniques, ok := e.vulnerabilityLinks(w, r, cve)
	if !ok {
		return
	}
	e.s.WriteJSON(w, r, http.StatusOK, map[string]any{
		"packages":       packages,
		"attackPatterns": attackPatterns,
		"techniques":     techniques,
		"vulnerability":  props,
		"sources":        sources,
		"provenance":     prov,
		"weaknesses":     asList(row["weaknesses"]),
		"exploits":       asList(row["exploits"]),
		"products":       asList(row["products"]),
		"domains":        asList(row["domains"]),
		"repositories":   asList(row["repositories"]),
		"fixCommits":     asList(row["fixCommits"]),
	})
}

// vulnerabilityIDCandidates returns the ids a path value may stand for, in
// lookup order: the canonical CVE id or advisory id (Requirement 9), then the
// trimmed raw value when it differs (an alias in a form no resolver knows).
// ids is empty when the value cannot be an id. display is the id named in a
// 404 message: the canonical id, or the upper-cased raw value.
func vulnerabilityIDCandidates(raw string) (ids []string, display string) {
	display = strings.ToUpper(raw)
	if raw == "" || len(raw) > 200 {
		return nil, display
	}
	if k, err := resolve.CVE(raw); err == nil {
		ids, display = append(ids, k.Value), k.Value
	} else if k, err := resolve.Advisory(raw); err == nil {
		ids, display = append(ids, k.Value), k.Value
	}
	if len(ids) == 0 || ids[0] != raw {
		ids = append(ids, raw)
	}
	return ids, display
}

// resolveAlias returns the cveID of the Vulnerability that has one of ids in
// its aliases, or "" when none has. It returns false after writing a response
// when the query fails.
func (e *Entities) resolveAlias(w http.ResponseWriter, r *http.Request, ids []string) (string, bool) {
	rows, ok := e.run(w, r, cypherVulnerabilityByAlias, map[string]any{"aliases": ids})
	if !ok {
		return "", false
	}
	if len(rows) == 0 {
		return "", true
	}
	id, _ := rows[0]["cveID"].(string)
	return id, true
}

func (e *Entities) weakness(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(strings.TrimSpace(r.PathValue("cweID")))
	rows, ok := e.run(w, r, cypherWeaknessByID, map[string]any{"id": id})
	if !ok {
		return
	}
	if len(rows) == 0 {
		e.notFound(w, r, "Weakness", id)
		return
	}
	props, sources, prov := splitProps(asProps(rows[0]["props"]))
	e.s.WriteJSON(w, r, http.StatusOK, map[string]any{"weakness": props, "sources": sources, "provenance": prov})
}

// resolveName finds the stored key for name: exact match first, then a
// case-insensitive match. It returns false after writing a response when the
// query fails or nothing matches.
func (e *Entities) resolveName(w http.ResponseWriter, r *http.Request, typ, exactQ, foldQ, name string) (string, bool) {
	rows, ok := e.run(w, r, exactQ, map[string]any{"name": name})
	if !ok {
		return "", false
	}
	if len(rows) == 0 {
		if rows, ok = e.run(w, r, foldQ, map[string]any{"lower": strings.ToLower(name)}); !ok {
			return "", false
		}
	}
	if len(rows) > 0 {
		if k, _ := rows[0]["key"].(string); k != "" {
			return k, true
		}
	}
	e.notFound(w, r, typ, name)
	return "", false
}

func (e *Entities) product(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	key, ok := e.resolveName(w, r, "Product", cypherProductExact, cypherProductFold, name)
	if !ok {
		return
	}
	rows, ok := e.run(w, r, cypherProductByKey, map[string]any{"name": key})
	if !ok {
		return
	}
	if len(rows) == 0 {
		e.notFound(w, r, "Product", name)
		return
	}
	props, sources, prov := splitProps(asProps(rows[0]["props"]))
	e.s.WriteJSON(w, r, http.StatusOK, map[string]any{
		"product": props, "vendors": asList(rows[0]["vendors"]), "sources": sources, "provenance": prov,
	})
}

func (e *Entities) vendor(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	key, ok := e.resolveName(w, r, "Vendor", cypherVendorExact, cypherVendorFold, name)
	if !ok {
		return
	}
	rows, ok := e.run(w, r, cypherVendorByKey, map[string]any{"name": key})
	if !ok {
		return
	}
	if len(rows) == 0 {
		e.notFound(w, r, "Vendor", name)
		return
	}
	props, sources, prov := splitProps(asProps(rows[0]["props"]))
	e.s.WriteJSON(w, r, http.StatusOK, map[string]any{
		"vendor": props, "products": asList(rows[0]["products"]), "sources": sources, "provenance": prov,
	})
}

// exploitFields is the metadata whitelist (Requirement 24.2): no code, no
// other properties.
var exploitFields = []string{"eid", "exploitPublishDate", "exploitType", "platform"}

func (e *Entities) exploit(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("eid"))
	rows, ok := e.run(w, r, cypherExploitByID, map[string]any{"id": id})
	if !ok {
		return
	}
	if len(rows) == 0 {
		e.notFound(w, r, "Exploit", id)
		return
	}
	all, sources, prov := splitProps(asProps(rows[0]["props"]))
	meta := map[string]any{}
	for _, f := range exploitFields {
		if v, ok := all[f]; ok {
			meta[f] = v
		}
	}
	e.s.WriteJSON(w, r, http.StatusOK, map[string]any{
		"exploit": meta, "authors": asList(rows[0]["authors"]),
		"vulnerabilities": asList(rows[0]["vulnerabilities"]),
		"sources":         sources, "provenance": prov,
	})
}
