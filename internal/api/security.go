package api

import (
	"net/http"
	"strings"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/resolve"
)

// maxLinked bounds every list of related entities on a detail page.
const maxLinked = 100

// vulnerabilityLinks reads the package, attack pattern and technique lists
// of a vulnerability. Lists of a schema phase that is not applied are empty
// and their queries do not run. It returns false after writing a response
// when a query fails.
func (e *Entities) vulnerabilityLinks(w http.ResponseWriter, r *http.Request, cve string) (pkgs, aps, techs []any, ok bool) {
	pkgs, aps, techs = []any{}, []any{}, []any{}
	phase := e.s.maxPhase(r.Context())
	params := map[string]any{"id": cve, "limit": maxLinked}
	if phase >= 2 {
		rows, ok := e.run(w, r, cypherVulnerabilityPackages, params)
		if !ok {
			return nil, nil, nil, false
		}
		pkgs = rowsToList(rows)
	}
	if phase >= 3 {
		rows, ok := e.run(w, r, cypherVulnerabilityAttackPatterns, params)
		if !ok {
			return nil, nil, nil, false
		}
		aps = rowsToList(rows)
		if rows, ok = e.run(w, r, cypherVulnerabilityTechniques, params); !ok {
			return nil, nil, nil, false
		}
		techs = rowsToList(rows)
	}
	return pkgs, aps, techs, true
}

// rowsToList converts result rows to JSON-safe objects. A missing value
// stays null; a missing list becomes an empty list.
func rowsToList(rows []Row) []any {
	out := make([]any, len(rows))
	for i, row := range rows {
		m := make(map[string]any, len(row))
		for k, v := range row {
			if k == "affectedRanges" {
				m[k] = asList(v)
				continue
			}
			m[k] = jsonValue(v)
		}
		out[i] = m
	}
	return out
}

// entityPage serves one entity route: it looks the key up with query, then
// writes {name: props, ...lists, sources, provenance}. lists maps a row
// column to the response field of the same name.
func (e *Entities) entityPage(w http.ResponseWriter, r *http.Request, typ, name, id, display, query string, lists ...string) {
	rows, ok := e.run(w, r, query, map[string]any{"id": id, "limit": maxLinked})
	if !ok {
		return
	}
	if len(rows) == 0 {
		e.notFound(w, r, typ, display)
		return
	}
	props, sources, prov := splitProps(asProps(rows[0]["props"]))
	body := map[string]any{name: props, "sources": sources, "provenance": prov}
	for _, l := range lists {
		body[l] = asList(rows[0][l])
	}
	e.s.WriteJSON(w, r, http.StatusOK, body)
}

func (e *Entities) pkg(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.PathValue("purl"))
	id := raw
	if k, err := resolve.Package(raw); err == nil {
		id = k.Value
	}
	if len(id) > maxIDLen {
		e.notFound(w, r, "Package", id[:maxIDLen])
		return
	}
	rows, ok := e.run(w, r, cypherPackageByPurl, map[string]any{"id": id, "limit": maxLinked})
	if !ok {
		return
	}
	if len(rows) == 0 {
		e.notFound(w, r, "Package", id)
		return
	}
	vulns, ok := e.run(w, r, cypherPackageVulns, map[string]any{"id": id, "limit": maxLinked})
	if !ok {
		return
	}
	props, sources, prov := splitProps(asProps(rows[0]["props"]))
	e.s.WriteJSON(w, r, http.StatusOK, map[string]any{
		"package": props, "vulnerabilities": rowsToList(vulns),
		"repositories": asList(rows[0]["repositories"]),
		"sources":      sources, "provenance": prov,
	})
}

func (e *Entities) attackPattern(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.PathValue("capecID"))
	id, display := canonical(raw, resolve.CAPEC)
	e.entityPage(w, r, "AttackPattern", "attackPattern", id, display, cypherAttackPatternByID, "weaknesses", "techniques")
}

func (e *Entities) technique(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.PathValue("attackID"))
	id, display := canonical(raw, resolve.Technique)
	e.entityPage(w, r, "Technique", "technique", id, display, cypherTechniqueByID, "attackPatterns", "atlasTechniques")
}

func (e *Entities) atlasTechnique(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.PathValue("atlasID"))
	id, display := canonical(raw, resolve.Atlas)
	e.entityPage(w, r, "AtlasTechnique", "atlasTechnique", id, display, cypherAtlasTechniqueByID, "techniques")
}

// canonical returns the stored key for raw, or the upper-cased raw value
// (cut to maxIDLen) when the resolver rejects it, and the id to show in a
// 404 message.
func canonical(raw string, resolver func(string) (resolve.Key, error)) (id, display string) {
	if k, err := resolver(raw); err == nil {
		return k.Value, k.Value
	}
	id = strings.ToUpper(raw)
	if len(id) > maxIDLen {
		id = id[:maxIDLen]
	}
	return id, id
}
