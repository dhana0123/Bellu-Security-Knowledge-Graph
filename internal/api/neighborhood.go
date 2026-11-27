package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/graph"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/model"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/resolve"
)

const (
	neighborhoodDefaultLimit = 100
	neighborhoodMaxLimit     = 300
	neighborhoodMaxList      = 50
	maxIDLen                 = 256
	maxNodeLabelLen          = 100
	maxPropStringLen         = 500
)

// neighborhoodQueries holds one constant query per (label, depth), generated
// at start-up from the schema registry (label and key names never come from a
// request) and registered in allQueries for the read-only lint.
var neighborhoodQueries = map[string][2]string{}

const nbLayer1 = `
MATCH (s:%[1]s {%[2]s: $id})
CALL {
  WITH s
  MATCH (s)-[r]-(a)
  WHERE a <> s AND ($allRels OR type(r) IN $relTypes)
    AND ($allNodes OR any(l IN labels(a) WHERE l IN $nodeTypes))
  WITH DISTINCT a, {nid(a)} AS aid
  ORDER BY aid
  LIMIT $cap
  RETURN collect(a) AS d1
}`

const nbLayer2 = `
CALL {
  WITH s, d1
  UNWIND (CASE WHEN size(d1) <= $keep THEN d1 ELSE [] END) AS a
  MATCH (a)-[r]-(b)
  WHERE b <> s AND NOT b IN d1 AND ($allRels OR type(r) IN $relTypes)
    AND ($allNodes OR any(l IN labels(b) WHERE l IN $nodeTypes))
  WITH DISTINCT b, {nid(b)} AS bid
  ORDER BY bid
  LIMIT $cap
  RETURN collect(b) AS d2
}`

const nbTail = `
WITH s, %s AS ordered
WITH s, ordered[0..$keep] AS sel, size(ordered) > $keep AS truncated
CALL {
  WITH s, sel
  WITH [s] + sel AS members
  UNWIND members AS x
  MATCH (x)-[r]->(y)
  WHERE y IN members AND ($allRels OR type(r) IN $relTypes)
  RETURN collect({source: {nid(x)}, target: {nid(y)}, type: type(r), viewID: r.viewID}) AS edges
}
RETURN [n IN [s] + sel | {id: {nid(n)}, labels: labels(n), props: properties(n)}] AS nodes, edges, truncated`

// keyExpr returns the key property of node v by its domain label. A
// coalesce over all key names is wrong once two labels share a property name
// (FixCommit has a url property, and url is the Repository key).
func keyExpr(v string) string {
	var b strings.Builder
	b.WriteString("CASE head([l IN labels(" + v + ") WHERE l IN $domainLabels])")
	for _, l := range model.Labels {
		if l.Kind == model.Domain {
			fmt.Fprintf(&b, " WHEN '%s' THEN %s.%s", l.Name, v, l.Key)
		}
	}
	b.WriteString(" END")
	return b.String()
}
func nidExpr(v string) string {
	return fmt.Sprintf("head([l IN labels(%s) WHERE l IN $domainLabels]) + ':' + toString(%s)", v, keyExpr(v))
}
func buildNeighborhood(label, key string, depth int) string {
	q := fmt.Sprintf(nbLayer1, label, key)
	var tail string
	if depth == 2 {
		q += nbLayer2
		tail = fmt.Sprintf(nbTail, "d1 + d2")
	} else {
		tail = fmt.Sprintf(nbTail, "d1")
	}
	q += tail
	for _, v := range []string{"a", "b", "x", "y", "n"} {
		q = strings.ReplaceAll(q, "{nid("+v+")}", nidExpr(v))
	}
	return q
}

func init() {
	for _, l := range model.Labels {
		if l.Kind == model.Domain {
			q1 := buildNeighborhood(l.Name, l.Key, 1)
			q2 := buildNeighborhood(l.Name, l.Key, 2)
			neighborhoodQueries[l.Name] = [2]string{q1, q2}
			allQueries = append(allQueries, q1, q2)
		}
	}
}

// writeParamError answers 400 for a *paramError.
func (s *Server) writeParamError(w http.ResponseWriter, r *http.Request, err error) {
	var pe *paramError
	if errors.As(err, &pe) {
		s.WriteError(w, r, http.StatusBadRequest, ErrorBody{Code: "invalid_parameter", Message: pe.msg, Parameter: pe.param})
		return
	}
	s.WriteError(w, r, http.StatusBadRequest, ErrorBody{Code: "invalid_parameter", Message: "invalid request"})
}

type nbRequest struct {
	label     string
	id        string
	depth     int
	limit     int
	nodeTypes []string
	relTypes  []string
}

func (o *ops) parseNeighborhood(r *http.Request) (nbRequest, error) {
	v := r.URL.Query()
	req := nbRequest{depth: 1, limit: neighborhoodDefaultLimit}
	maxPhase := o.s.maxPhase(r.Context())
	allowedLabels := map[string]bool{}
	for _, n := range model.DomainLabels(maxPhase) {
		allowedLabels[n] = true
	}
	req.label = v.Get("type")
	if req.label == "" {
		return req, bad("type", "is required")
	}
	if !allowedLabels[req.label] {
		return req, bad("type", "is not a known node type")
	}
	req.id = strings.TrimSpace(v.Get("id"))
	if req.id == "" {
		return req, bad("id", "is required")
	}
	if utf8.RuneCountInString(req.id) > maxIDLen {
		return req, bad("id", "must be at most 256 characters")
	}
	if req.label == "Vulnerability" {
		// CVE ids are upper case; advisory ids have their own canonical form.
		if k, err := resolve.CVE(req.id); err == nil {
			req.id = k.Value
		} else if k, err := resolve.Advisory(req.id); err == nil {
			req.id = k.Value
		} else {
			req.id = strings.ToUpper(req.id)
		}
	}
	if s := v.Get("depth"); s != "" {
		if s != "1" && s != "2" {
			return req, bad("depth", "must be 1 or 2")
		}
		req.depth = int(s[0] - '0')
	}
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > neighborhoodMaxLimit {
			return req, bad("limit", "must be an integer from 1 to 300")
		}
		req.limit = n
	}
	var err error
	if req.nodeTypes, err = parseAllowList(v.Get("nodeTypes"), "nodeTypes", allowedLabels); err != nil {
		return req, err
	}
	allowedRels := map[string]bool{}
	for _, rt := range model.Rels {
		if rt.Phase <= maxPhase {
			allowedRels[rt.Name] = true
		}
	}
	if req.relTypes, err = parseAllowList(v.Get("relTypes"), "relTypes", allowedRels); err != nil {
		return req, err
	}
	return req, nil
}

// parseAllowList parses a comma list. It returns nil when the parameter is
// absent or empty (no restriction).
func parseAllowList(s, param string, allowed map[string]bool) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	if len(parts) > neighborhoodMaxList {
		return nil, bad(param, "must have at most 50 entries")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if !allowed[p] {
			return nil, bad(param, "contains an unknown entry")
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

type nbNode struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Key        string         `json:"key"`
	Label      string         `json:"label"`
	Properties map[string]any `json:"properties"`
}

type nbEdge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
	ViewID any    `json:"viewID,omitempty"`
}

func cutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// scalarProps keeps scalar values only; lists, maps, internal and provenance
// properties are dropped and long strings are cut.
func scalarProps(props map[string]any) map[string]any {
	out := map[string]any{}
	for k, raw := range props {
		if strings.HasPrefix(k, "bskg") || provKey.MatchString(k) {
			continue
		}
		switch x := jsonValue(raw).(type) {
		case string:
			out[k] = cutRunes(x, maxPropStringLen)
		case bool, int64, int, float64:
			out[k] = x
		}
	}
	return out
}

func (o *ops) neighborhood(w http.ResponseWriter, r *http.Request) {
	req, err := o.parseNeighborhood(r)
	if err != nil {
		o.s.writeParamError(w, r, err)
		return
	}
	ctx, cancel := o.s.QueryContext(r)
	defer cancel()
	qs := neighborhoodQueries[req.label]
	params := map[string]any{
		"id": req.id, "limit": int64(req.limit), "cap": int64(req.limit), "keep": int64(req.limit - 1),
		"allRels": req.relTypes == nil, "relTypes": orEmpty(req.relTypes),
		"allNodes": req.nodeTypes == nil, "nodeTypes": orEmpty(req.nodeTypes),
		"domainLabels": model.DomainLabels(o.s.maxPhase(r.Context())),
	}
	rows, err := o.q(ctx, qs[req.depth-1], params)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || graph.Classify(err) == graph.ClassTransient {
			o.s.WriteError(w, r, http.StatusServiceUnavailable, ErrorBody{Code: "unavailable", Message: "the neighborhood query timed out or the graph store is unavailable"})
			return
		}
		o.s.WriteGraphError(w, r, err)
		return
	}
	if len(rows) == 0 {
		o.s.WriteError(w, r, http.StatusNotFound, ErrorBody{Code: "not_found", Message: req.label + " " + req.id + " not found"})
		return
	}
	row := rows[0]
	nodes := []nbNode{}
	for _, n := range asList(row["nodes"]) {
		m, _ := n.(map[string]any)
		id, _ := m["id"].(string)
		typ, key, ok := strings.Cut(id, ":")
		if !ok {
			continue
		}
		nodes = append(nodes, nbNode{ID: id, Type: typ, Key: key, Label: cutRunes(key, maxNodeLabelLen), Properties: scalarProps(asProps(m["props"]))})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	edges := []nbEdge{}
	seen := map[string]bool{}
	for _, e := range asList(row["edges"]) {
		m, _ := e.(map[string]any)
		src, _ := m["source"].(string)
		dst, _ := m["target"].(string)
		typ, _ := m["type"].(string)
		if src == "" || dst == "" {
			continue
		}
		ed := nbEdge{Source: src, Target: dst, Type: typ, ID: src + "|" + typ + "|" + dst}
		if vid := m["viewID"]; vid != nil {
			ed.ViewID = vid
			ed.ID += "|" + fmt.Sprint(vid)
		}
		if !seen[ed.ID] {
			seen[ed.ID] = true
			edges = append(edges, ed)
		}
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
	truncated, _ := row["truncated"].(bool)
	o.s.WriteJSON(w, r, http.StatusOK, map[string]any{"nodes": nodes, "edges": edges, "truncated": truncated})
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
