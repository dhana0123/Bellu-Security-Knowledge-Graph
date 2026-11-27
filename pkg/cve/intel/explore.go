package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// Explorer is the read-only graph exploration surface used by the viewer API.
// It is implemented by the SQLite client returned from Open and kept separate
// from Client so existing Client implementations stay valid.
type Explorer interface {
	// GraphSlice returns up to limit nodes (ordered by id, optionally filtered by
	// node type) and the edges among them.
	GraphSlice(ctx context.Context, limit int, types []string) (*Subgraph, error)
	// Neighborhood returns the nodes within depth hops of a node (either edge
	// direction), capped at limit nodes, and the edges among them. id is a node
	// id or any identifier accepted by GetVulnerability.
	Neighborhood(ctx context.Context, id string, depth, limit int) (*Subgraph, error)
	GetNode(ctx context.Context, id string) (*GraphNode, error)
	Stats(ctx context.Context) (*Stats, error)
	Snapshot(ctx context.Context) (*SnapshotInfo, error)
	Search(ctx context.Context, q string, limit int) (*SearchResult, error)
	// History lists the recorded versions of the source records of a
	// vulnerability. Without a history table it returns ErrHistoryUnavailable.
	History(ctx context.Context, id string) ([]HistoryEntry, error)
	GetAdvisory(ctx context.Context, id string) (*Advisory, error)
	GetPackage(ctx context.Context, ecosystem, name string) (*PackageDetail, error)
}

// Limits for exploration queries.
const (
	MaxGraphNodes = 5000
	MaxDepth      = 3
	MaxSearchHits = 100
)

// GraphNode is a node with its raw properties.
type GraphNode struct {
	ID    string         `json:"id"`
	Type  string         `json:"type"`
	Props map[string]any `json:"props"`
}

// GraphEdge is an edge with its raw properties.
type GraphEdge struct {
	ID    string         `json:"id"`
	Type  string         `json:"type"`
	Src   string         `json:"src"`
	Dst   string         `json:"dst"`
	Props map[string]any `json:"props"`
}

// Subgraph is a set of nodes and the edges among them.
type Subgraph struct {
	Nodes     []GraphNode
	Edges     []GraphEdge
	Truncated bool   // more nodes exist than were returned
	Center    string // resolved start node of a neighbourhood query
}

// Coverage counts vulnerabilities carrying each enrichment.
type Coverage struct {
	Vulnerabilities int
	KEV             int
	EPSS            int
	CVSS            int
}

// SnapshotInfo describes the opened graph.db.
type SnapshotInfo struct {
	Meta       map[string]string
	HasHistory bool
	Nodes      int
	Edges      int
}

// Stats summarises the graph.
type Stats struct {
	Nodes         int
	Edges         int
	NodesByType   map[string]int
	EdgesByType   map[string]int
	RecordsBySrc  map[string]int // SourceRecord nodes of kind "record" per source
	Coverage      Coverage
	Discrepancies int
	TrustStates   map[string]int
	Snapshot      SnapshotInfo
}

// SearchResult holds matches of a free-text search.
type SearchResult struct {
	Vulnerabilities []VulnerabilitySummary
	Packages        []PackageRef
	Products        []ProductRef
}

// PackageRef identifies a package node.
type PackageRef struct {
	ID        string
	Ecosystem string
	Name      string
}

// ProductRef identifies a product node.
type ProductRef struct {
	ID      string
	Vendor  string
	Product string
}

// HistoryEntry is one recorded version of a source record.
type HistoryEntry struct {
	EntityID   string
	Source     string
	ExternalID string
	Version    int
	EventTime  string
	RecordedAt string
	State      string
	Modified   string
}

// Advisory is the detail of one source record.
type Advisory struct {
	ID            string
	Source        string
	ExternalID    string
	Kind          string
	Identifiers   []string
	Modified      string
	Withdrawn     string
	Vulnerability string // merged vulnerability id, empty when unlinked
	Severities    []SeverityAssessment
}

// PackageDetail is the detail of one package node.
type PackageDetail struct {
	ID              string
	Ecosystem       string
	Name            string
	Mapped          bool
	VulnerabilityN  int
	Vulnerabilities []VulnRef // up to MaxSearchHits, ordered by id
}

var _ Explorer = (*sqliteClient)(nil)

func (c *sqliteClient) nodeCount(ctx context.Context, q string, args ...any) (int, error) {
	var n int
	err := c.db.QueryRowContext(ctx, q, args...).Scan(&n)
	return n, err
}

func (c *sqliteClient) countBy(ctx context.Context, q string) (map[string]int, error) {
	rows, err := c.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k *string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		key := ""
		if k != nil {
			key = *k
		}
		out[key] = n
	}
	return out, rows.Err()
}

func (c *sqliteClient) edgesAmong(ctx context.Context, ids map[string]bool) ([]GraphEdge, error) {
	list := make([]string, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	sort.Strings(list)
	out := []GraphEdge{}
	const chunk = 400
	for i := 0; i < len(list); i += chunk {
		part := list[i:min(i+chunk, len(list))]
		args := make([]any, len(part))
		for j, id := range part {
			args[j] = id
		}
		q := `SELECT id,type,src,dst,props FROM edges WHERE src IN (?` + strings.Repeat(",?", len(part)-1) + `)`
		rows, err := c.db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var e GraphEdge
			var props string
			if err := rows.Scan(&e.ID, &e.Type, &e.Src, &e.Dst, &props); err != nil {
				rows.Close()
				return nil, err
			}
			if !ids[e.Dst] {
				continue
			}
			if err := json.Unmarshal([]byte(props), &e.Props); err != nil {
				rows.Close()
				return nil, fmt.Errorf("edge %s: %w", e.ID, err)
			}
			out = append(out, e)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func toGraphNodes(ns []nodeRow) []GraphNode {
	out := make([]GraphNode, 0, len(ns))
	for _, n := range ns {
		out = append(out, GraphNode{ID: n.ID, Type: n.Type, Props: n.Props})
	}
	return out
}

// GraphSlice implements Explorer.
func (c *sqliteClient) GraphSlice(ctx context.Context, limit int, types []string) (*Subgraph, error) {
	if limit < 1 || limit > MaxGraphNodes {
		return nil, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalidRequest, MaxGraphNodes)
	}
	q := `SELECT id, type, props FROM nodes`
	args := []any{}
	if len(types) > 0 {
		q += ` WHERE type IN (?` + strings.Repeat(",?", len(types)-1) + `)`
		for _, t := range types {
			args = append(args, t)
		}
	}
	q += ` ORDER BY id LIMIT ?`
	args = append(args, limit+1)
	ns, err := c.queryNodes(ctx, q, args...)
	if err != nil {
		return nil, unavailable(err)
	}
	g := &Subgraph{}
	if len(ns) > limit {
		ns, g.Truncated = ns[:limit], true
	}
	ids := make(map[string]bool, len(ns))
	for _, n := range ns {
		ids[n.ID] = true
	}
	g.Nodes = toGraphNodes(ns)
	if len(ids) == 0 {
		g.Edges = []GraphEdge{}
		return g, nil
	}
	if g.Edges, err = c.edgesAmong(ctx, ids); err != nil {
		return nil, unavailable(err)
	}
	return g, nil
}

func (c *sqliteClient) resolveAnyNode(ctx context.Context, id string) (*nodeRow, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("%w: id must not be empty", ErrInvalidRequest)
	}
	n, err := c.node(ctx, id)
	if err != nil {
		return nil, unavailable(err)
	}
	if n != nil {
		return n, nil
	}
	return c.resolveVulnerability(ctx, id)
}

// GetNode implements Explorer.
func (c *sqliteClient) GetNode(ctx context.Context, id string) (*GraphNode, error) {
	n, err := c.resolveAnyNode(ctx, id)
	if err != nil {
		return nil, unavailable(err)
	}
	return &GraphNode{ID: n.ID, Type: n.Type, Props: n.Props}, nil
}

// Neighborhood implements Explorer.
func (c *sqliteClient) Neighborhood(ctx context.Context, id string, depth, limit int) (*Subgraph, error) {
	if depth < 1 || depth > MaxDepth {
		return nil, fmt.Errorf("%w: depth must be between 1 and %d", ErrInvalidRequest, MaxDepth)
	}
	if limit < 1 || limit > MaxGraphNodes {
		return nil, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalidRequest, MaxGraphNodes)
	}
	start, err := c.resolveAnyNode(ctx, id)
	if err != nil {
		return nil, unavailable(err)
	}
	seen := map[string]bool{start.ID: true}
	frontier := []string{start.ID}
	truncated := false
	for d := 0; d < depth && len(frontier) > 0 && !truncated; d++ {
		var next []string
		for _, f := range frontier {
			rows, err := c.db.QueryContext(ctx, `SELECT dst FROM edges WHERE src=? UNION SELECT src FROM edges WHERE dst=? ORDER BY 1`, f, f)
			if err != nil {
				return nil, unavailable(err)
			}
			for rows.Next() {
				var o string
				if err := rows.Scan(&o); err != nil {
					rows.Close()
					return nil, unavailable(err)
				}
				if seen[o] {
					continue
				}
				if len(seen) >= limit {
					truncated = true
					continue
				}
				seen[o] = true
				next = append(next, o)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return nil, unavailable(err)
			}
		}
		frontier = next
	}
	g := &Subgraph{Truncated: truncated, Nodes: []GraphNode{}, Center: start.ID}
	ids := make([]string, 0, len(seen))
	for s := range seen {
		ids = append(ids, s)
	}
	sort.Strings(ids)
	for _, nid := range ids {
		n, err := c.node(ctx, nid)
		if err != nil {
			return nil, unavailable(err)
		}
		if n != nil {
			g.Nodes = append(g.Nodes, GraphNode{ID: n.ID, Type: n.Type, Props: n.Props})
		}
	}
	if g.Edges, err = c.edgesAmong(ctx, seen); err != nil {
		return nil, unavailable(err)
	}
	return g, nil
}

// Snapshot implements Explorer.
func (c *sqliteClient) Snapshot(ctx context.Context) (*SnapshotInfo, error) {
	s, err := c.snapshot(ctx)
	if err != nil {
		return nil, unavailable(err)
	}
	return s, nil
}

func (c *sqliteClient) snapshot(ctx context.Context) (*SnapshotInfo, error) {
	s := &SnapshotInfo{Meta: map[string]string{}}
	rows, err := c.db.QueryContext(ctx, `SELECT key, value FROM meta ORDER BY key`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return nil, err
		}
		s.Meta[k] = v
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	s.HasHistory = s.Meta["has_history"] == "true"
	if s.Nodes, err = c.nodeCount(ctx, `SELECT COUNT(*) FROM nodes`); err != nil {
		return nil, err
	}
	if s.Edges, err = c.nodeCount(ctx, `SELECT COUNT(*) FROM edges`); err != nil {
		return nil, err
	}
	return s, nil
}

// Stats implements Explorer.
func (c *sqliteClient) Stats(ctx context.Context) (*Stats, error) {
	st, err := c.stats(ctx)
	if err != nil {
		return nil, unavailable(err)
	}
	return st, nil
}

func (c *sqliteClient) stats(ctx context.Context) (*Stats, error) {
	snap, err := c.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	st := &Stats{Nodes: snap.Nodes, Edges: snap.Edges, Snapshot: *snap}
	if st.NodesByType, err = c.countBy(ctx, `SELECT type, COUNT(*) FROM nodes GROUP BY type`); err != nil {
		return nil, err
	}
	if st.EdgesByType, err = c.countBy(ctx, `SELECT type, COUNT(*) FROM edges GROUP BY type`); err != nil {
		return nil, err
	}
	if st.RecordsBySrc, err = c.countBy(ctx, `SELECT json_extract(props,'$.source'), COUNT(*) FROM nodes
		WHERE type='SourceRecord' AND json_extract(props,'$.kind')='record' GROUP BY 1`); err != nil {
		return nil, err
	}
	if st.TrustStates, err = c.countBy(ctx, `SELECT json_extract(props,'$.trust_state'), COUNT(*) FROM nodes
		WHERE type='Vulnerability' GROUP BY 1`); err != nil {
		return nil, err
	}
	cv := &st.Coverage
	cv.Vulnerabilities = st.NodesByType["Vulnerability"]
	if cv.KEV, err = c.nodeCount(ctx, `SELECT COUNT(DISTINCT src) FROM edges WHERE type='LISTED_IN_KEV'`); err != nil {
		return nil, err
	}
	if cv.EPSS, err = c.nodeCount(ctx, `SELECT COUNT(DISTINCT src) FROM edges WHERE type='HAS_EPSS'`); err != nil {
		return nil, err
	}
	if cv.CVSS, err = c.nodeCount(ctx, `SELECT COUNT(DISTINCT e.src) FROM edges e JOIN nodes n ON n.id=e.dst
		WHERE e.type='HAS_ASSESSMENT' AND lower(COALESCE(json_extract(n.props,'$.type'),'')) LIKE '%cvss%'`); err != nil {
		return nil, err
	}
	if st.Discrepancies, err = c.nodeCount(ctx, `SELECT COUNT(*) FROM nodes WHERE type='Vulnerability'
		AND json_extract(props,'$.discrepancy') IN (1, 'true')`); err != nil {
		return nil, err
	}
	return st, nil
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// Search implements Explorer. Vulnerabilities match by id or alias prefix,
// packages and products by name substring.
func (c *sqliteClient) Search(ctx context.Context, q string, limit int) (*SearchResult, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return nil, fmt.Errorf("%w: q must not be empty", ErrInvalidRequest)
	}
	if limit < 1 || limit > MaxSearchHits {
		return nil, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalidRequest, MaxSearchHits)
	}
	res := &SearchResult{Vulnerabilities: []VulnerabilitySummary{}, Packages: []PackageRef{}, Products: []ProductRef{}}
	seen := map[string]bool{}
	add := func(n nodeRow) {
		id := strings.TrimPrefix(n.ID, "vuln:")
		if seen[id] || len(res.Vulnerabilities) >= limit {
			return
		}
		seen[id] = true
		res.Vulnerabilities = append(res.Vulnerabilities, VulnerabilitySummary{ID: id, Summary: str(n.Props, "summary"), TrustState: str(n.Props, "trust_state")})
	}
	up := escapeLike(strings.ToUpper(q))
	vs, err := c.queryNodes(ctx, `SELECT id, type, props FROM nodes WHERE type='Vulnerability'
		AND id LIKE ? ESCAPE '\' ORDER BY id LIMIT ?`, "vuln:"+up+"%", limit)
	if err != nil {
		return nil, unavailable(err)
	}
	for _, v := range vs {
		add(v)
	}
	if len(res.Vulnerabilities) < limit {
		als, err := c.queryNodes(ctx, `SELECT id, type, props FROM nodes WHERE type='SourceRecord'
			AND upper(json_extract(props,'$.external_id')) LIKE ? ESCAPE '\' ORDER BY id LIMIT ?`, up+"%", limit)
		if err != nil {
			return nil, unavailable(err)
		}
		for _, a := range als {
			v, err := c.followAlias(ctx, a.ID)
			if err != nil {
				return nil, unavailable(err)
			}
			if v != nil {
				add(*v)
			}
		}
	}
	like := "%" + escapeLike(strings.ToLower(q)) + "%"
	pk, err := c.queryNodes(ctx, `SELECT id, type, props FROM nodes WHERE type='Package'
		AND lower(json_extract(props,'$.name')) LIKE ? ESCAPE '\' ORDER BY id LIMIT ?`, like, limit)
	if err != nil {
		return nil, unavailable(err)
	}
	for _, p := range pk {
		res.Packages = append(res.Packages, PackageRef{ID: p.ID, Ecosystem: str(p.Props, "ecosystem"), Name: str(p.Props, "name")})
	}
	pr, err := c.queryNodes(ctx, `SELECT id, type, props FROM nodes WHERE type='Product'
		AND lower(json_extract(props,'$.product')) LIKE ? ESCAPE '\' ORDER BY id LIMIT ?`, like, limit)
	if err != nil {
		return nil, unavailable(err)
	}
	for _, p := range pr {
		res.Products = append(res.Products, ProductRef{ID: p.ID, Vendor: str(p.Props, "vendor"), Product: str(p.Props, "product")})
	}
	return res, nil
}

// History implements Explorer.
func (c *sqliteClient) History(ctx context.Context, id string) ([]HistoryEntry, error) {
	if err := c.requireHistory(ctx); err != nil {
		return nil, err
	}
	vn, err := c.resolveVulnerability(ctx, id)
	if err != nil {
		return nil, unavailable(err)
	}
	cur, err := c.loadVulnerability(ctx, vn)
	if err != nil {
		return nil, unavailable(err)
	}
	out := []HistoryEntry{}
	for _, s := range cur.Sources {
		rows, err := c.db.QueryContext(ctx, `SELECT version, COALESCE(event_time,''), COALESCE(recorded_at,''), COALESCE(state,''), COALESCE(payload,'')
			FROM history WHERE entity_id=? ORDER BY version`, s.ID)
		if err != nil {
			return nil, unavailable(err)
		}
		for rows.Next() {
			h := HistoryEntry{EntityID: s.ID, Source: s.Source, ExternalID: s.ExternalID}
			var payload string
			if err := rows.Scan(&h.Version, &h.EventTime, &h.RecordedAt, &h.State, &payload); err != nil {
				rows.Close()
				return nil, unavailable(err)
			}
			var rec model.Record
			if json.Unmarshal([]byte(payload), &rec) == nil && !rec.Modified.IsZero() {
				h.Modified = rec.Modified.UTC().Format("2006-01-02T15:04:05Z")
			}
			out = append(out, h)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, unavailable(err)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RecordedAt != out[j].RecordedAt {
			return out[i].RecordedAt < out[j].RecordedAt
		}
		if out[i].EntityID != out[j].EntityID {
			return out[i].EntityID < out[j].EntityID
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
}

// GetAdvisory implements Explorer. id is a source-record node id ("src:...",
// "alias:...") or a bare external id; with several matches the smallest node id wins.
func (c *sqliteClient) GetAdvisory(ctx context.Context, id string) (*Advisory, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("%w: id must not be empty", ErrInvalidRequest)
	}
	var n *nodeRow
	var err error
	if strings.HasPrefix(id, "src:") || strings.HasPrefix(id, "alias:") {
		if n, err = c.node(ctx, id); err != nil {
			return nil, unavailable(err)
		}
		if n != nil && n.Type != "SourceRecord" {
			n = nil
		}
	} else {
		for _, in := range []string{id, strings.ToUpper(id)} {
			var ns []nodeRow
			ns, err = c.queryNodes(ctx, `SELECT id, type, props FROM nodes WHERE type='SourceRecord'
				AND json_extract(props,'$.external_id')=? ORDER BY id LIMIT 1`, in)
			if err != nil {
				return nil, unavailable(err)
			}
			if len(ns) > 0 {
				n = &ns[0]
				break
			}
		}
	}
	if n == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	a := &Advisory{ID: n.ID, Source: str(n.Props, "source"), ExternalID: str(n.Props, "external_id"),
		Kind: str(n.Props, "kind"), Modified: str(n.Props, "modified"), Withdrawn: str(n.Props, "withdrawn"),
		Identifiers: []string{}, Severities: []SeverityAssessment{}}
	if l, ok := n.Props["identifiers"].([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				a.Identifiers = append(a.Identifiers, s)
			}
		}
	}
	v, err := c.followAlias(ctx, n.ID)
	if err != nil {
		return nil, unavailable(err)
	}
	if v != nil {
		a.Vulnerability = strings.TrimPrefix(v.ID, "vuln:")
		sevs, err := c.neighbors(ctx, v.ID, "HAS_ASSESSMENT")
		if err != nil {
			return nil, unavailable(err)
		}
		for _, s := range sevs {
			if a.Kind == "record" && (str(s.Props, "record_id") != a.ExternalID || str(s.Props, "source") != a.Source) {
				continue
			}
			a.Severities = append(a.Severities, SeverityAssessment{
				ID: s.ID, Source: str(s.Props, "source"), RecordID: str(s.Props, "record_id"), Type: str(s.Props, "type"),
				Version: str(s.Props, "version"), Score: num(s.Props, "score"), Vector: str(s.Props, "vector"),
				Rating: str(s.Props, "rating"), Validation: str(s.Props, "validation"), Reason: str(s.Props, "reason")})
		}
	}
	return a, nil
}

// GetPackage implements Explorer.
func (c *sqliteClient) GetPackage(ctx context.Context, ecosystem, name string) (*PackageDetail, error) {
	if strings.TrimSpace(ecosystem) == "" || strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%w: ecosystem and name must not be empty", ErrInvalidRequest)
	}
	id := model.PackageID(ecosystem, name)
	n, err := c.node(ctx, id)
	if err != nil {
		return nil, unavailable(err)
	}
	if n == nil || n.Type != "Package" {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	d := &PackageDetail{ID: id, Ecosystem: str(n.Props, "ecosystem"), Name: str(n.Props, "name")}
	d.Mapped, _ = n.Props["mapped"].(bool)
	if d.VulnerabilityN, err = c.nodeCount(ctx, `SELECT COUNT(DISTINCT src) FROM edges WHERE dst=? AND type='AFFECTS'`, id); err != nil {
		return nil, unavailable(err)
	}
	if d.Vulnerabilities, err = c.searchAffects(ctx, id, PageReq{Limit: MaxSearchHits}); err != nil {
		return nil, err
	}
	return d, nil
}
