package intel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	_ "modernc.org/sqlite" // pure Go SQLite driver
)

// sqliteClient implements Client over a graph.db opened read-only.
type sqliteClient struct {
	db *sql.DB
}

var _ Client = (*sqliteClient)(nil)

// Open opens a graph.db read-only (mode=ro, query_only) and checks its schema version.
func Open(path string) (Client, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty path", ErrInvalidRequest)
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSourceUnavailable, err)
	}
	u := url.URL{Scheme: "file", Opaque: (&url.URL{Path: path}).EscapedPath(),
		RawQuery: "mode=ro&immutable=0&_pragma=query_only(1)&_pragma=busy_timeout(5000)"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSourceUnavailable, err)
	}
	var raw string
	err = db.QueryRowContext(context.Background(), `SELECT value FROM meta WHERE key='schema_version'`).Scan(&raw)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: reading meta.schema_version: %v", ErrSourceUnavailable, err)
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v < 1 {
		_ = db.Close()
		return nil, fmt.Errorf("%w: invalid meta.schema_version %q", ErrSourceUnavailable, raw)
	}
	if v > MaxSchemaVersion {
		_ = db.Close()
		return nil, &SchemaVersionError{File: v, Supported: MaxSchemaVersion}
	}
	return &sqliteClient{db: db}, nil
}

// Close releases the database handle.
func (c *sqliteClient) Close() error { return c.db.Close() }

func unavailable(err error) error {
	if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidRequest) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrSourceUnavailable, err)
}

type nodeRow struct {
	ID    string
	Type  string
	Props map[string]any
}

func (c *sqliteClient) node(ctx context.Context, id string) (*nodeRow, error) {
	var typ, props string
	err := c.db.QueryRowContext(ctx, `SELECT type, props FROM nodes WHERE id=?`, id).Scan(&typ, &props)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n := &nodeRow{ID: id, Type: typ}
	if err := json.Unmarshal([]byte(props), &n.Props); err != nil {
		return nil, fmt.Errorf("node %s: %w", id, err)
	}
	return n, nil
}

// neighbors returns the dst nodes of edges (src, typ), ordered by node id.
func (c *sqliteClient) neighbors(ctx context.Context, src, typ string) ([]nodeRow, error) {
	return c.queryNodes(ctx, `SELECT n.id, n.type, n.props FROM edges e JOIN nodes n ON n.id=e.dst
		WHERE e.src=? AND e.type=? ORDER BY n.id`, src, typ)
}

func (c *sqliteClient) queryNodes(ctx context.Context, q string, args ...any) ([]nodeRow, error) {
	rows, err := c.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []nodeRow
	for rows.Next() {
		var n nodeRow
		var props string
		if err := rows.Scan(&n.ID, &n.Type, &props); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(props), &n.Props); err != nil {
			return nil, fmt.Errorf("node %s: %w", n.ID, err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// resolveVulnerability maps an identifier to a Vulnerability node id.
// Accepted: vuln:/src:/alias: prefixed node ids, or a bare id (vuln id, alias
// or source external id). Source-record and alias nodes are followed through
// ALIAS_OF; when several vulnerabilities result, the smallest id wins.
func (c *sqliteClient) resolveVulnerability(ctx context.Context, id string) (*nodeRow, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("%w: id must not be empty", ErrInvalidRequest)
	}
	if strings.HasPrefix(id, "vuln:") || strings.HasPrefix(id, "src:") || strings.HasPrefix(id, "alias:") {
		v, err := c.resolveNodeID(ctx, id)
		if err == nil && v == nil {
			err = fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		return v, err
	}
	// Stored identifiers are upper-case; try the input as given, then upper-cased.
	variants := []string{id}
	if up := strings.ToUpper(id); up != id {
		variants = append(variants, up)
	}
	for _, in := range variants {
		for _, cand := range []string{"vuln:" + in, "alias:" + in} {
			if v, err := c.resolveNodeID(ctx, cand); err != nil || v != nil {
				return v, err
			}
		}
	}
	// Fall back to source records by external id. No index covers external_id;
	// this is a scan over SourceRecord nodes (nodes_type).
	for _, in := range variants {
		recs, err := c.queryNodes(ctx, `SELECT id, type, props FROM nodes
			WHERE type='SourceRecord' AND json_extract(props,'$.external_id')=? ORDER BY id`, in)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			if v, err := c.followAlias(ctx, r.ID); err != nil || v != nil {
				return v, err
			}
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
}

// resolveNodeID resolves one node id; a nil node with nil error is "no match".
func (c *sqliteClient) resolveNodeID(ctx context.Context, id string) (*nodeRow, error) {
	n, err := c.node(ctx, id)
	if err != nil || n == nil {
		return nil, err
	}
	if n.Type == "Vulnerability" {
		return n, nil
	}
	return c.followAlias(ctx, n.ID)
}

func (c *sqliteClient) followAlias(ctx context.Context, srcID string) (*nodeRow, error) {
	vs, err := c.neighbors(ctx, srcID, "ALIAS_OF")
	if err != nil {
		return nil, err
	}
	for i := range vs {
		if vs[i].Type == "Vulnerability" {
			return &vs[i], nil
		}
	}
	return nil, nil
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func num(m map[string]any, k string) float64 {
	f, _ := m[k].(float64)
	return f
}

// GetVulnerability looks up a vulnerability by id, alias or prefixed node id.
func (c *sqliteClient) GetVulnerability(ctx context.Context, id string, opts ...Option) (*Vulnerability, error) {
	o := applyOptions(opts)
	if o.hasAsOf {
		return c.getVulnerabilityAsOf(ctx, id, o.asOf)
	}
	vn, err := c.resolveVulnerability(ctx, id)
	if err != nil {
		return nil, unavailable(err)
	}
	v, err := c.loadVulnerability(ctx, vn)
	if err != nil {
		return nil, unavailable(err)
	}
	return v, nil
}

func (c *sqliteClient) loadVulnerability(ctx context.Context, vn *nodeRow) (*Vulnerability, error) {
	p := vn.Props
	v := &Vulnerability{
		ID:         strings.TrimPrefix(vn.ID, "vuln:"),
		Summary:    str(p, "summary"),
		Published:  str(p, "published"),
		Modified:   str(p, "modified"),
		Withdrawn:  str(p, "withdrawn"),
		TrustState: str(p, "trust_state"),
		Aliases:    []string{}, Severities: []SeverityAssessment{}, Weaknesses: []string{}, Sources: []SourceRecordRef{},
	}
	if d, _ := p["discrepancy"].(bool); d {
		v.Discrepancy = &Discrepancy{Present: true}
	}

	// Aliases: identifiers of every node with ALIAS_OF -> vuln.
	al, err := c.queryNodes(ctx, `SELECT n.id, n.type, n.props FROM edges e JOIN nodes n ON n.id=e.src
		WHERE e.dst=? AND e.type='ALIAS_OF' ORDER BY n.id`, vn.ID)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{v.ID: true}
	for _, a := range al {
		ids := []string{str(a.Props, "external_id")}
		if l, ok := a.Props["identifiers"].([]any); ok {
			for _, x := range l {
				if s, ok := x.(string); ok {
					ids = append(ids, s)
				}
			}
		}
		for _, s := range ids {
			if s != "" && !seen[s] {
				seen[s] = true
				v.Aliases = append(v.Aliases, s)
			}
		}
	}
	sort.Strings(v.Aliases)

	sevs, err := c.neighbors(ctx, vn.ID, "HAS_ASSESSMENT")
	if err != nil {
		return nil, err
	}
	for _, s := range sevs {
		v.Severities = append(v.Severities, SeverityAssessment{
			ID: s.ID, Source: str(s.Props, "source"), RecordID: str(s.Props, "record_id"), Type: str(s.Props, "type"),
			Version: str(s.Props, "version"), Score: num(s.Props, "score"), Vector: str(s.Props, "vector"),
			Rating: str(s.Props, "rating"), Validation: str(s.Props, "validation"), Reason: str(s.Props, "reason"),
		})
	}

	ws, err := c.neighbors(ctx, vn.ID, "CLASSIFIED_AS")
	if err != nil {
		return nil, err
	}
	for _, w := range ws {
		if s := str(w.Props, "cwe_id"); s != "" {
			v.Weaknesses = append(v.Weaknesses, s)
		}
	}

	ks, err := c.neighbors(ctx, vn.ID, "LISTED_IN_KEV")
	if err != nil {
		return nil, err
	}
	if len(ks) > 0 {
		k := ks[0]
		v.KEV = &KEVEntry{CVE: str(k.Props, "cve"), DateAdded: str(k.Props, "date_added"),
			DueDate: str(k.Props, "due_date"), Ransomware: str(k.Props, "ransomware")}
	}

	es, err := c.neighbors(ctx, vn.ID, "HAS_EPSS")
	if err != nil {
		return nil, err
	}
	for _, e := range es {
		if cur, _ := e.Props["current"].(bool); !cur {
			continue
		}
		if v.EPSS == nil || str(e.Props, "date") > v.EPSS.Date {
			v.EPSS = &EPSSAssessment{CVE: str(e.Props, "cve"), Score: num(e.Props, "score"),
				Percentile: num(e.Props, "percentile"), Date: str(e.Props, "date")}
		}
	}

	srcs, err := c.neighbors(ctx, vn.ID, "HAS_SOURCE_RECORD")
	if err != nil {
		return nil, err
	}
	for _, s := range srcs {
		if str(s.Props, "kind") != "record" {
			continue
		}
		v.Sources = append(v.Sources, SourceRecordRef{ID: s.ID, Source: str(s.Props, "source"),
			ExternalID: str(s.Props, "external_id"), Modified: str(s.Props, "modified"), Withdrawn: str(s.Props, "withdrawn")})
	}
	return v, nil
}
