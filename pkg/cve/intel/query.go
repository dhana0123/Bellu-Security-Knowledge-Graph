package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// MaxDependencies is the largest batch AnalyzeDependencies accepts.
const MaxDependencies = 5000

// analyzeTimeout bounds one AnalyzeDependencies call.
const analyzeTimeout = 10 * time.Second

// OpenInstalled opens the graph of the snapshot installed under dataDir, i.e.
// <dataDir>/current/graph.db (current is a symlink to snapshots/<id>).
// It returns ErrNotInstalled when no snapshot is installed.
func OpenInstalled(dataDir string) (Client, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, fmt.Errorf("%w: empty data dir", ErrInvalidRequest)
	}
	p := filepath.Join(dataDir, "current", "graph.db")
	if _, err := os.Stat(p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s not found", ErrNotInstalled, p)
		}
		return nil, fmt.Errorf("%w: %v", ErrSourceUnavailable, err)
	}
	return Open(p)
}

// GetAttackPaths always returns ErrNotImplemented and never touches the database.
func (c *sqliteClient) GetAttackPaths(ctx context.Context, cveID string) ([]AttackPath, error) {
	return nil, ErrNotImplemented
}

// checkAsOf validates an as-of option for methods that do not support it in D1.
// A history-less graph yields ErrHistoryUnavailable; with history the method
// is not implemented (only GetVulnerability supports as-of in D1).
func (c *sqliteClient) checkAsOf(ctx context.Context, opts []Option) error {
	o := applyOptions(opts)
	if !o.hasAsOf {
		return nil
	}
	if err := validAsOf(o.asOf); err != nil {
		return err
	}
	if err := c.requireHistory(ctx); err != nil {
		return err
	}
	return fmt.Errorf("%w: as-of queries are only supported by GetVulnerability", ErrNotImplemented)
}

func validAsOf(t time.Time) error {
	if t.IsZero() {
		return fmt.Errorf("%w: zero time", ErrInvalidAsOf)
	}
	if t.After(time.Now()) {
		return fmt.Errorf("%w: %s is in the future", ErrInvalidAsOf, t.UTC().Format(time.RFC3339))
	}
	return nil
}

func (c *sqliteClient) requireHistory(ctx context.Context) error {
	var v string
	err := c.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='has_history'`).Scan(&v)
	if err != nil && !strings.Contains(err.Error(), "no rows") {
		return unavailable(err)
	}
	if err != nil || strings.TrimSpace(v) != "true" {
		return ErrHistoryUnavailable
	}
	return nil
}

// ---------------------------------------------------------------------------
// package matching

type affEntry struct {
	Source     string        `json:"source"`
	Scheme     string        `json:"scheme"`
	Ranges     []model.Range `json:"ranges"`
	Bounds     []model.Bound `json:"bounds"`
	Versions   []string      `json:"versions"`
	Introduced string        `json:"introduced"`
	Fixed      string        `json:"fixed"`
}

type affEdge struct {
	Entries []affEntry `json:"entries"`
	Status  string     `json:"status"`
}

func (e affEntry) affected() model.Affected {
	return model.Affected{Ranges: e.Ranges, Bounds: e.Bounds, Versions: e.Versions}
}

func (e affEntry) asRange() *AffectedRange {
	vs := e.Versions
	if vs == nil {
		vs = []string{}
	}
	return &AffectedRange{Source: e.Source, Scheme: e.Scheme, Introduced: e.Introduced, Fixed: e.Fixed, Versions: vs}
}

// GetPackageVulnerabilities returns the vulnerabilities whose affected entries
// match version of the package. The result is never nil without an error.
func (c *sqliteClient) GetPackageVulnerabilities(ctx context.Context, ecosystem, name, version string, opts ...Option) ([]PackageMatch, error) {
	if err := validateDep("", ecosystem, name, version); err != nil {
		return nil, err
	}
	if err := c.checkAsOf(ctx, opts); err != nil {
		return nil, err
	}
	out, err := c.matchPackage(ctx, ecosystem, name, version)
	if err != nil {
		return nil, unavailable(err)
	}
	return out, nil
}

func validateDep(prefix, ecosystem, name, version string) error {
	for _, f := range []struct{ n, v string }{{"ecosystem", ecosystem}, {"name", name}, {"version", version}} {
		if strings.TrimSpace(f.v) == "" {
			return fmt.Errorf("%w: %s%s must not be empty", ErrInvalidRequest, prefix, f.n)
		}
	}
	return nil
}

func (c *sqliteClient) matchPackage(ctx context.Context, ecosystem, name, version string) ([]PackageMatch, error) {
	pkgID := model.PackageID(ecosystem, name)
	rows, err := c.db.QueryContext(ctx, `SELECT e.props, n.id, n.props FROM edges e JOIN nodes n ON n.id=e.src
		WHERE e.dst=? AND e.type='AFFECTS' ORDER BY e.src`, pkgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PackageMatch{}
	for rows.Next() {
		var ep, vid, vp string
		if err := rows.Scan(&ep, &vid, &vp); err != nil {
			return nil, err
		}
		var edge affEdge
		if err := json.Unmarshal([]byte(ep), &edge); err != nil {
			return nil, fmt.Errorf("edge props of %s: %w", vid, err)
		}
		var vprops map[string]any
		if err := json.Unmarshal([]byte(vp), &vprops); err != nil {
			return nil, fmt.Errorf("node %s: %w", vid, err)
		}
		m := PackageMatch{
			Vulnerability: VulnerabilitySummary{ID: strings.TrimPrefix(vid, "vuln:"), Summary: str(vprops, "summary"), TrustState: str(vprops, "trust_state")},
			Level:         LevelAffectedPackage,
			TrustState:    edge.Status,
		}
		var matched, unknown bool
		for _, en := range edge.Entries {
			scheme := en.Scheme
			if scheme == "" {
				scheme = "generic"
			}
			r, _ := en.affected().MatchVersion(scheme, version)
			if r == model.Match {
				m.State, m.Range, m.FixedVersion = MatchAffected, en.asRange(), en.Fixed
				matched = true
				break
			}
			if r == model.Unknown {
				unknown = true
			}
		}
		switch {
		case matched:
		case unknown:
			m.State = MatchUnknown
		default:
			continue
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// products and patches

// GetAffectedProducts lists the packages and products a vulnerability affects.
func (c *sqliteClient) GetAffectedProducts(ctx context.Context, cveID string, opts ...Option) ([]AffectedProduct, error) {
	if err := c.checkAsOf(ctx, opts); err != nil {
		return nil, err
	}
	vn, err := c.resolveVulnerability(ctx, cveID)
	if err != nil {
		return nil, unavailable(err)
	}
	rows, err := c.db.QueryContext(ctx, `SELECT e.props, n.id, n.type, n.props FROM edges e JOIN nodes n ON n.id=e.dst
		WHERE e.src=? AND e.type='AFFECTS' ORDER BY n.id`, vn.ID)
	if err != nil {
		return nil, unavailable(err)
	}
	defer rows.Close()
	out := []AffectedProduct{}
	for rows.Next() {
		var ep, id, typ, np string
		if err := rows.Scan(&ep, &id, &typ, &np); err != nil {
			return nil, unavailable(err)
		}
		var e, n map[string]any
		if err := json.Unmarshal([]byte(ep), &e); err != nil {
			return nil, unavailable(err)
		}
		if err := json.Unmarshal([]byte(np), &n); err != nil {
			return nil, unavailable(err)
		}
		p := AffectedProduct{ID: id, Introduced: str(e, "introduced"), Fixed: str(e, "fixed"), Status: str(e, "status")}
		if typ == "Product" {
			p.Kind, p.Vendor, p.Name = "product", str(n, "vendor"), str(n, "product")
		} else {
			p.Kind, p.Ecosystem, p.Name = "package", str(n, "ecosystem"), str(n, "name")
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, unavailable(err)
	}
	return out, nil
}

// GetPatches lists the fix references of a vulnerability.
func (c *sqliteClient) GetPatches(ctx context.Context, cveID string, opts ...Option) ([]Patch, error) {
	if err := c.checkAsOf(ctx, opts); err != nil {
		return nil, err
	}
	vn, err := c.resolveVulnerability(ctx, cveID)
	if err != nil {
		return nil, unavailable(err)
	}
	ns, err := c.neighbors(ctx, vn.ID, "FIXED_BY")
	if err != nil {
		return nil, unavailable(err)
	}
	out := []Patch{}
	for _, n := range ns {
		out = append(out, Patch{ID: n.ID, URL: str(n.Props, "url"), Source: str(n.Props, "source"), FixedVersion: str(n.Props, "fixed_version")})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// batch

// AnalyzeDependencies matches each dependency; results follow input order.
// 1..MaxDependencies entries are accepted; any invalid entry fails the whole
// call with ErrInvalidRequest naming the index and field.
func (c *sqliteClient) AnalyzeDependencies(ctx context.Context, deps []Dependency) ([]DependencyResult, error) {
	if len(deps) == 0 {
		return nil, fmt.Errorf("%w: deps must contain at least 1 entry", ErrInvalidRequest)
	}
	if len(deps) > MaxDependencies {
		return nil, fmt.Errorf("%w: deps has %d entries, limit is %d", ErrInvalidRequest, len(deps), MaxDependencies)
	}
	for i, d := range deps {
		if err := validateDep(fmt.Sprintf("deps[%d].", i), d.Ecosystem, d.Name, d.Version); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, analyzeTimeout)
	defer cancel()
	out := make([]DependencyResult, len(deps))
	for i, d := range deps {
		ms, err := c.matchPackage(ctx, d.Ecosystem, d.Name, d.Version)
		if err != nil {
			return nil, unavailable(err)
		}
		out[i] = DependencyResult{Dependency: d, Vulnerabilities: ms}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// as-of

// getVulnerabilityAsOf rebuilds the source-record view of a vulnerability from
// the history table (latest version per record with recorded_at <= t).
// Aliases, severities, weaknesses, summary and dates come from those records.
// KEV and EPSS are not versioned in history and are left nil; the trust state
// and discrepancy flag are taken from the current graph.
func (c *sqliteClient) getVulnerabilityAsOf(ctx context.Context, id string, t time.Time) (*Vulnerability, error) {
	if err := validAsOf(t); err != nil {
		return nil, err
	}
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
	type visible struct {
		ref   SourceRecordRef
		rec   model.Record
		state string
	}
	var vis []visible
	for _, s := range cur.Sources {
		rows, err := c.db.QueryContext(ctx, `SELECT recorded_at, state, payload FROM history WHERE entity_id=? ORDER BY version`, s.ID)
		if err != nil {
			return nil, unavailable(err)
		}
		var best *visible
		for rows.Next() {
			var at, state, payload string
			if err := rows.Scan(&at, &state, &payload); err != nil {
				rows.Close()
				return nil, unavailable(err)
			}
			rt := model.ParseTime(at)
			if rt.IsZero() || rt.After(t) {
				continue
			}
			var rec model.Record
			if err := json.Unmarshal([]byte(payload), &rec); err != nil {
				rows.Close()
				return nil, unavailable(fmt.Errorf("history %s: %w", s.ID, err))
			}
			best = &visible{rec: rec, state: state}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, unavailable(err)
		}
		if best == nil {
			continue
		}
		best.ref = SourceRecordRef{ID: s.ID, Source: best.rec.Source, ExternalID: best.rec.ID}
		if !best.rec.Modified.IsZero() {
			best.ref.Modified = best.rec.Modified.UTC().Format(time.RFC3339)
		}
		if best.state == "withdrawn" || !best.rec.Withdrawn.IsZero() {
			best.state = "withdrawn"
			if !best.rec.Withdrawn.IsZero() {
				best.ref.Withdrawn = best.rec.Withdrawn.UTC().Format(time.RFC3339)
			}
		}
		vis = append(vis, *best)
	}
	if len(vis) == 0 {
		return nil, fmt.Errorf("%w: %s had no recorded source at %s", ErrNotFound, id, t.UTC().Format(time.RFC3339))
	}
	sort.Slice(vis, func(i, j int) bool { return vis[i].ref.ID < vis[j].ref.ID })
	v := &Vulnerability{
		ID: cur.ID, TrustState: cur.TrustState, Discrepancy: cur.Discrepancy,
		Aliases: []string{}, Severities: []SeverityAssessment{}, Weaknesses: []string{}, Sources: []SourceRecordRef{},
	}
	seen := map[string]bool{cur.ID: true}
	wk := map[string]bool{}
	allWithdrawn := true
	var latest time.Time
	for _, x := range vis {
		v.Sources = append(v.Sources, x.ref)
		if x.state != "withdrawn" {
			allWithdrawn = false
		}
		for _, a := range append([]string{x.rec.ID}, x.rec.Aliases...) {
			if a = model.NormID(a); a != "" && !seen[a] {
				seen[a] = true
				v.Aliases = append(v.Aliases, a)
			}
		}
		for _, w := range x.rec.Weaknesses {
			if !wk[w] {
				wk[w] = true
				v.Weaknesses = append(v.Weaknesses, w)
			}
		}
		for _, s := range x.rec.Severities {
			sa := SeverityAssessment{Source: s.Source, RecordID: x.rec.ID, Type: s.Type, Version: s.Version,
				Vector: s.Vector, Validation: s.Validation, Reason: s.Reason}
			if s.Score != nil {
				sa.Score = *s.Score
			}
			v.Severities = append(v.Severities, sa)
		}
		if x.state == "withdrawn" {
			continue
		}
		if x.rec.Summary != "" && !x.rec.Modified.Before(latest) {
			v.Summary = x.rec.Summary
		}
		if !x.rec.Modified.IsZero() && x.rec.Modified.After(latest) {
			latest = x.rec.Modified
		}
		if p := x.rec.Published; !p.IsZero() {
			if s := p.UTC().Format(time.RFC3339); v.Published == "" || s < v.Published {
				v.Published = s
			}
		}
	}
	if !latest.IsZero() {
		v.Modified = latest.UTC().Format(time.RFC3339)
	}
	if allWithdrawn {
		for _, x := range vis {
			if x.ref.Withdrawn > v.Withdrawn {
				v.Withdrawn = x.ref.Withdrawn
			}
		}
	}
	sort.Strings(v.Aliases)
	sort.Strings(v.Weaknesses)
	return v, nil
}
