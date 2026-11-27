package graph

// Projection building (requirement 9). Build reads only the canonical store and
// streams nodes and edges to two callbacks. It does not know about sinks;
// Projector.Run wires those on top.
//
// Decisions worth knowing:
//
//   - Withdrawn source records. A record whose latest stored state carries a
//     withdrawal time still yields a SourceRecord node (with a non-null
//     `withdrawn` property) and its HAS_SOURCE_RECORD / ALIAS_OF edges, but no
//     other fact is derived from it: no AFFECTS, Version, SeverityAssessment,
//     Weakness, Patch or Exploit. A vulnerability whose records are all
//     withdrawn is still emitted (core facts such as KEV and EPSS are keyed by
//     CVE, not by record) with a non-null `withdrawn` time.
//
//   - Enrichment lookup. KEV, EPSS, weakness, patch and exploit rows are looked
//     up under the canonical vulnerability id, every identifier resolved to the
//     vulnerability and every member record id, deduplicated. Identifiers that
//     are a different CVE are never used (a multi-CVE advisory is a member of
//     several vulnerabilities and must not leak one CVE's KEV into another).
//     Only linked KEV/EPSS rows are visible (Store.Enrichment). Weaknesses,
//     patches and exploits are additionally required to be present in an
//     active (non-withdrawn) member record.
//
//   - Ecosystem filter. With a non-empty Policy.Ecosystems it applies to the
//     Ecosystem level and to the empty (full vocabulary) level. Core ignores it
//     (no packages, all CVEs; design "Distribution levels") and Complete ignores
//     it by definition (R10.8). While it applies, a vulnerability is emitted
//     only if it affects at least one package of a selected ecosystem, only
//     packages of selected ecosystems are emitted, and products (which have no
//     ecosystem) and their vendors are excluded.
//
//   - ALIAS_OF. Every SourceRecord node (kind 'record' and kind 'alias') gets an
//     ALIAS_OF edge to each vulnerability it belongs to or resolves to, so every
//     identifier resolves with one node lookup and one edge lookup. Alias nodes
//     are created for the identifiers listed in vulnerability_identifier that
//     are not the id of a member record.
//
//   - Version nodes. Explicit versions, introduced / last_affected boundaries
//     (and NVD start/end-inclusive bounds) get a Version node and an
//     AFFECTS_VERSION edge. `fixed` / end-exclusive values and patch fixed
//     versions get a Version node, and FIXES_VERSION connects a Patch to the
//     fixed version of every target the patch source reports. The sentinel "0"
//     and GIT ranges are not versions. Version props do not depend on the
//     vulnerability so the shared node is identical whichever vulnerability
//     emits it first.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/canonical"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/trust"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/version"
)

// Stats counts what Build emitted.
type Stats struct {
	Vulnerabilities        int            // vulnerabilities emitted
	SkippedVulnerabilities int            // dropped by the ecosystem filter
	Nodes                  map[string]int // by node type
	Edges                  map[string]int // by edge type

	// Set by Projector.Run only.
	Mode       string `json:"mode,omitempty"`        // full, incremental or unchanged
	Changed    int    `json:"changed,omitempty"`     // vulnerabilities re-projected by an incremental run
	Watermark  int64  `json:"watermark,omitempty"`   // canonical change feed position the graph reflects
	FullReason string `json:"full_reason,omitempty"` // why an incremental request did a full build
}

const buildPageSize = 500

// Build streams the projection of the canonical store selected by policy. Shared nodes are
// deduplicated with an in-memory set, so memory grows with the number of distinct shared nodes;
// Projector.Run uses BuildWith and a disk-backed set instead.
func Build(ctx context.Context, store *canonical.Store, policy Policy, emitNode func(Node) error, emitEdge func(Edge) error) (Stats, error) {
	return BuildWith(ctx, store, policy, BuildOptions{}, emitNode, emitEdge)
}

// BuildOptions tunes BuildWith.
type BuildOptions struct {
	// Seen decides which shared node and edge ids were already emitted. Nil keeps them in memory.
	Seen IDTracker
	// Owner, when set, is called for every node ('n') and edge ('e') a vulnerability produces,
	// including shared ones another vulnerability already emitted. Incremental projection uses
	// it to learn which vulnerabilities depend on which graph elements.
	Owner func(vulnID string, kind byte, id string) error
}

// BuildWith is Build with options.
func BuildWith(ctx context.Context, store *canonical.Store, policy Policy, opts BuildOptions, emitNode func(Node) error, emitEdge func(Edge) error) (Stats, error) {
	st := Stats{Nodes: map[string]int{}, Edges: map[string]int{}}
	b, err := newBuilder(store, policy, opts, emitNode, emitEdge, &st)
	if err != nil {
		return st, err
	}
	last := ""
	for {
		ids, err := pageVulnerabilityIDs(ctx, store.DB, last, buildPageSize)
		if err != nil {
			return st, err
		}
		if len(ids) == 0 {
			break
		}
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return st, err
			}
			if err := b.vulnerability(ctx, id); err != nil {
				return st, fmt.Errorf("graph: vulnerability %s: %w", id, err)
			}
		}
		last = ids[len(ids)-1]
	}
	return st, nil
}

func newBuilder(store *canonical.Store, policy Policy, opts BuildOptions, emitNode func(Node) error, emitEdge func(Edge) error, st *Stats) (*builder, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if store == nil || store.DB == nil {
		return nil, fmt.Errorf("graph: nil canonical store")
	}
	seen := opts.Seen
	if seen == nil {
		seen = NewMemTracker()
	}
	b := &builder{
		store: store, policy: policy, emitNode: emitNode, emitEdge: emitEdge,
		seen: seen, owner: opts.Owner, stats: st,
		filter: policy.filterActive(), eco: map[string]bool{},
	}
	for _, e := range policy.Ecosystems {
		b.eco[strings.ToLower(strings.TrimSpace(e))] = true
	}
	return b, nil
}

// filterActive reports whether the ecosystem selection restricts the output.
func (p Policy) filterActive() bool {
	return len(p.Ecosystems) > 0 && p.Level != LevelCore && p.Level != LevelComplete
}

func pageVulnerabilityIDs(ctx context.Context, db *sql.DB, after string, n int) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT id FROM vulnerability WHERE id > ? ORDER BY id LIMIT ?`, after, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

type builder struct {
	store    *canonical.Store
	policy   Policy
	emitNode func(Node) error
	emitEdge func(Edge) error
	seen     IDTracker // shared node and edge ids already emitted
	owner    func(vulnID string, kind byte, id string) error
	stats    *Stats
	filter   bool
	eco      map[string]bool
}

// buf collects one vulnerability's output so the ecosystem filter can drop it whole.
type buf struct {
	nodes []Node
	edges []Edge
}

func (b *builder) node(w *buf, n Node) {
	if b.policy.AllowsNode(n.Type) {
		w.nodes = append(w.nodes, n)
	}
}

// edge keeps the edge only when its type and both endpoint node types are in the level.
func (b *builder) edge(w *buf, typ, src, dst string, props map[string]any) {
	if !b.policy.AllowsEdge(typ) {
		return
	}
	w.edges = append(w.edges, NewEdge(typ, src, dst, props))
}

// privateNode reports node types whose id contains the vulnerability id, so no other
// vulnerability can emit them. Every other node type may be shared and goes through the seen set.
func privateNode(t string) bool {
	return t == NodeVulnerability || t == NodePatch || t == NodeExploit
}

// privateEdge reports edge types with the vulnerability node (or a patch of it) as an endpoint.
// BELONGS_TO_VENDOR connects two shared nodes and is the only shared edge type.
func privateEdge(t string) bool { return t != EdgeBelongsToVendor }

// flush emits the vulnerability's nodes and edges. An id repeated inside one vulnerability is
// emitted once. A shared id another vulnerability already emitted is skipped, so the first
// vulnerability in id order owns its properties.
func (b *builder) flush(vid string, w *buf) error {
	localN := make(map[string]struct{}, len(w.nodes))
	for _, n := range w.nodes {
		if b.owner != nil {
			if err := b.owner(vid, 'n', n.ID); err != nil {
				return err
			}
		}
		if _, ok := localN[n.ID]; ok {
			continue
		}
		localN[n.ID] = struct{}{}
		if !privateNode(n.Type) {
			first, err := b.seen.First('n', n.ID)
			if err != nil {
				return err
			}
			if !first {
				continue
			}
		}
		if n.Props == nil {
			n.Props = map[string]any{}
		}
		if err := b.emitNode(n); err != nil {
			return err
		}
		b.stats.Nodes[n.Type]++
	}
	localE := make(map[string]struct{}, len(w.edges))
	for _, e := range w.edges {
		if b.owner != nil {
			if err := b.owner(vid, 'e', e.ID); err != nil {
				return err
			}
		}
		if _, ok := localE[e.ID]; ok {
			continue
		}
		localE[e.ID] = struct{}{}
		if !privateEdge(e.Type) {
			first, err := b.seen.First('e', e.ID)
			if err != nil {
				return err
			}
			if !first {
				continue
			}
		}
		if e.Props == nil {
			e.Props = map[string]any{}
		}
		if err := b.emitEdge(e); err != nil {
			return err
		}
		b.stats.Edges[e.Type]++
	}
	return nil
}

// ---------------------------------------------------------------------------

type affEntry struct {
	source   string
	scheme   string
	ranges   []model.Range
	bounds   []model.Bound
	versions []string
	rangeKey map[string]bool
}

type target struct {
	id      string
	isPkg   bool
	node    Node
	vendor  *Node
	entries map[string]*affEntry
	// version values -> true when the vulnerability affects it (false: fixed only)
	versions map[string]bool
}

func (b *builder) selected(eco string) bool { return b.eco[strings.ToLower(strings.TrimSpace(eco))] }

func (b *builder) vulnerability(ctx context.Context, vid string) error {
	recs, err := b.store.SourceRecords(ctx, vid)
	if err != nil {
		return err
	}
	idents, err := b.identifiers(ctx, vid)
	if err != nil {
		return err
	}
	var active []model.Record
	activeKey := map[string]bool{}
	for _, r := range recs {
		if r.Withdrawn.IsZero() {
			active = append(active, r)
			activeKey[r.Source+"\x00"+r.ID] = true
		}
	}

	targets := b.targets(active)
	if b.filter {
		ok := false
		for _, t := range targets {
			if t.isPkg {
				ok = true
				break
			}
		}
		if !ok {
			b.stats.SkippedVulnerabilities++
			return nil
		}
	}

	w := &buf{}
	vnode := vulnerabilityID(vid)

	// Severity assessments of active records.
	sevs, err := b.severities(ctx, vid, activeKey)
	if err != nil {
		return err
	}
	report := canonical.BuildSeverityReport(entriesOf(sevs))

	var ev []trust.Evidence
	srcSeen := map[string]bool{}
	for _, r := range active {
		if !srcSeen[r.Source] {
			srcSeen[r.Source] = true
			ev = append(ev, trust.Evidence{Source: r.Source, Direct: true})
		}
	}
	var trustState any
	if len(ev) > 0 {
		trustState = string(trust.Classify(ev))
	}
	b.node(w, Node{ID: vnode, Type: NodeVulnerability, Props: vulnerabilityProps(vid, recs, active, trustState, report.Discrepancy)})

	// SourceRecord nodes and aliases.
	recIDs := map[string]bool{}
	for _, r := range recs {
		recIDs[r.ID] = true
		sid := SourceRecordID(r.Source, r.ID)
		b.node(w, Node{ID: sid, Type: NodeSourceRecord, Props: map[string]any{
			"source": r.Source, "external_id": r.ID, "kind": "record",
			"identifiers": identifiersOf(r), "modified": tsOrNil(r.Modified), "withdrawn": tsOrNil(r.Withdrawn),
		}})
		b.edge(w, EdgeHasSourceRecord, vnode, sid, nil)
		b.edge(w, EdgeAliasOf, sid, vnode, nil)
	}
	for _, id := range idents {
		if recIDs[id] {
			continue
		}
		aid := AliasID(id)
		b.node(w, Node{ID: aid, Type: NodeSourceRecord, Props: map[string]any{
			"source": nil, "external_id": id, "kind": "alias",
			"identifiers": []any{id}, "modified": nil, "withdrawn": nil,
		}})
		b.edge(w, EdgeAliasOf, aid, vnode, nil)
	}

	// Severity.
	for _, s := range sevs {
		sid := SeverityID(s.Source, s.RecordID, s.Type, s.Vector)
		b.node(w, Node{ID: sid, Type: NodeSeverityAssessment, Props: map[string]any{
			"source": s.Source, "record_id": s.RecordID, "type": s.Type, "version": nilIfEmpty(s.Version),
			"score": s.Score, "vector": s.Vector, "rating": nilIfEmpty(s.Rating),
			"validation": s.Validation, "reason": nilIfEmpty(s.Reason),
			"published_at": s.PublishedAt, "ingested_at": s.IngestedAt,
		}})
		b.edge(w, EdgeHasAssessment, vnode, sid, nil)
	}

	// Enrichment.
	keys := enrichmentKeys(vid, idents, recs)
	if err := b.enrichment(ctx, w, vid, vnode, keys, active, targets); err != nil {
		return err
	}

	// Targets, versions.
	b.targetFacts(w, vnode, targets)

	if err := b.flush(vid, w); err != nil {
		return err
	}
	b.stats.Vulnerabilities++
	return nil
}

func vulnerabilityID(id string) string { return VulnerabilityID(id) }

func (b *builder) identifiers(ctx context.Context, vid string) ([]string, error) {
	rows, err := b.store.QueryCached(ctx, `SELECT value FROM vulnerability_identifier WHERE vulnerability_id=? ORDER BY value`, vid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func identifiersOf(r model.Record) []any {
	seen := map[string]bool{}
	var ids []string
	for _, x := range append([]string{r.ID}, r.Aliases...) {
		if x != "" && !seen[x] {
			seen[x] = true
			ids = append(ids, x)
		}
	}
	sort.Strings(ids)
	out := make([]any, len(ids))
	for i, x := range ids {
		out[i] = x
	}
	return out
}

func tsOrNil(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func vulnerabilityProps(vid string, all, active []model.Record, trustState any, discrepancy bool) map[string]any {
	src := active
	if len(src) == 0 {
		src = all
	}
	summary := ""
	var published, modified time.Time
	for _, r := range src {
		if summary == "" {
			summary = r.Summary
		}
		if !r.Published.IsZero() && (published.IsZero() || r.Published.Before(published)) {
			published = r.Published
		}
	}
	var withdrawn time.Time
	for _, r := range all {
		if r.Modified.After(modified) {
			modified = r.Modified
		}
	}
	if len(active) == 0 && len(all) > 0 {
		for _, r := range all {
			if r.Withdrawn.After(withdrawn) {
				withdrawn = r.Withdrawn
			}
		}
	}
	return map[string]any{
		"id": vid, "summary": summary, "published": tsOrNil(published), "modified": tsOrNil(modified),
		"withdrawn": tsOrNil(withdrawn), "trust_state": trustState, "discrepancy": discrepancy,
	}
}

// ---------------------------------------------------------------------------
// severity

type sevRow struct {
	canonical.SeverityEntry
	PublishedAt any
	IngestedAt  any
}

func entriesOf(rows []sevRow) []canonical.SeverityEntry {
	out := make([]canonical.SeverityEntry, len(rows))
	for i, r := range rows {
		out[i] = r.SeverityEntry
	}
	return out
}

func (b *builder) severities(ctx context.Context, vid string, active map[string]bool) ([]sevRow, error) {
	rows, err := b.store.QueryCached(ctx, `SELECT sa.source,sa.record_id,sa.type,sa.vector,COALESCE(sa.version,''),sa.score,
COALESCE(sa.rating,''),sa.validation,COALESCE(sa.reason,''),sa.published_at,sa.ingested_at
FROM severity_assessment sa JOIN record_vulnerability rv ON rv.source=sa.source AND rv.external_id=sa.record_id
WHERE rv.vulnerability_id=? ORDER BY sa.source,sa.record_id,sa.type,sa.vector`, vid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sevRow
	for rows.Next() {
		var e sevRow
		var sc sql.NullFloat64
		var pub, ing sql.NullString
		if err := rows.Scan(&e.Source, &e.RecordID, &e.Type, &e.Vector, &e.Version, &sc, &e.Rating, &e.Validation, &e.Reason, &pub, &ing); err != nil {
			return nil, err
		}
		if !active[e.Source+"\x00"+e.RecordID] {
			continue
		}
		if sc.Valid {
			v := sc.Float64
			e.Score = &v
		}
		if pub.Valid {
			e.PublishedAt = pub.String
		}
		if ing.Valid {
			e.IngestedAt = ing.String
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// enrichment

func enrichmentKeys(vid string, idents []string, recs []model.Record) []string {
	seen := map[string]bool{}
	var keys []string
	add := func(k string) {
		k = strings.TrimSpace(k)
		if k == "" || seen[k] {
			return
		}
		// A different CVE belongs to a different vulnerability.
		if model.IsCVE(k) && k != vid {
			return
		}
		seen[k] = true
		keys = append(keys, k)
	}
	add(vid)
	for _, x := range idents {
		add(x)
	}
	for _, r := range recs {
		add(r.ID)
	}
	sort.Strings(keys)
	return keys
}

func (b *builder) enrichment(ctx context.Context, w *buf, vid, vnode string, keys []string, active []model.Record, targets []*target) error {
	// What the active records themselves carry.
	actCWE := map[string]bool{}
	actPatch := map[[2]string]bool{}
	actExploit := map[[2]string]bool{}
	for _, r := range active {
		for _, c := range r.Weaknesses {
			actCWE[strings.TrimSpace(c)] = true
		}
		for _, p := range r.Patches() {
			actPatch[[2]string{p.URL, p.Source}] = true
		}
		for _, x := range r.Exploits() {
			actExploit[[2]string{x.URL, x.Source}] = true
		}
	}
	kevs := map[string]*model.KEV{}
	epss := map[string]*model.EPSS{}
	cwes := map[string]bool{}
	patches := map[[2]string]model.Patch{}
	exploits := map[[2]string]model.Exploit{}
	views, err := b.store.EnrichmentMany(ctx, keys)
	if err != nil {
		return err
	}
	for _, k := range keys {
		v := views[k]
		if v == nil {
			continue
		}
		if v.KEV != nil {
			kevs[v.KEV.CVE] = v.KEV
		}
		if v.EPSS != nil {
			epss[EPSSID(v.EPSS.CVE, v.EPSS.Date)] = v.EPSS
		}
		for _, c := range v.Weaknesses {
			if actCWE[c] {
				cwes[c] = true
			}
		}
		for _, p := range v.Patches {
			if actPatch[[2]string{p.URL, p.Source}] {
				patches[[2]string{p.URL, p.Source}] = mergePatch(patches[[2]string{p.URL, p.Source}], p)
			}
		}
		for _, x := range v.Exploits {
			if actExploit[[2]string{x.URL, x.Source}] {
				exploits[[2]string{x.URL, x.Source}] = x
			}
		}
	}
	for _, c := range sortedKeys(cwes) {
		wid := WeaknessID(strings.TrimPrefix(strings.ToUpper(c), "CWE-"))
		b.node(w, Node{ID: wid, Type: NodeWeakness, Props: map[string]any{"cwe_id": c}})
		b.edge(w, EdgeClassifiedAs, vnode, wid, nil)
	}
	for _, cve := range sortedKeys(kevs) {
		k := kevs[cve]
		kid := KEVID(k.CVE)
		b.node(w, Node{ID: kid, Type: NodeKEVEntry, Props: map[string]any{
			"cve": k.CVE, "date_added": nilIfEmpty(k.DateAdded), "due_date": nilIfEmpty(k.DueDate), "ransomware": nilIfEmpty(k.Ransomware),
		}})
		b.edge(w, EdgeListedInKEV, vnode, kid, nil)
	}
	for _, id := range sortedKeys(epss) {
		e := epss[id]
		b.node(w, Node{ID: id, Type: NodeEPSSAssessment, Props: map[string]any{
			"cve": e.CVE, "score": e.Score, "percentile": e.Percentile, "date": e.Date, "current": true,
		}})
		b.edge(w, EdgeHasEPSS, vnode, id, nil)
	}
	for _, k := range sortedPairs(patches) {
		p := patches[k]
		pid := PatchID(vid, p.URL, p.Source)
		b.node(w, Node{ID: pid, Type: NodePatch, Props: map[string]any{
			"url": p.URL, "source": p.Source, "fixed_version": nilIfEmpty(p.FixedVersion),
		}})
		b.edge(w, EdgeFixedBy, vnode, pid, nil)
		if p.FixedVersion == "" || !validVersion(p.FixedVersion) {
			continue
		}
		for _, t := range targets {
			if _, ok := t.entries[p.Source]; !ok {
				continue
			}
			vi := VersionID(t.entries[p.Source].scheme, t.id, p.FixedVersion)
			b.versionNode(w, t, t.entries[p.Source].scheme, p.FixedVersion)
			b.edge(w, EdgeFixesVersion, pid, vi, nil)
		}
	}
	for _, k := range sortedPairs(exploits) {
		x := exploits[k]
		xid := ExploitID(vid, x.URL, x.Source)
		b.node(w, Node{ID: xid, Type: NodeExploit, Props: map[string]any{"url": x.URL, "source": x.Source}})
		b.edge(w, EdgeHasExploit, vnode, xid, nil)
	}
	return nil
}

func mergePatch(old, p model.Patch) model.Patch {
	if old.FixedVersion != "" && p.FixedVersion == "" {
		p.FixedVersion = old.FixedVersion
	}
	return p
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedPairs[V any](m map[[2]string]V) [][2]string {
	out := make([][2]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}

// ---------------------------------------------------------------------------
// packages, products, versions, AFFECTS

func validVersion(v string) bool {
	return v != "" && v != "0" && len(v) <= version.MaxVersionLen
}

func (b *builder) targets(active []model.Record) []*target {
	byID := map[string]*target{}
	for _, r := range active {
		for _, a := range r.Affected {
			name := strings.TrimSpace(a.Name)
			if name == "" {
				continue
			}
			isProduct := a.Kind == "product"
			var id, scheme string
			var mk func() *target
			if isProduct {
				if !b.policy.AllowsNode(NodeProduct) || b.filter {
					continue
				}
				id, scheme = ProductID(a.Vendor, name), "generic"
				mk = func() *target {
					vendor := strings.ToLower(strings.TrimSpace(a.Vendor))
					t := &target{id: id, node: Node{ID: id, Type: NodeProduct, Props: map[string]any{
						"vendor": vendor, "product": strings.ToLower(name),
					}}}
					if vendor != "" {
						t.vendor = &Node{ID: VendorID(vendor), Type: NodeVendor, Props: map[string]any{"name": vendor}}
					}
					return t
				}
			} else {
				if !b.policy.AllowsNode(NodePackage) {
					continue
				}
				if b.filter && !b.selected(a.Ecosystem) {
					continue
				}
				id = PackageID(a.Ecosystem, name)
				if scheme = version.SchemeFor(a.Ecosystem); scheme == "" {
					scheme = "generic"
				}
				mk = func() *target {
					return &target{id: id, isPkg: true, node: Node{ID: id, Type: NodePackage, Props: map[string]any{
						"ecosystem": a.Ecosystem, "name": name, "mapped": !a.Unmapped,
					}}}
				}
			}
			t := byID[id]
			if t == nil {
				t = mk()
				t.entries = map[string]*affEntry{}
				t.versions = map[string]bool{}
				byID[id] = t
			}
			e := t.entries[r.Source]
			if e == nil {
				e = &affEntry{source: r.Source, scheme: scheme, rangeKey: map[string]bool{}}
				t.entries[r.Source] = e
			}
			for _, rg := range a.Ranges {
				k := jsonString(rg)
				if !e.rangeKey[k] {
					e.rangeKey[k] = true
					e.ranges = append(e.ranges, rg)
				}
				if strings.EqualFold(rg.Type, "GIT") {
					continue
				}
				for _, ev := range rg.Events {
					if validVersion(ev.Introduced) {
						t.versions[ev.Introduced] = true
					}
					if validVersion(ev.LastAffected) {
						t.versions[ev.LastAffected] = true
					}
					if validVersion(ev.Fixed) {
						if _, ok := t.versions[ev.Fixed]; !ok {
							t.versions[ev.Fixed] = false
						}
					}
				}
			}
			for _, bd := range a.Bounds {
				k := "b" + jsonString(bd)
				if !e.rangeKey[k] {
					e.rangeKey[k] = true
					e.bounds = append(e.bounds, bd)
				}
				for _, v := range []string{bd.StartIncl, bd.StartExcl, bd.EndIncl} {
					if validVersion(v) {
						t.versions[v] = true
					}
				}
				if validVersion(bd.EndExcl) {
					if _, ok := t.versions[bd.EndExcl]; !ok {
						t.versions[bd.EndExcl] = false
					}
				}
			}
			for _, v := range a.Versions {
				k := "v" + v
				if !e.rangeKey[k] {
					e.rangeKey[k] = true
					e.versions = append(e.versions, v)
				}
				if validVersion(v) {
					t.versions[v] = true
				}
			}
		}
	}
	ids := sortedKeys(byID)
	out := make([]*target, 0, len(ids))
	for _, id := range ids {
		out = append(out, byID[id])
	}
	return out
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// generic converts v to plain JSON values (maps, slices, strings) so props
// compare and hash identically in every sink.
func generic(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

func (b *builder) versionNode(w *buf, t *target, scheme, v string) {
	b.node(w, Node{ID: VersionID(scheme, t.id, v), Type: NodeVersion, Props: map[string]any{
		"scheme": scheme, "version": v, "target": t.id,
	}})
}

func (e *affEntry) introduced() any {
	for _, rg := range e.ranges {
		if strings.EqualFold(rg.Type, "GIT") {
			continue
		}
		for _, ev := range rg.Events {
			if ev.Introduced != "" {
				return ev.Introduced
			}
		}
	}
	for _, bd := range e.bounds {
		if bd.StartIncl != "" {
			return bd.StartIncl
		}
		if bd.StartExcl != "" {
			return bd.StartExcl
		}
	}
	return nil
}

func (e *affEntry) fixed() any {
	for _, rg := range e.ranges {
		if strings.EqualFold(rg.Type, "GIT") {
			continue
		}
		for _, ev := range rg.Events {
			if ev.Fixed != "" {
				return ev.Fixed
			}
		}
	}
	for _, bd := range e.bounds {
		if bd.EndExcl != "" {
			return bd.EndExcl
		}
	}
	return nil
}

func (e *affEntry) props() map[string]any {
	rg, bd, vs := []any{}, []any{}, []any{}
	for _, r := range e.ranges {
		rg = append(rg, generic(r))
	}
	for _, x := range e.bounds {
		bd = append(bd, generic(x))
	}
	for _, v := range e.versions {
		vs = append(vs, v)
	}
	return map[string]any{
		"source": e.source, "scheme": e.scheme, "ranges": rg, "bounds": bd, "versions": vs,
		"introduced": e.introduced(), "fixed": e.fixed(),
	}
}

func (b *builder) targetFacts(w *buf, vnode string, targets []*target) {
	for _, t := range targets {
		b.node(w, t.node)
		if t.vendor != nil {
			b.node(w, *t.vendor)
			b.edge(w, EdgeBelongsToVendor, t.id, t.vendor.ID, nil)
		}
		sources := sortedKeys(t.entries)
		var ev []trust.Evidence
		entries := make([]any, 0, len(sources))
		for _, s := range sources {
			entries = append(entries, t.entries[s].props())
			ev = append(ev, trust.Evidence{Source: s, Direct: true})
		}
		status := string(trust.Classify(ev))
		first := t.entries[sources[0]]
		srcList := make([]any, len(sources))
		for i, s := range sources {
			srcList[i] = s
		}
		b.edge(w, EdgeAffects, vnode, t.id, map[string]any{
			"entries": entries, "sources": srcList, "status": status,
			"introduced": first.introduced(), "fixed": first.fixed(), "scheme": first.scheme, "source": first.source,
		})
		scheme := first.scheme
		for _, v := range sortedKeys(t.versions) {
			vid := VersionID(scheme, t.id, v)
			b.versionNode(w, t, scheme, v)
			if t.versions[v] {
				b.edge(w, EdgeAffectsVersion, vnode, vid, nil)
			}
		}
	}
}
