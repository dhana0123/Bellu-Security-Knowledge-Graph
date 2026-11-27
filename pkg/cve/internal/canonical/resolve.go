package canonical

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// Resolution rule names stored in entity_resolution.method.
const (
	RuleExactIdentifier     = "exact-identifier"
	RuleMultiCVE            = "multi-cve"
	RuleIdentifierCollision = "identifier-collision"
)

// Resolve defaults.
const (
	defaultBatchRows = 20000 // desired rows per write transaction
	inChunk          = 400   // bind variables per IN (...) query
	fullDirtyShare   = 4     // dirty*fullDirtyShare >= total records -> full pass
)

// ResolveOptions configures Resolve.
//
// Full forces a pass over every record; otherwise Resolve re-resolves only the identifier
// components that contain a record changed since the last run (the result equals a full pass).
// When Fuzzy is set, token-set Jaccard similarity over summaries is computed for records in
// different groups that share a package name; pairs scoring at least FuzzyThreshold (default 0.8
// when not in (0,1]) are written to candidate_pair only. Fuzzy implies a full pass and is
// bounded by blocking (see fuzzyCandidates). BatchRows bounds the rows written per transaction.
type ResolveOptions struct {
	Fuzzy          bool
	FuzzyThreshold float64
	Full           bool
	BatchRows      int
}

// ResolveReport summarizes one Resolve run. Groups, Memberships and Collisions are totals in the
// store after the run; NewDecisions and LinkedEnrichment count what this run changed.
type ResolveReport struct {
	Groups           int    `json:"groups"`
	Memberships      int    `json:"memberships"`
	NewDecisions     int    `json:"new_decisions"`
	Collisions       int    `json:"collisions"`
	LinkedEnrichment int    `json:"linked_enrichment"`
	Mode             string `json:"mode"`          // "full" or "incremental"
	DirtyRecords     int    `json:"dirty_records"` // records marked changed when the run started
	RecordsResolved  int    `json:"records_resolved"`
	Components       int    `json:"components"` // components written in this run
	// FuzzyComparisons is the number of record pairs scored by the fuzzy pass (0 without Fuzzy).
	FuzzyComparisons int `json:"fuzzy_comparisons,omitempty"`
}

// ---- compact in-memory graph ----

// rgraph is the compact identifier graph of the records being resolved. Strings are interned
// once; records hold int32 offsets into one flat identifier slice. No JSON payload is kept.
type rgraph struct {
	idx   map[string]int32
	names []string
	isCVE []bool

	srcIdx map[string]int32
	srcs   []string

	recSrc []int32
	recExt []int32 // interned external_id (raw, as stored)
	recOff []int32 // len = records+1
	flat   []int32 // identifiers per record, sorted by string after finish()
	order  []int32 // record positions sorted by (source, external_id)
}

func newRGraph() *rgraph {
	return &rgraph{idx: map[string]int32{}, srcIdx: map[string]int32{}, recOff: []int32{0}}
}

func (g *rgraph) intern(s string) int32 {
	if i, ok := g.idx[s]; ok {
		return i
	}
	i := int32(len(g.names))
	g.idx[s] = i
	g.names = append(g.names, s)
	g.isCVE = append(g.isCVE, model.IsCVE(s))
	return i
}

func (g *rgraph) beginRecord(source, ext string) {
	si, ok := g.srcIdx[source]
	if !ok {
		si = int32(len(g.srcs))
		g.srcIdx[source] = si
		g.srcs = append(g.srcs, source)
	}
	g.recSrc = append(g.recSrc, si)
	g.recExt = append(g.recExt, g.intern(ext))
}

func (g *rgraph) addIdent(v string) { g.flat = append(g.flat, g.intern(v)) }

func (g *rgraph) endRecord() { g.recOff = append(g.recOff, int32(len(g.flat))) }

func (g *rgraph) records() int { return len(g.recSrc) }

func (g *rgraph) recIDs(r int32) []int32 { return g.flat[g.recOff[r]:g.recOff[r+1]] }

func (g *rgraph) recKey(r int32) string {
	return recordKey(g.srcs[g.recSrc[r]], g.names[g.recExt[r]])
}

// finish sorts identifiers within each record and records by (source, external_id), both
// byte-wise and independent of database collation.
func (g *rgraph) finish() {
	for r := int32(0); r < int32(g.records()); r++ {
		ids := g.recIDs(r)
		slices.SortFunc(ids, func(a, b int32) int { return strings.Compare(g.names[a], g.names[b]) })
	}
	g.order = make([]int32, g.records())
	for i := range g.order {
		g.order[i] = int32(i)
	}
	slices.SortFunc(g.order, func(a, b int32) int {
		if c := strings.Compare(g.srcs[g.recSrc[a]], g.srcs[g.recSrc[b]]); c != 0 {
			return c
		}
		return strings.Compare(g.names[g.recExt[a]], g.names[g.recExt[b]])
	})
}

// ---- guarded union-find over interned ids ----

type member struct {
	comp, rec, cve int32 // cve >= 0 for multi-CVE attachments
}

type collisionKey [2]int32 // CVE ids ordered by string

type solved struct {
	g        *rgraph
	inV      []bool  // vertex of the graph (identifiers that become vulnerability_identifier rows)
	compOf   []int32 // vertex -> component index, -1 if not a vertex
	canon    []int32 // component -> canonical vertex
	vstart   []int32 // component -> start in verts (len comps+1)
	verts    []int32 // vertices grouped by component
	mstart   []int32 // component -> start in members (len comps+1)
	members  []member
	collRecs map[collisionKey][]int32
	collBy   [][]collisionKey // component of the smaller CVE -> collisions
}

func (g *rgraph) solve() *solved {
	n := len(g.names)
	parent := make([]int32, n)
	size := make([]int32, n)
	cveOf := make([]int32, n)
	for i := range parent {
		parent[i] = int32(i)
		size[i] = 1
		cveOf[i] = -1
		if g.isCVE[i] {
			cveOf[i] = int32(i)
		}
	}
	find := func(x int32) int32 {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	inV := make([]bool, n)
	collRecs := map[collisionKey][]int32{}

	cvesOf := func(ids []int32, buf []int32) []int32 {
		buf = buf[:0]
		for _, x := range ids {
			if g.isCVE[x] {
				buf = append(buf, x)
			}
		}
		return buf
	}
	var cbuf []int32
	for _, r := range g.order {
		ids := g.recIDs(r)
		if len(ids) == 0 {
			continue
		}
		cbuf = cvesOf(ids, cbuf)
		if len(cbuf) >= 2 {
			for _, c := range cbuf {
				inV[c] = true
			}
			continue
		}
		anchor := ids[0]
		if len(cbuf) == 1 {
			anchor = cbuf[0]
		}
		for _, x := range ids {
			inV[x] = true
		}
		for _, x := range ids {
			if x == anchor {
				continue
			}
			ra, rb := find(anchor), find(x)
			if ra == rb {
				continue
			}
			ca, cb := cveOf[ra], cveOf[rb]
			if ca >= 0 && cb >= 0 && ca != cb {
				if g.names[cb] < g.names[ca] {
					ca, cb = cb, ca
				}
				k := collisionKey{ca, cb}
				if l := collRecs[k]; len(l) == 0 || l[len(l)-1] != r {
					collRecs[k] = append(collRecs[k], r)
				}
				continue
			}
			if size[ra] < size[rb] {
				ra, rb = rb, ra
			}
			parent[rb] = ra
			size[ra] += size[rb]
			if cveOf[ra] < 0 {
				cveOf[ra] = cveOf[rb]
			}
		}
	}

	// Canonical id per root: the CVE id, else the smallest identifier (string order).
	smallest := make([]int32, n)
	for i := range smallest {
		smallest[i] = -1
	}
	var roots []int32
	for i := int32(0); i < int32(n); i++ {
		if !inV[i] {
			continue
		}
		r := find(i)
		if smallest[r] < 0 {
			roots = append(roots, r)
			smallest[r] = i
		} else if g.names[i] < g.names[smallest[r]] {
			smallest[r] = i
		}
	}
	canonOfRoot := func(r int32) int32 {
		if c := cveOf[r]; c >= 0 {
			return c
		}
		return smallest[r]
	}
	slices.SortFunc(roots, func(a, b int32) int { return strings.Compare(g.names[canonOfRoot(a)], g.names[canonOfRoot(b)]) })

	sv := &solved{g: g, inV: inV, compOf: make([]int32, n), collRecs: collRecs}
	for i := range sv.compOf {
		sv.compOf[i] = -1
	}
	rootComp := make(map[int32]int32, len(roots))
	for ci, r := range roots {
		rootComp[r] = int32(ci)
		sv.canon = append(sv.canon, canonOfRoot(r))
	}
	counts := make([]int32, len(roots)+1)
	for i := int32(0); i < int32(n); i++ {
		if inV[i] {
			c := rootComp[find(i)]
			sv.compOf[i] = c
			counts[c+1]++
		}
	}
	for i := 1; i < len(counts); i++ {
		counts[i] += counts[i-1]
	}
	sv.vstart = append([]int32(nil), counts...)
	sv.verts = make([]int32, counts[len(roots)])
	fill := append([]int32(nil), counts[:len(roots)]...)
	for i := int32(0); i < int32(n); i++ {
		if c := sv.compOf[i]; c >= 0 {
			sv.verts[fill[c]] = i
			fill[c]++
		}
	}

	// Memberships in record order.
	for _, r := range g.order {
		ids := g.recIDs(r)
		if len(ids) == 0 {
			continue
		}
		cbuf = cvesOf(ids, cbuf)
		if len(cbuf) >= 2 {
			for _, c := range cbuf {
				sv.members = append(sv.members, member{sv.compOf[c], r, c})
			}
			continue
		}
		anchor := ids[0]
		if len(cbuf) == 1 {
			anchor = cbuf[0]
		}
		sv.members = append(sv.members, member{sv.compOf[anchor], r, -1})
	}
	slices.SortStableFunc(sv.members, func(a, b member) int { return int(a.comp) - int(b.comp) })
	sv.mstart = make([]int32, len(roots)+1)
	for _, m := range sv.members {
		sv.mstart[m.comp+1]++
	}
	for i := 1; i < len(sv.mstart); i++ {
		sv.mstart[i] += sv.mstart[i-1]
	}
	sv.collBy = make([][]collisionKey, len(roots))
	keys := make([]collisionKey, 0, len(collRecs))
	for k := range collRecs {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b collisionKey) int {
		if c := strings.Compare(g.names[a[0]], g.names[b[0]]); c != 0 {
			return c
		}
		return strings.Compare(g.names[a[1]], g.names[b[1]])
	})
	for _, k := range keys {
		c := sv.compOf[k[0]]
		sv.collBy[c] = append(sv.collBy[c], k)
	}
	return sv
}

func marshal(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func recordKey(source, id string) string { return source + ":" + id }

type resDecision struct {
	body       string // JSON stored in entity_resolution.decision
	confidence float64
}

// batchRows is the desired state for a run of components.
type batchRows struct {
	vulns     []string
	idents    [][2]string // value, vulnerability
	members   [][4]string // source, external_id, vulnerability, method
	decisions map[[3]string]resDecision
	nrows     int
}

// memberMethod returns the resolution method of record (source, id) in the component whose
// canonical id is vuln, or false if the solved state has no such membership.
func (sv *solved) memberMethod(source, id, vuln string) (string, bool) {
	g := sv.g
	vi, ok := g.idx[vuln]
	if !ok || !sv.inV[vi] {
		return "", false
	}
	c := sv.compOf[vi]
	if g.names[sv.canon[c]] != vuln {
		return "", false
	}
	ms := sv.members[sv.mstart[c]:sv.mstart[c+1]] // in (source, external_id) order
	i, found := slices.BinarySearchFunc(ms, [2]string{source, id}, func(m member, k [2]string) int {
		if c := strings.Compare(g.srcs[g.recSrc[m.rec]], k[0]); c != 0 {
			return c
		}
		return strings.Compare(g.names[g.recExt[m.rec]], k[1])
	})
	if !found {
		return "", false
	}
	if ms[i].cve >= 0 {
		return RuleMultiCVE, true
	}
	return RuleExactIdentifier, true
}

func (sv *solved) addComponent(b *batchRows, c int32) {
	g := sv.g
	v := g.names[sv.canon[c]]
	b.vulns = append(b.vulns, v)
	for _, x := range sv.verts[sv.vstart[c]:sv.vstart[c+1]] {
		b.idents = append(b.idents, [2]string{g.names[x], v})
	}
	ms := sv.members[sv.mstart[c]:sv.mstart[c+1]]
	var exact []member
	for _, m := range ms {
		src, ext := g.srcs[g.recSrc[m.rec]], g.names[g.recExt[m.rec]]
		if m.cve >= 0 {
			b.members = append(b.members, [4]string{src, ext, v, RuleMultiCVE})
			var cves []string
			for _, x := range g.recIDs(m.rec) {
				if g.isCVE[x] {
					cves = append(cves, g.names[x])
				}
			}
			key := g.recKey(m.rec)
			b.decisions[[3]string{v, key, RuleMultiCVE}] = resDecision{confidence: 1,
				body: marshal(map[string]any{"rule": RuleMultiCVE, "matched": []string{g.names[m.cve]},
					"cve_ids": cves, "source_record_ids": []string{key}})}
			continue
		}
		b.members = append(b.members, [4]string{src, ext, v, RuleExactIdentifier})
		exact = append(exact, m)
	}
	if len(exact) >= 2 {
		count := map[int32]int{}
		for _, m := range exact {
			for _, x := range g.recIDs(m.rec) {
				count[x]++
			}
		}
		for _, m := range exact {
			var matched []string
			for _, x := range g.recIDs(m.rec) {
				if count[x] >= 2 {
					matched = append(matched, g.names[x])
				}
			}
			if len(matched) == 0 {
				continue
			}
			key := g.recKey(m.rec)
			b.decisions[[3]string{v, key, RuleExactIdentifier}] = resDecision{confidence: 1,
				body: marshal(map[string]any{"rule": RuleExactIdentifier, "matched": matched,
					"source_record_ids": []string{key}})}
		}
	}
	for _, k := range sv.collBy[c] {
		var keys []string
		for _, r := range sv.collRecs[k] {
			keys = append(keys, g.recKey(r))
		}
		sort.Strings(keys)
		keys = slices.Compact(keys)
		a, bb := g.names[k[0]], g.names[k[1]]
		b.decisions[[3]string{a, bb, RuleIdentifierCollision}] = resDecision{confidence: 0,
			body: marshal(map[string]any{"rule": RuleIdentifierCollision,
				"cve_ids": []string{a, bb}, "source_record_ids": keys})}
	}
	b.nrows += 1 + int(sv.vstart[c+1]-sv.vstart[c]) + len(ms)
}

// ---- Resolve ----

type dirtyKey struct{ source, id, hash string }

// Resolve groups source records into canonical vulnerabilities using exact identifier equality
// only (guarded union-find, see design.md "Entity resolution"), then reconciles the
// vulnerability, vulnerability_identifier, record_vulnerability and entity_resolution tables in
// batched transactions. source_record is never written.
//
// Memory holds only interned identifier strings and int32 offsets, never record JSON. Without
// opts.Full it resolves only the identifier components that contain a record changed since the
// last run; components are independent, so the result equals a full pass.
func (s *Store) Resolve(ctx context.Context, opts ResolveOptions) (ResolveReport, error) {
	var rep ResolveReport
	if err := s.indexMissingRecords(ctx); err != nil {
		return rep, err
	}
	dirty, err := s.loadDirty(ctx)
	if err != nil {
		return rep, err
	}
	rep.DirtyRecords = len(dirty)
	var total int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM source_record`).Scan(&total); err != nil {
		return rep, err
	}
	full := opts.Full || opts.Fuzzy || len(dirty)*fullDirtyShare >= total
	rep.Mode = "incremental"
	if full {
		rep.Mode = "full"
	}

	var g *rgraph
	if full {
		g, err = s.loadAll(ctx)
	} else {
		g, err = s.loadClosure(ctx, dirty)
	}
	if err != nil {
		return rep, err
	}
	rep.RecordsResolved = g.records()
	if g.records() > 0 || full {
		g.finish()
		sv := g.solve()
		rep.Components = len(sv.canon)
		if err := s.applySolved(ctx, sv, full, opts, &rep); err != nil {
			return rep, err
		}
		if opts.Fuzzy {
			cands, ncmp, err := s.fuzzyCandidates(ctx, sv, opts)
			if err != nil {
				return rep, err
			}
			rep.FuzzyComparisons = ncmp
			if err := s.applyCandidates(ctx, cands); err != nil {
				return rep, err
			}
		}
	}
	if !opts.Fuzzy {
		// candidate_pair only holds the output of the latest fuzzy run.
		if err := s.applyCandidates(ctx, nil); err != nil {
			return rep, err
		}
	}
	if err := s.clearDirty(ctx, dirty); err != nil {
		return rep, err
	}
	// Flip pending KEV/EPSS rows for CVEs that now exist and link them to the vulnerability.
	n, err := s.LinkPending(ctx)
	if err != nil {
		return rep, err
	}
	rep.LinkedEnrichment = n
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerability`).Scan(&rep.Groups); err != nil {
		return rep, err
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM record_vulnerability`).Scan(&rep.Memberships); err != nil {
		return rep, err
	}
	if rep.Collisions, err = s.CountCollisions(ctx); err != nil {
		return rep, err
	}
	return rep, nil
}

func (s *Store) loadDirty(ctx context.Context) ([]dirtyKey, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT source, external_id, content_hash FROM resolve_dirty ORDER BY source, external_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []dirtyKey
	for rows.Next() {
		var k dirtyKey
		if err := rows.Scan(&k.source, &k.id, &k.hash); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// clearDirty removes the marks this run processed; a record changed again meanwhile has a
// different hash and stays marked.
func (s *Store) clearDirty(ctx context.Context, keys []dirtyKey) error {
	for i := 0; i < len(keys); i += 2000 {
		end := min(i+2000, len(keys))
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, k := range keys[i:end] {
			if _, err := tx.ExecContext(ctx, `DELETE FROM resolve_dirty WHERE source=? AND external_id=? AND content_hash=?`, k.source, k.id, k.hash); err != nil {
				tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// loadAll streams every (record, identifier) row in index order; only ids are read.
func (s *Store) loadAll(ctx context.Context) (*rgraph, error) {
	g := newRGraph()
	rows, err := s.DB.QueryContext(ctx, `SELECT source, external_id, value FROM record_identifier ORDER BY source, external_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var curS, curE string
	open := false
	for rows.Next() {
		var src, ext, v string
		if err := rows.Scan(&src, &ext, &v); err != nil {
			return nil, err
		}
		if !open || src != curS || ext != curE {
			if open {
				g.endRecord()
			}
			g.beginRecord(src, ext)
			curS, curE, open = src, ext, true
		}
		g.addIdent(v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if open {
		g.endRecord()
	}
	return g, nil
}

// loadClosure loads the records of every identifier component that contains a dirty record or
// belonged to a vulnerability of one (so that components that split or merge are rewritten).
func (s *Store) loadClosure(ctx context.Context, dirty []dirtyKey) (*rgraph, error) {
	g := newRGraph()
	type rk struct{ s, e string }
	seenRec := map[rk]bool{}
	seenID := map[string]bool{}
	seenV := map[string]bool{}
	var idQ, vQ []string
	var recQ []rk

	query := func(q string, args ...any) ([][]string, error) {
		rows, err := s.DB.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		cols, _ := rows.Columns()
		var out [][]string
		for rows.Next() {
			vals := make([]string, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				return nil, err
			}
			out = append(out, vals)
		}
		return out, rows.Err()
	}
	addVuln := func(v string) {
		if !seenV[v] {
			seenV[v] = true
			vQ = append(vQ, v)
		}
	}
	addRec := func(k rk) error {
		if seenRec[k] {
			return nil
		}
		seenRec[k] = true
		ids, err := query(`SELECT value FROM record_identifier WHERE source=? AND external_id=?`, k.s, k.e)
		if err != nil {
			return err
		}
		if len(ids) > 0 {
			g.beginRecord(k.s, k.e)
			for _, r := range ids {
				g.addIdent(r[0])
				if !seenID[r[0]] {
					seenID[r[0]] = true
					idQ = append(idQ, r[0])
				}
			}
			g.endRecord()
		}
		vs, err := query(`SELECT vulnerability_id FROM record_vulnerability WHERE source=? AND external_id=?`, k.s, k.e)
		if err != nil {
			return err
		}
		for _, r := range vs {
			addVuln(r[0])
		}
		return nil
	}
	for _, d := range dirty {
		if err := addRec(rk{d.source, d.id}); err != nil {
			return nil, err
		}
	}
	for len(idQ) > 0 || len(vQ) > 0 || len(recQ) > 0 {
		for len(idQ) > 0 {
			chunk := idQ[:min(inChunk, len(idQ))]
			idQ = idQ[len(chunk):]
			rows, err := query(`SELECT DISTINCT source, external_id FROM record_identifier WHERE value IN (`+placeholders(len(chunk))+`)`, toAny(chunk)...)
			if err != nil {
				return nil, err
			}
			for _, r := range rows {
				if err := addRec(rk{r[0], r[1]}); err != nil {
					return nil, err
				}
			}
		}
		for len(vQ) > 0 {
			v := vQ[len(vQ)-1]
			vQ = vQ[:len(vQ)-1]
			idents, err := query(`SELECT value FROM vulnerability_identifier WHERE vulnerability_id=?`, v)
			if err != nil {
				return nil, err
			}
			for _, r := range idents {
				if !seenID[r[0]] {
					seenID[r[0]] = true
					idQ = append(idQ, r[0])
				}
			}
			recs, err := query(`SELECT source, external_id FROM record_vulnerability WHERE vulnerability_id=?`, v)
			if err != nil {
				return nil, err
			}
			for _, r := range recs {
				recQ = append(recQ, rk{r[0], r[1]})
			}
			// A recorded collision involving v pulls the other CVE's component in too.
			for _, q := range []string{
				`SELECT right_id FROM entity_resolution WHERE method='identifier-collision' AND left_id=?`,
				`SELECT left_id FROM entity_resolution WHERE method='identifier-collision' AND right_id=?`} {
				others, err := query(q, v)
				if err != nil {
					return nil, err
				}
				for _, r := range others {
					addVuln(r[0])
				}
			}
		}
		for len(recQ) > 0 {
			k := recQ[len(recQ)-1]
			recQ = recQ[:len(recQ)-1]
			if err := addRec(k); err != nil {
				return nil, err
			}
		}
	}
	return g, nil
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func toAny(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

// applySolved writes the solved components in batched transactions.
func (s *Store) applySolved(ctx context.Context, sv *solved, full bool, opts ResolveOptions, rep *ResolveReport) error {
	limit := opts.BatchRows
	if limit <= 0 {
		limit = defaultBatchRows
	}
	now := s.now()
	touched := map[string]struct{}{}
	newBatch := func() *batchRows { return &batchRows{decisions: map[[3]string]resDecision{}} }
	b := newBatch()
	flush := func() error {
		if len(b.vulns) == 0 {
			return nil
		}
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if err := applyBatch(ctx, tx, sv, b, now, touched, rep); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		b = newBatch()
		return nil
	}
	for c := int32(0); c < int32(len(sv.canon)); c++ {
		sv.addComponent(b, c)
		if b.nrows >= limit {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	return s.sweepStale(ctx, touched, full)
}

func inQuery(ctx context.Context, tx *sql.Tx, prefix, suffix string, pre []any, vals []string, fn func(*sql.Rows) error) error {
	for i := 0; i < len(vals); i += inChunk {
		chunk := vals[i:min(i+inChunk, len(vals))]
		rows, err := tx.QueryContext(ctx, prefix+placeholders(len(chunk))+suffix, append(append([]any(nil), pre...), toAny(chunk)...)...)
		if err != nil {
			return err
		}
		for rows.Next() {
			if err := fn(rows); err != nil {
				rows.Close()
				return err
			}
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	return nil
}

// applyBatch diffs the desired rows of a run of components against the stored rows that can
// overlap them and applies only the difference.
func applyBatch(ctx context.Context, tx *sql.Tx, sv *solved, b *batchRows, now string, touched map[string]struct{}, rep *ResolveReport) error {
	// vulnerability
	haveV := map[string]bool{}
	if err := inQuery(ctx, tx, `SELECT id FROM vulnerability WHERE id IN (`, `)`, nil, b.vulns, func(r *sql.Rows) error {
		var id string
		if err := r.Scan(&id); err != nil {
			return err
		}
		haveV[id] = true
		return nil
	}); err != nil {
		return err
	}
	for _, id := range b.vulns {
		if !haveV[id] {
			if _, err := tx.ExecContext(ctx, `INSERT INTO vulnerability(id) VALUES(?) ON CONFLICT DO NOTHING`, id); err != nil {
				return err
			}
		}
	}

	// vulnerability_identifier, keyed by value (each value belongs to one vulnerability).
	wantI := make(map[[2]string]bool, len(b.idents))
	values := make([]string, 0, len(b.idents))
	for _, k := range b.idents {
		wantI[k] = true
		values = append(values, k[0])
	}
	haveI := map[[2]string]bool{}
	if err := inQuery(ctx, tx, `SELECT value, vulnerability_id FROM vulnerability_identifier WHERE value IN (`, `)`, nil, values, func(r *sql.Rows) error {
		var k [2]string
		if err := r.Scan(&k[0], &k[1]); err != nil {
			return err
		}
		haveI[k] = true
		return nil
	}); err != nil {
		return err
	}
	for k := range haveI {
		if !wantI[k] {
			touched[k[1]] = struct{}{}
			if _, err := tx.ExecContext(ctx, `DELETE FROM vulnerability_identifier WHERE value=? AND vulnerability_id=?`, k[0], k[1]); err != nil {
				return err
			}
		}
	}
	for _, k := range b.idents {
		if !haveI[k] {
			if _, err := tx.ExecContext(ctx, `INSERT INTO vulnerability_identifier(value, vulnerability_id) VALUES(?,?) ON CONFLICT DO NOTHING`, k[0], k[1]); err != nil {
				return err
			}
		}
	}

	// record_vulnerability, looked up by record.
	wantM := make(map[[3]string]string, len(b.members))
	bySource := map[string][]string{}
	seenRec := map[[2]string]bool{}
	for _, m := range b.members {
		wantM[[3]string{m[0], m[1], m[2]}] = m[3]
		if k := [2]string{m[0], m[1]}; !seenRec[k] {
			seenRec[k] = true
			bySource[m[0]] = append(bySource[m[0]], m[1])
		}
	}
	haveM := map[[3]string]string{}
	for src, ids := range bySource {
		if err := inQuery(ctx, tx, `SELECT source, external_id, vulnerability_id, method FROM record_vulnerability WHERE source=? AND external_id IN (`, `)`, []any{src}, ids, func(r *sql.Rows) error {
			var k [3]string
			var m string
			if err := r.Scan(&k[0], &k[1], &k[2], &m); err != nil {
				return err
			}
			haveM[k] = m
			return nil
		}); err != nil {
			return err
		}
	}
	for k, m := range haveM {
		// A record can belong to several vulnerabilities (multi-CVE advisories) whose components
		// are written in different batches, so a row this batch does not want is stale only if
		// the solved state as a whole does not want it either.
		want, ok := wantM[k]
		if !ok {
			want, ok = sv.memberMethod(k[0], k[1], k[2])
		}
		if !ok || want != m {
			touched[k[2]] = struct{}{}
			if _, err := tx.ExecContext(ctx, `DELETE FROM record_vulnerability WHERE source=? AND external_id=? AND vulnerability_id=?`, k[0], k[1], k[2]); err != nil {
				return err
			}
			delete(haveM, k)
		}
	}
	for _, m := range b.members {
		k := [3]string{m[0], m[1], m[2]}
		if _, ok := haveM[k]; !ok {
			if _, err := tx.ExecContext(ctx, `INSERT INTO record_vulnerability(source, external_id, vulnerability_id, method) VALUES(?,?,?,?) ON CONFLICT DO NOTHING`, m[0], m[1], m[2], m[3]); err != nil {
				return err
			}
		}
	}

	// entity_resolution, looked up by left_id (the vulnerability).
	haveD := map[[3]string]string{}
	if err := inQuery(ctx, tx, `SELECT left_id, right_id, method, decision FROM entity_resolution WHERE left_id IN (`, `)`, nil, b.vulns, func(r *sql.Rows) error {
		var k [3]string
		var body string
		if err := r.Scan(&k[0], &k[1], &k[2], &body); err != nil {
			return err
		}
		haveD[k] = body
		return nil
	}); err != nil {
		return err
	}
	for k := range haveD {
		if _, ok := b.decisions[k]; !ok {
			if _, err := tx.ExecContext(ctx, `DELETE FROM entity_resolution WHERE left_id=? AND right_id=? AND method=?`, k[0], k[1], k[2]); err != nil {
				return err
			}
		}
	}
	for k, dec := range b.decisions {
		old, ok := haveD[k]
		switch {
		case !ok:
			if _, err := tx.ExecContext(ctx, `INSERT INTO entity_resolution(left_id, right_id, decision, confidence, method, recorded_at) VALUES(?,?,?,?,?,?)`,
				k[0], k[1], dec.body, dec.confidence, k[2], now); err != nil {
				return err
			}
			rep.NewDecisions++
		case old != dec.body:
			// Content changed but the link is the same: keep the original decision time.
			if _, err := tx.ExecContext(ctx, `UPDATE entity_resolution SET decision=? WHERE left_id=? AND right_id=? AND method=?`,
				dec.body, k[0], k[1], k[2]); err != nil {
				return err
			}
		}
	}
	return nil
}

// sweepStale removes vulnerabilities that lost every record, and their identifier and decision
// rows. Incremental runs check only the vulnerabilities their diffs touched; full runs also
// remove any vulnerability that has no record at all.
func (s *Store) sweepStale(ctx context.Context, touched map[string]struct{}, full bool) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ids := make([]string, 0, len(touched))
	for v := range touched {
		ids = append(ids, v)
	}
	sort.Strings(ids)
	for i := 0; i < len(ids); i += inChunk {
		chunk := ids[i:min(i+inChunk, len(ids))]
		ph := placeholders(len(chunk))
		args := toAny(chunk)
		for _, q := range []string{
			`DELETE FROM vulnerability WHERE id IN (` + ph + `) AND NOT EXISTS (SELECT 1 FROM record_vulnerability rv WHERE rv.vulnerability_id=vulnerability.id)`,
			`DELETE FROM vulnerability_identifier WHERE vulnerability_id IN (` + ph + `) AND NOT EXISTS (SELECT 1 FROM vulnerability v WHERE v.id=vulnerability_identifier.vulnerability_id)`,
			`DELETE FROM entity_resolution WHERE left_id IN (` + ph + `) AND NOT EXISTS (SELECT 1 FROM vulnerability v WHERE v.id=entity_resolution.left_id)`,
		} {
			if _, err := tx.ExecContext(ctx, q, args...); err != nil {
				return err
			}
		}
	}
	if full {
		for _, q := range []string{
			`DELETE FROM vulnerability WHERE NOT EXISTS (SELECT 1 FROM record_vulnerability rv WHERE rv.vulnerability_id=vulnerability.id)`,
			`DELETE FROM vulnerability_identifier WHERE NOT EXISTS (SELECT 1 FROM vulnerability v WHERE v.id=vulnerability_identifier.vulnerability_id)`,
			`DELETE FROM entity_resolution WHERE method IN ('exact-identifier','multi-cve','identifier-collision') AND NOT EXISTS (SELECT 1 FROM vulnerability v WHERE v.id=entity_resolution.left_id)`,
			`DELETE FROM record_vulnerability WHERE NOT EXISTS (SELECT 1 FROM source_record sr WHERE sr.source=record_vulnerability.source AND sr.external_id=record_vulnerability.external_id)`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// Enrichment rows that pointed at a removed vulnerability fall back to unlinked.
	if len(ids) > 0 || full {
		return s.LinkEnrichmentIDs(ctx, true)
	}
	return nil
}
