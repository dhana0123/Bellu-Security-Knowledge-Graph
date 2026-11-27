// Package upsert turns normalized source records into graph writes. Plan is
// pure: it compares the desired records with the existing state and returns
// the writes, the Change records, and the counters. Apply (apply.go) runs the
// writes in a transaction.
package upsert

import (
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/change"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/model"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/provenance"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/resolve"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
)

// Change record types.
const (
	TypeEntityCreated       = change.TypeEntityCreated
	TypePropertyChanged     = change.TypePropertyChanged
	TypeRelationshipCreated = change.TypeRelationshipCreated
	TypeRelationshipRemoved = "relationshipRemoved"
	TypeVulnerabilityMerged = change.TypeVulnerabilityMerged
	TypeAliasConflict       = change.TypeAliasConflict
	removedProp             = "removed"
	exploitsType            = "EXPLOITS"
	exploitPublishDateProp  = "exploitPublishDate"
	labelVulnerability      = "Vulnerability"
	labelExploit            = "Exploit"
	labelWeakness           = "Weakness"
	productTypeProp         = "productType"
	exploitabilityProp      = "exploitability"
	exploitDateProp         = "exploitDate"
	sourcesProp             = "sources"
)

// RunContext holds the per-run settings Plan needs. Bulk is true when the
// source has no checkpoint watermark and no version (first load).
type RunContext struct {
	Source string
	RunID  string
	Now    time.Time
	Bulk   bool
}

// RelID identifies a relationship: type, endpoints, and identity properties.
type RelID struct {
	Type     string
	From, To resolve.Key
	Ident    string
}

// State is the existing graph content for the keys of a batch. A node or
// relationship maps to its stored properties.
type State struct {
	Nodes map[resolve.Key]map[string]any
	Rels  map[RelID]map[string]any
}

// Desired is one normalized record.
type Desired struct {
	ID string // source record id, stored as the provenance reference
	N  source.Normalized
}

// Batch is the desired content of one transaction.
type Batch []Desired

// NodeWrite sets properties on one node (created if absent). A nil value
// removes the property.
type NodeWrite struct {
	Key   resolve.Key
	Props map[string]any
}

// RelWrite sets properties on one relationship (created if absent). Key holds
// the identity properties.
type RelWrite struct {
	Type     string
	From, To resolve.Key
	Key      map[string]any
	Props    map[string]any
}

// Writes is the set of database writes of one batch.
type Writes struct {
	Source        string
	Nodes         []NodeWrite
	Rels          []RelWrite
	RecomputeCVEs []string // Vulnerabilities whose exploitability must be recomputed
	// Merges run first in Apply, before Nodes and Rels (see alias.go).
	Merges []MergeWrite
}

// Counts are the per-batch counters. Created, Updated, Unchanged, and Skipped
// count records; the others count items.
type Counts struct {
	Created    int
	Updated    int
	Unchanged  int
	Skipped    int // Gate failed
	Missing    int // record lacked a mappable field
	Unresolved int // MustExist or missing endpoint, unresolved reference
	Rejected   int // invalid identifier or relationship
}

type nodeW struct {
	key      resolve.Key
	created  bool
	cur, set map[string]any
}

type relW struct {
	id       RelID
	created  bool
	cur, set map[string]any
}

type planner struct {
	rc    RunContext
	st    State
	nodes map[resolve.Key]*nodeW
	nord  []*nodeW
	rels  map[RelID]*relW
	rord  []*relW
	out   map[resolve.Key][]RelID // existing relationships by start node
	recs  []change.Record
	cnt   Counts
	recom map[string]struct{}
	// merges are the planned Vulnerability merges; gone holds the merged-away
	// keys, which no longer exist for the rest of the batch (alias.go).
	merges []MergeWrite
	gone   map[resolve.Key]bool
	// per-record flags
	created, changed bool
}

// Plan compares desired with existing and returns the writes, the Change
// records (without ids; Apply assigns them), and the counters.
func Plan(existing State, desired Batch, rc RunContext) (Writes, []change.Record, Counts) {
	p := &planner{
		rc: rc, st: existing,
		nodes: map[resolve.Key]*nodeW{}, rels: map[RelID]*relW{},
		out: map[resolve.Key][]RelID{}, recom: map[string]struct{}{},
		gone: map[resolve.Key]bool{},
	}
	for id := range existing.Rels {
		p.out[id.From] = append(p.out[id.From], id)
	}
	for _, d := range desired {
		p.record(d)
	}
	w := Writes{Source: rc.Source}
	for _, n := range p.nord {
		if len(n.set) > 0 {
			w.Nodes = append(w.Nodes, NodeWrite{Key: n.key, Props: n.set})
		}
	}
	for _, r := range p.rord {
		if len(r.set) == 0 {
			continue
		}
		rt, _ := model.RelByName(r.id.Type)
		key := map[string]any{}
		for _, k := range rt.Identity {
			key[k] = r.cur[k]
		}
		w.Rels = append(w.Rels, RelWrite{Type: r.id.Type, From: r.id.From, To: r.id.To, Key: key, Props: r.set})
	}
	for id := range p.recom {
		w.RecomputeCVEs = append(w.RecomputeCVEs, id)
	}
	sort.Strings(w.RecomputeCVEs)
	w.Merges = p.merges
	return w, p.recs, p.cnt
}

func (p *planner) record(d Desired) {
	n, ap := expandAdvisory(d.N)
	if len(n.Gate) > 0 && !p.gateOpen(n.Gate) {
		p.cnt.Skipped++
		return
	}
	if n.Missing {
		p.cnt.Missing++
	}
	p.created, p.changed = false, false
	if ap != nil {
		n = p.aliasStep(ap, n)
	}
	for _, e := range n.Entities {
		p.entity(e, d.ID)
	}
	desired := map[RelID]bool{}
	for _, r := range n.Rels {
		if id, ok := p.rel(r, d.ID); ok {
			desired[id] = true
		}
	}
	if n.Anchor != nil {
		p.removals(*n.Anchor, n.Owned, desired, d.ID)
	}
	switch {
	case p.created:
		p.cnt.Created++
	case p.changed:
		p.cnt.Updated++
	default:
		p.cnt.Unchanged++
	}
}

func (p *planner) gateOpen(refs []source.Ref) bool {
	for _, r := range refs {
		if k, err := resolve.Resolve(r); err == nil && p.node(k) != nil {
			return true
		}
	}
	return false
}

// node returns the working node, loading it from the existing state, or nil
// when the node exists neither in the graph nor in this batch.
func (p *planner) node(k resolve.Key) *nodeW {
	if p.gone[k] {
		return nil
	}
	if n := p.nodes[k]; n != nil {
		return n
	}
	ex, ok := p.st.Nodes[k]
	if !ok {
		return nil
	}
	n := &nodeW{key: k, cur: clone(ex), set: map[string]any{}}
	p.nodes[k] = n
	p.nord = append(p.nord, n)
	return n
}

func (p *planner) countErr(err error) {
	if resolve.IsUnresolved(err) {
		p.cnt.Unresolved++
	} else {
		p.cnt.Rejected++
	}
}

func (p *planner) entity(e source.Entity, ref string) {
	k, err := resolve.Resolve(e.Ref)
	if err != nil {
		p.countErr(err)
		return
	}
	n := p.node(k)
	if n == nil && e.Ref.MustExist {
		p.cnt.Unresolved++
		return
	}
	if n == nil {
		props := clone(e.Props)
		if k.Label == labelVulnerability {
			setDefault(props, exploitabilityProp, int64(0))
			setDefault(props, exploitDateProp, []string{})
		}
		if e.Ref.Kind == source.RefCPE {
			if c, err := resolve.CPE(e.Ref.Raw); err == nil {
				setDefault(props, productTypeProp, c.ProductType)
			}
		}
		for _, c := range e.Clear {
			delete(props, c)
		}
		keyProps := map[string]any{k.Prop: k.Value}
		n = &nodeW{key: k, created: true, cur: clone(props), set: clone(props)}
		n.cur[k.Prop], n.set[k.Prop] = k.Value, k.Value
		p.nodes[k] = n
		p.nord = append(p.nord, n)
		p.addSource(n.cur)
		p.stamp(n.cur, n.set, ref)
		// Change record.
		nv := clone(props)
		nv[k.Prop] = k.Value
		if p.rc.Bulk {
			nv = keyProps
		}
		if !p.rc.Bulk || k.Label == labelVulnerability || k.Label == labelExploit || k.Label == labelWeakness {
			p.rec(k.String(), TypeEntityCreated, "", "", change.EncodeProps(nv))
		}
		p.created = true
		return
	}
	// Existing node: change only differing properties.
	dirty := false
	quiet := quietProps(e, n.cur)
	for _, name := range sortedKeys(e.Props) {
		v := e.Props[name]
		if name == k.Prop || equalValue(n.cur[name], v) {
			continue
		}
		if !quiet[name] {
			p.rec(k.String(), TypePropertyChanged, name, change.EncodeValue(n.cur[name]), change.EncodeValue(v))
		}
		n.cur[name], n.set[name] = v, v
		dirty = true
		if k.Label == labelExploit && name == exploitPublishDateProp {
			p.exploitDateChanged(k)
		}
	}
	for _, name := range e.Clear {
		if old, ok := n.cur[name]; ok && name != k.Prop {
			p.rec(k.String(), TypePropertyChanged, name, change.EncodeValue(old), "null")
			delete(n.cur, name)
			n.set[name] = nil
			dirty = true
		}
	}
	if p.addSource(n.cur) || dirty {
		p.stamp(n.cur, n.set, ref)
		p.changed = true
	}
}

// thresholdEpsilon absorbs float rounding when a change equals the threshold.
const thresholdEpsilon = 1e-9

// quietProps returns the properties of e whose changes are stored without a
// Change_Record (Entity.ChangeThreshold, Entity.ChangeFollows). A governing
// property is quiet when old and new are both numeric and the absolute change
// is below its threshold. A follower is quiet when its governor is quiet. It
// returns nil when e sets no ChangeThreshold.
func quietProps(e source.Entity, cur map[string]any) map[string]bool {
	if len(e.ChangeThreshold) == 0 {
		return nil
	}
	quiet := map[string]bool{}
	for name, t := range e.ChangeThreshold {
		nv, ok := e.Props[name]
		if !ok {
			continue
		}
		o, ook := numeric(cur[name])
		n, nok := numeric(nv)
		if ook && nok && math.Abs(n-o) < t-thresholdEpsilon {
			quiet[name] = true
		}
	}
	for name, gov := range e.ChangeFollows {
		if _, has := e.ChangeThreshold[gov]; has && quiet[gov] {
			quiet[name] = true
		}
	}
	return quiet
}

func numeric(v any) (float64, bool) {
	switch x := normalize(v).(type) {
	case float64:
		return x, !math.IsNaN(x)
	}
	return 0, false
}

// exploitDateChanged queues the Vulnerabilities an Exploit points at.
func (p *planner) exploitDateChanged(k resolve.Key) {
	for _, id := range p.out[k] {
		if id.Type == exploitsType {
			p.recom[id.To.Value] = struct{}{}
		}
	}
}

func (p *planner) relation(id RelID) *relW {
	if r := p.rels[id]; r != nil {
		return r
	}
	ex, ok := p.st.Rels[id]
	if !ok {
		return nil
	}
	r := &relW{id: id, cur: clone(ex), set: map[string]any{}}
	p.rels[id] = r
	p.rord = append(p.rord, r)
	return r
}

func (p *planner) rel(r source.Rel, ref string) (RelID, bool) {
	rt, ok := model.RelByName(r.Type)
	if !ok {
		p.cnt.Rejected++
		return RelID{}, false
	}
	from, err := resolve.Resolve(r.From)
	if err != nil {
		p.countErr(err)
		return RelID{}, false
	}
	to, err := resolve.Resolve(r.To)
	if err != nil {
		p.countErr(err)
		return RelID{}, false
	}
	if from.Label != rt.From || to.Label != rt.To {
		p.cnt.Rejected++
		return RelID{}, false
	}
	for _, k := range rt.Identity {
		if _, ok := r.Key[k]; !ok {
			p.cnt.Rejected++
			return RelID{}, false
		}
	}
	// Both endpoints must exist or be created in this batch.
	fn, tn := p.node(from), p.node(to)
	if fn == nil || tn == nil {
		p.cnt.Unresolved++
		return RelID{}, false
	}
	id := RelID{Type: r.Type, From: from, To: to, Ident: ident(rt.Identity, r.Key)}
	props := clone(r.Props)
	for k, v := range r.Key {
		props[k] = v
	}
	w := p.relation(id)
	ek := relEntityKey(id)
	if w == nil {
		w = &relW{id: id, created: true, cur: clone(props), set: clone(props)}
		p.rels[id] = w
		p.rord = append(p.rord, w)
		p.addSource(w.cur)
		p.stamp(w.cur, w.set, ref)
		if !(p.rc.Bulk && fn.created) {
			p.rec(ek, TypeRelationshipCreated, "", "", change.EncodeProps(props))
		}
		p.created = true
		p.relTouched(id)
		return id, true
	}
	dirty := false
	rk := provenance.RemovedKeyOf(p.rc.Source)
	if removed, _ := w.cur[rk].(bool); removed {
		delete(w.cur, rk)
		w.set[rk] = nil
		p.refreshRemoved(w)
		p.rec(ek, TypeRelationshipCreated, "", "", change.EncodeProps(props))
		p.relTouched(id)
		dirty = true
	}
	for _, name := range sortedKeys(props) {
		v := props[name]
		if equalValue(w.cur[name], v) {
			continue
		}
		p.rec(ek, TypePropertyChanged, name, change.EncodeValue(w.cur[name]), change.EncodeValue(v))
		w.cur[name], w.set[name] = v, v
		dirty = true
	}
	if p.addSource(w.cur) || dirty {
		p.stamp(w.cur, w.set, ref)
		p.changed = true
	}
	return id, true
}

// removals marks owned relationships of the anchor that this source no longer
// asserts. They are never deleted.
func (p *planner) removals(anchor source.Ref, owned []source.OwnedRel, desired map[RelID]bool, ref string) {
	ak, err := resolve.Resolve(anchor)
	if err != nil {
		return
	}
	own := map[string]bool{}
	for _, o := range owned {
		own[o.Type] = true
	}
	rk := provenance.RemovedKeyOf(p.rc.Source)
	for _, id := range p.out[ak] {
		if !own[id.Type] || desired[id] {
			continue
		}
		w := p.relation(id)
		if w == nil || !hasSource(w.cur, p.rc.Source) {
			continue
		}
		if removed, _ := w.cur[rk].(bool); removed {
			continue
		}
		w.cur[rk], w.set[rk] = true, true
		p.refreshRemoved(w)
		p.stamp(w.cur, w.set, ref)
		p.rec(relEntityKey(id), TypeRelationshipRemoved, "", "", "null")
		p.relTouched(id)
		p.changed = true
	}
}

// relTouched queues exploitability recomputation for EXPLOITS changes.
func (p *planner) relTouched(id RelID) {
	if id.Type == exploitsType {
		p.recom[id.To.Value] = struct{}{}
	}
}

// refreshRemoved maintains the derived `removed` property: true only when
// every source of the relationship marked it removed; absent otherwise.
func (p *planner) refreshRemoved(w *relW) {
	want := false
	srcs := sourcesOf(w.cur)
	if len(srcs) > 0 {
		want = true
		for _, s := range srcs {
			if v, _ := w.cur[provenance.RemovedKeyOf(s)].(bool); !v {
				want = false
				break
			}
		}
	}
	had, _ := w.cur[removedProp].(bool)
	switch {
	case want && !had:
		w.cur[removedProp], w.set[removedProp] = true, true
	case !want && had:
		delete(w.cur, removedProp)
		w.set[removedProp] = nil
	}
}

// addSource adds the run's source to cur.sources and reports whether it was new.
func (p *planner) addSource(cur map[string]any) bool {
	if hasSource(cur, p.rc.Source) {
		return false
	}
	cur[sourcesProp] = append(sourcesOf(cur), p.rc.Source)
	return true
}

// stamp writes the provenance properties of the run's source.
func (p *planner) stamp(cur, set map[string]any, ref string) {
	pp, err := provenance.Props(p.rc.Source, p.rc.RunID, ref, p.rc.Now)
	if err != nil {
		return
	}
	delete(pp, sourcesProp)
	for k, v := range pp {
		cur[k], set[k] = v, v
	}
}

func (p *planner) rec(entityKey, typ, field, oldV, newV string) {
	p.recs = append(p.recs, change.Record{
		EntityKey: entityKey, Type: typ, Field: field, OldValue: oldV, NewValue: newV,
		Source: p.rc.Source, RunID: p.rc.RunID, At: p.rc.Now,
	})
}

func relEntityKey(id RelID) string {
	s := id.Type + ":" + id.From.Value + "|" + id.To.Value
	if id.Ident != "" {
		s += "|" + id.Ident
	}
	return s
}

// ident renders the identity properties of a relationship.
func ident(names []string, props map[string]any) string {
	var parts []string
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s=%v", n, props[n]))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func sourcesOf(props map[string]any) []string {
	switch v := props[sourcesProp].(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func hasSource(props map[string]any, src string) bool {
	for _, s := range sourcesOf(props) {
		if s == src {
			return true
		}
	}
	return false
}

func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func setDefault(m map[string]any, k string, v any) {
	if _, ok := m[k]; !ok {
		m[k] = v
	}
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// normalize puts a stored or desired value into a comparable form: numbers by
// value, dates by civil date, lists in order.
func normalize(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case neo4j.Date:
		return x.Time().Format("2006-01-02")
	case time.Time:
		u := x.UTC()
		if u.Equal(u.Truncate(24 * time.Hour)) {
			return u.Format("2006-01-02")
		}
		return u.Truncate(time.Millisecond)
	case int:
		return normalize(int64(x))
	case int32:
		return normalize(int64(x))
	case int64:
		if x > -(1<<53) && x < 1<<53 {
			return float64(x)
		}
		return x
	case float32:
		return float64(x)
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Slice {
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = normalize(rv.Index(i).Interface())
		}
		return out
	}
	return v
}

func equalValue(a, b any) bool {
	na, nb := normalize(a), normalize(b)
	if fa, ok := na.(float64); ok {
		if fb, ok := nb.(float64); ok {
			return fa == fb || (math.IsNaN(fa) && math.IsNaN(fb))
		}
	}
	return reflect.DeepEqual(na, nb)
}
