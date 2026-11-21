package upsert

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/change"
	"github.com/bellu/bskg/internal/model"
	"github.com/bellu/bskg/internal/resolve"
	"github.com/bellu/bskg/internal/source"
)

// Alias handling for advisory sources (Requirements 9.4 to 9.9). Adapters set
// source.Normalized.Advisory; the rules below are generic. See
// source.Advisory for the semantics seen by adapters.

const (
	aliasesProp = "aliases"
	// MaxAliases caps the aliases list of one Vulnerability.
	MaxAliases = 100
)

// MergeWrite merges the advisory-keyed Vulnerability From into Into inside the
// transaction of the batch. Apply runs merges before node and relationship
// writes. A merge whose From node is already gone is a no-op, so re-running a
// batch is safe.
type MergeWrite struct {
	From, Into resolve.Key
}

// aliasPlan is the state-free analysis of a record's Advisory.
type aliasPlan struct {
	adv      resolve.Key   // Vulnerability keyed by the advisory id
	cves     []resolve.Key // valid CVE aliases, deduplicated, ascending
	others   []string      // other aliases, trimmed, deduplicated
	rejected int           // CVE aliases that are not CVE ids
}

// planAdvisory validates adv. It returns nil when adv is nil or its id is not
// a valid advisory id (the refs then fail to resolve and are rejected as
// usual).
func planAdvisory(adv *source.Advisory) *aliasPlan {
	if adv == nil {
		return nil
	}
	k, err := resolve.Advisory(adv.ID)
	if err != nil {
		return nil
	}
	ap := &aliasPlan{adv: k}
	seen := map[string]bool{}
	for _, c := range adv.CVEs {
		ck, err := resolve.CVE(c)
		if err != nil {
			ap.rejected++
			continue
		}
		if !seen[ck.Value] {
			seen[ck.Value] = true
			ap.cves = append(ap.cves, ck)
		}
	}
	sort.Slice(ap.cves, func(i, j int) bool { return ap.cves[i].Value < ap.cves[j].Value })
	oseen := map[string]bool{k.Value: true}
	for _, a := range adv.OtherAliases {
		v := strings.TrimSpace(a)
		if v == "" || oseen[v] {
			continue
		}
		oseen[v] = true
		ap.others = append(ap.others, v)
	}
	return ap
}

// targets returns the Vulnerability keys the record attaches to.
func (ap *aliasPlan) targets() []resolve.Key {
	if len(ap.cves) == 0 {
		return []resolve.Key{ap.adv}
	}
	return ap.cves
}

// targetRefs returns the refs that replace the advisory ref.
func (ap *aliasPlan) targetRefs() []source.Ref {
	if len(ap.cves) == 0 {
		return []source.Ref{{Kind: source.RefAdvisory, Raw: ap.adv.Value}}
	}
	out := make([]source.Ref, len(ap.cves))
	for i, c := range ap.cves {
		out[i] = source.Ref{Kind: source.RefCVE, Raw: c.Value}
	}
	return out
}

// isAdvisoryRef reports whether r names this record's advisory.
func (ap *aliasPlan) isAdvisoryRef(r source.Ref) bool {
	if r.Kind != source.RefAdvisory {
		return false
	}
	k, err := resolve.Advisory(r.Raw)
	return err == nil && k == ap.adv
}

// expand returns the refs r stands for.
func (ap *aliasPlan) expand(r source.Ref) []source.Ref {
	if ap.isAdvisoryRef(r) {
		return ap.targetRefs()
	}
	return []source.Ref{r}
}

// expandAdvisory rewrites the refs of n that name n.Advisory.ID to the target
// Vulnerability refs. It is pure and state-free, so Load and Plan agree on the
// keys. It returns n unchanged and a nil plan when n has no usable Advisory.
//
// With two or more targets an entity or relationship is repeated per target.
// The Anchor (owned-relationship removal) is dropped in that case, because
// removal handling needs one anchor node.
func expandAdvisory(n source.Normalized) (source.Normalized, *aliasPlan) {
	ap := planAdvisory(n.Advisory)
	if ap == nil {
		return n, nil
	}
	out := n
	out.Entities = nil
	for _, e := range n.Entities {
		for _, r := range ap.expand(e.Ref) {
			c := e
			c.Ref = r
			if ap.isAdvisoryRef(e.Ref) && r.Kind == source.RefCVE {
				c.Ref.MustExist = false
			}
			out.Entities = append(out.Entities, c)
		}
	}
	out.Rels = nil
	for _, r := range n.Rels {
		for _, f := range ap.expand(r.From) {
			for _, t := range ap.expand(r.To) {
				c := r
				c.From, c.To = f, t
				out.Rels = append(out.Rels, c)
			}
		}
	}
	out.Gate = nil
	for _, g := range n.Gate {
		out.Gate = append(out.Gate, ap.expand(g)...)
	}
	if n.Anchor != nil {
		if ex := ap.expand(*n.Anchor); len(ex) == 1 {
			a := ex[0]
			out.Anchor = &a
		} else {
			out.Anchor = nil
		}
	}
	return out, ap
}

// aliasStep applies the alias rules to the record n (already expanded): it
// makes sure every target Vulnerability gets an entity carrying the merged
// `aliases`, plans the merge of an existing advisory node into a single CVE
// target, and writes the Change_Records.
func (p *planner) aliasStep(ap *aliasPlan, n source.Normalized) source.Normalized {
	p.cnt.Rejected += ap.rejected
	targets := ap.targets()
	ents := append([]source.Entity(nil), n.Entities...)
	refs := ap.targetRefs()
	conflict := false
	for i, tk := range targets {
		var cur []string
		if nd := p.node(tk); nd != nil {
			cur = stringsOf(nd.cur[aliasesProp])
		}
		var add []string
		switch {
		case len(targets) == 1 && len(ap.cves) == 0:
			add = ap.others // the node is keyed by the advisory id itself
		case len(targets) == 1:
			add = append([]string{ap.adv.Value}, ap.others...)
			if _, exists := p.st.Nodes[ap.adv]; exists && !p.gone[ap.adv] {
				if an := p.node(ap.adv); an != nil {
					add = append(add, stringsOf(an.cur[aliasesProp])...)
				}
				p.merge(ap.adv, tk)
			}
		default:
			add = []string{ap.adv.Value}
		}
		merged := unionAliases(tk.Value, cur, add)
		if len(targets) > 1 && !equalValue(cur, merged) {
			conflict = true
		}
		ents = withAliases(ents, tk, refs[i], merged)
	}
	if conflict {
		ids := make([]string, len(targets))
		for i, t := range targets {
			ids[i] = t.Value
		}
		p.rec(ap.adv.String(), TypeAliasConflict, aliasesProp, "", change.EncodeValue(ids))
		p.changed = true
	}
	n.Entities = ents
	return n
}

// merge plans the merge of the advisory-keyed node from into into.
func (p *planner) merge(from, into resolve.Key) {
	p.rec(into.String(), TypeVulnerabilityMerged, "",
		change.EncodeValue([]string{from.String(), into.String()}), change.EncodeValue(into.String()))
	p.merges = append(p.merges, MergeWrite{From: from, Into: into})
	p.gone[from] = true
	delete(p.nodes, from)
	kept := p.nord[:0]
	for _, n := range p.nord {
		if n.key != from {
			kept = append(kept, n)
		}
	}
	p.nord = kept
	p.recom[into.Value] = struct{}{}
	p.changed = true
}

// withAliases sets the aliases property on the entity of key tk, adding an
// entity (with ref) when the record has none.
func withAliases(ents []source.Entity, tk resolve.Key, ref source.Ref, aliases []string) []source.Entity {
	for i, e := range ents {
		if k, err := resolve.Resolve(e.Ref); err == nil && k == tk {
			props := clone(e.Props)
			if len(aliases) > 0 {
				props[aliasesProp] = aliases
			}
			ents[i].Props = props
			return ents
		}
	}
	e := source.Entity{Ref: ref}
	if len(aliases) > 0 {
		e.Props = map[string]any{aliasesProp: aliases}
	}
	return append(ents, e)
}

// unionAliases returns cur followed by the new values of add, without
// duplicates, without self, at most MaxAliases. Existing aliases keep their
// order and are never dropped by the cap.
func unionAliases(self string, cur, add []string) []string {
	out := make([]string, 0, len(cur)+len(add))
	seen := map[string]bool{self: true}
	for _, lst := range [][]string{cur, add} {
		for _, a := range lst {
			if a == "" || seen[a] || len(out) >= MaxAliases {
				continue
			}
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

func stringsOf(v any) []string {
	switch x := v.(type) {
	case []string:
		return append([]string(nil), x...)
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// advisoryKeys returns the node keys a record's Advisory adds to the load: the
// advisory-keyed node and the CVE targets.
func advisoryKeys(ap *aliasPlan) []resolve.Key {
	return append([]resolve.Key{ap.adv}, ap.cves...)
}

const (
	cypherMergeRead = "MATCH (f:Vulnerability {cveID: $from}) RETURN properties(f) AS props"
	cypherMergeInto = "MERGE (t:Vulnerability {cveID: $into}) " +
		"ON CREATE SET t.exploitability = 0, t.exploitDate = [] RETURN properties(t) AS props"
	cypherMergeRels = "MATCH (f:Vulnerability {cveID: $from})-[r]-(o) " +
		"RETURN elementId(r) AS rid, type(r) AS typ, startNode(r) = f AS outgoing, " +
		"elementId(o) AS oid, (o:Vulnerability AND o.cveID = $into) AS toTarget, (o = f) AS self, properties(r) AS props"
	cypherMergeDelete = "MATCH (f:Vulnerability {cveID: $from}) DETACH DELETE f"
	cypherMergeCheck  = "MATCH (f:Vulnerability {cveID: $from}) RETURN count(f) AS n"
)

// mergeVulnerability moves everything of the Vulnerability w.From onto
// w.Into and deletes it: relationships keep their properties and provenance
// (those the target already has with the same type, other end, and identity
// are skipped), aliases and sources are unioned, and properties the target
// lacks are copied. A missing From node means the merge was already done.
func mergeVulnerability(ctx context.Context, tx neo4j.ManagedTransaction, w MergeWrite) error {
	fromP := map[string]any{"from": w.From.Value, "into": w.Into.Value}
	res, err := tx.Run(ctx, cypherMergeRead, fromP)
	if err != nil {
		return err
	}
	recs, err := res.Collect(ctx)
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		return nil
	}
	fprops, _ := recs[0].AsMap()["props"].(map[string]any)

	res, err = tx.Run(ctx, cypherMergeInto, fromP)
	if err != nil {
		return err
	}
	recs, err = res.Collect(ctx)
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		return fmt.Errorf("target %s not found", w.Into)
	}
	tprops, _ := recs[0].AsMap()["props"].(map[string]any)

	res, err = tx.Run(ctx, cypherMergeRels, fromP)
	if err != nil {
		return err
	}
	rels, err := res.Collect(ctx)
	if err != nil {
		return err
	}
	for _, r := range rels {
		m := r.AsMap()
		if self, _ := m["self"].(bool); self {
			continue
		}
		if tt, _ := m["toTarget"].(bool); tt {
			continue // would become a self-loop
		}
		if err := moveRel(ctx, tx, w, m); err != nil {
			return err
		}
	}

	set := map[string]any{}
	for k, v := range fprops {
		switch k {
		case "cveID", "aliases", "sources", "exploitability", "exploitDate":
		default:
			if _, ok := tprops[k]; !ok {
				set[k] = v
			}
		}
	}
	set["aliases"] = unionAliases(w.Into.Value, stringsOf(tprops["aliases"]),
		append([]string{w.From.Value}, stringsOf(fprops["aliases"])...))
	set["sources"] = unionStrings(stringsOf(tprops["sources"]), stringsOf(fprops["sources"]))
	if err := run(ctx, tx, "MATCH (t:Vulnerability {cveID: $into}) SET t += $props",
		map[string]any{"into": w.Into.Value, "props": set}); err != nil {
		return err
	}
	if err := run(ctx, tx, cypherMergeDelete, fromP); err != nil {
		return err
	}
	res, err = tx.Run(ctx, cypherMergeCheck, fromP)
	if err != nil {
		return err
	}
	chk, err := res.Collect(ctx)
	if err != nil {
		return err
	}
	if len(chk) == 0 {
		return fmt.Errorf("merge check returned no row")
	}
	if n, _ := chk[0].AsMap()["n"].(int64); n != 0 {
		return fmt.Errorf("%s still exists after the merge", w.From)
	}
	return nil
}

// moveRel copies one relationship of the advisory node onto the target node
// unless the target already has it. The original is removed with the node.
func moveRel(ctx context.Context, tx neo4j.ManagedTransaction, w MergeWrite, m map[string]any) error {
	typ, _ := m["typ"].(string)
	rt, ok := model.RelByName(typ)
	if !ok {
		return fmt.Errorf("unknown relationship type %q", typ)
	}
	props, _ := m["props"].(map[string]any)
	outgoing, _ := m["outgoing"].(bool)
	params := map[string]any{"into": w.Into.Value, "oid": m["oid"], "props": props}
	pat := "(t)-[x:`%s`]->(o)"
	if !outgoing {
		pat = "(t)<-[x:`%s`]-(o)"
	}
	cond := ""
	for i, k := range rt.Identity {
		name := fmt.Sprintf("id%d", i)
		cond += fmt.Sprintf(" AND x.`%s` = $%s", k, name)
		params[name] = props[k]
	}
	exists := fmt.Sprintf("MATCH (t:Vulnerability {cveID: $into}) MATCH (o) WHERE elementId(o) = $oid "+
		"OPTIONAL MATCH "+pat+" WHERE true%s RETURN count(x) AS n", typ, cond)
	res, err := tx.Run(ctx, exists, params)
	if err != nil {
		return err
	}
	recs, err := res.Collect(ctx)
	if err != nil {
		return err
	}
	if len(recs) > 0 {
		if n, _ := recs[0].AsMap()["n"].(int64); n > 0 {
			return nil
		}
	}
	create := "(t)-[x:`%s`]->(o)"
	if !outgoing {
		create = "(t)<-[x:`%s`]-(o)"
	}
	return run(ctx, tx, fmt.Sprintf("MATCH (t:Vulnerability {cveID: $into}) MATCH (o) WHERE elementId(o) = $oid "+
		"CREATE "+create+" SET x = $props", typ), params)
}

func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range [][]string{a, b} {
		for _, s := range l {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}
