package upsert

import (
	"context"
	"fmt"
	"sort"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/model"
	"github.com/bellu/bskg/internal/resolve"
	"github.com/bellu/bskg/internal/source"
)

// Load reads the existing nodes and relationships Plan needs for b: the nodes
// the batch names, and the outgoing relationships of the types the batch
// writes or owns (plus EXPLOITS of the Exploits in the batch, for date
// changes).
func Load(ctx context.Context, tx neo4j.ManagedTransaction, b Batch) (State, error) {
	nodeKeys := map[string]map[string]struct{}{} // label -> values
	relFrom := map[string]map[string]struct{}{}  // rel type -> start values
	addNode := func(r source.Ref) (resolve.Key, bool) {
		k, err := resolve.Resolve(r)
		if err != nil {
			return k, false
		}
		if nodeKeys[k.Label] == nil {
			nodeKeys[k.Label] = map[string]struct{}{}
		}
		nodeKeys[k.Label][k.Value] = struct{}{}
		return k, true
	}
	addFrom := func(typ string, k resolve.Key) {
		if relFrom[typ] == nil {
			relFrom[typ] = map[string]struct{}{}
		}
		relFrom[typ][k.Value] = struct{}{}
	}
	for _, d := range b {
		n, ap := expandAdvisory(d.N)
		d.N = n
		if ap != nil {
			for _, k := range advisoryKeys(ap) {
				addNode(source.Ref{Kind: refKindOf(k), Raw: k.Value})
			}
		}
		for _, r := range d.N.Gate {
			addNode(r)
		}
		for _, e := range d.N.Entities {
			if k, ok := addNode(e.Ref); ok && k.Label == labelExploit {
				addFrom(exploitsType, k)
			}
		}
		for _, r := range d.N.Rels {
			if k, ok := addNode(r.From); ok {
				addFrom(r.Type, k)
			}
			addNode(r.To)
		}
		if d.N.Anchor != nil {
			if k, ok := addNode(*d.N.Anchor); ok {
				for _, o := range d.N.Owned {
					addFrom(o.Type, k)
				}
			}
		}
	}
	st := State{Nodes: map[resolve.Key]map[string]any{}, Rels: map[RelID]map[string]any{}}
	for _, label := range sortedSet(nodeKeys) {
		l, ok := model.LabelByName(label)
		if !ok {
			continue
		}
		q := fmt.Sprintf("UNWIND $keys AS k MATCH (n:`%s` {`%s`: k}) RETURN k, properties(n) AS props", l.Name, l.Key)
		res, err := tx.Run(ctx, q, map[string]any{"keys": setList(nodeKeys[label])})
		if err != nil {
			return st, err
		}
		recs, err := res.Collect(ctx)
		if err != nil {
			return st, err
		}
		for _, r := range recs {
			k, _ := r.Get("k")
			props, _ := r.Get("props")
			ks, _ := k.(string)
			pm, _ := props.(map[string]any)
			st.Nodes[resolve.Key{Label: l.Name, Prop: l.Key, Value: ks}] = pm
		}
	}
	for _, typ := range sortedSet(relFrom) {
		rt, ok := model.RelByName(typ)
		if !ok {
			continue
		}
		from, _ := model.LabelByName(rt.From)
		to, _ := model.LabelByName(rt.To)
		q := fmt.Sprintf("UNWIND $keys AS k MATCH (a:`%s` {`%s`: k})-[r:`%s`]->(b:`%s`) RETURN a.`%s` AS f, b.`%s` AS t, properties(r) AS props",
			from.Name, from.Key, rt.Name, to.Name, from.Key, to.Key)
		res, err := tx.Run(ctx, q, map[string]any{"keys": setList(relFrom[typ])})
		if err != nil {
			return st, err
		}
		recs, err := res.Collect(ctx)
		if err != nil {
			return st, err
		}
		for _, r := range recs {
			f, _ := r.Get("f")
			t, _ := r.Get("t")
			props, _ := r.Get("props")
			fs, _ := f.(string)
			ts, _ := t.(string)
			pm, _ := props.(map[string]any)
			id := RelID{
				Type:  typ,
				From:  resolve.Key{Label: from.Name, Prop: from.Key, Value: fs},
				To:    resolve.Key{Label: to.Name, Prop: to.Key, Value: ts},
				Ident: ident(rt.Identity, pm),
			}
			st.Rels[id] = pm
		}
	}
	return st, nil
}

func sortedSet(m map[string]map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func setList(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// refKindOf returns the ref kind that resolves to a Vulnerability key.
func refKindOf(k resolve.Key) source.RefKind {
	if _, err := resolve.CVE(k.Value); err == nil {
		return source.RefCVE
	}
	return source.RefAdvisory
}
