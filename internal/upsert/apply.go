package upsert

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/change"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/model"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/provenance"
)

const appendSource = `CASE WHEN %[1]s.sources IS NULL THEN [$src] WHEN $src IN %[1]s.sources THEN %[1]s.sources ELSE %[1]s.sources + $src END`

const cypherChanges = `UNWIND $rows AS row
MERGE (c:Change {id: row.id})
ON CREATE SET c.entityKey = row.entityKey, c.type = row.type, c.field = row.field,
  c.oldValue = row.oldValue, c.newValue = row.newValue, c.source = row.source,
  c.runId = row.runId, c.at = datetime(row.at)`

// nodeCypher returns the node upsert statement for a label. Label and key
// property come from the model registry, never from input.
func nodeCypher(l model.Label) string {
	return fmt.Sprintf("UNWIND $rows AS row\nMERGE (n:`%s` {`%s`: row.key})\nSET n += row.props, n.sources = %s",
		l.Name, l.Key, fmt.Sprintf(appendSource, "n"))
}

// relCypher returns the relationship upsert statement for a type. The MERGE
// pattern includes the identity properties.
func relCypher(rt model.RelType) (string, error) {
	from, ok1 := model.LabelByName(rt.From)
	to, ok2 := model.LabelByName(rt.To)
	if !ok1 || !ok2 {
		return "", fmt.Errorf("upsert: relationship %s has unknown endpoint labels", rt.Name)
	}
	var id []string
	for _, k := range rt.Identity {
		id = append(id, fmt.Sprintf("`%s`: row.key.`%s`", k, k))
	}
	pat := ""
	if len(id) > 0 {
		pat = " {" + strings.Join(id, ", ") + "}"
	}
	return fmt.Sprintf("UNWIND $rows AS row\nMATCH (a:`%s` {`%s`: row.from})\nMATCH (b:`%s` {`%s`: row.to})\n"+
		"MERGE (a)-[r:`%s`%s]->(b)\nSET r += row.props, r.sources = %s",
		from.Name, from.Key, to.Name, to.Key, rt.Name, pat, fmt.Sprintf(appendSource, "r")), nil
}

func run(ctx context.Context, tx neo4j.ManagedTransaction, cypher string, params map[string]any) error {
	res, err := tx.Run(ctx, cypher, params)
	if err != nil {
		return err
	}
	_, err = res.Consume(ctx)
	return err
}

// Apply writes w and the Change records recs in tx, then recomputes
// exploitability for the affected Vulnerabilities in the same transaction.
// Any error is returned so the caller rolls the transaction back.
func Apply(ctx context.Context, tx neo4j.ManagedTransaction, w Writes, recs []change.Record) error {
	if !provenance.ValidSource(w.Source) {
		return fmt.Errorf("upsert: invalid source %q", w.Source)
	}
	for _, m := range w.Merges {
		if err := mergeVulnerability(ctx, tx, m); err != nil {
			return fmt.Errorf("merge vulnerability %s into %s: %w", m.From, m.Into, err)
		}
	}
	byLabel := map[string][]any{}
	for _, n := range w.Nodes {
		byLabel[n.Key.Label] = append(byLabel[n.Key.Label], map[string]any{"key": n.Key.Value, "props": n.Props})
	}
	labels := make([]string, 0, len(byLabel))
	for l := range byLabel {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	for _, name := range labels {
		l, ok := model.LabelByName(name)
		if !ok {
			return fmt.Errorf("upsert: unknown label %q", name)
		}
		if err := run(ctx, tx, nodeCypher(l), map[string]any{"rows": byLabel[name], "src": w.Source}); err != nil {
			return fmt.Errorf("upsert %s nodes: %w", name, err)
		}
	}
	byType := map[string][]any{}
	for _, r := range w.Rels {
		byType[r.Type] = append(byType[r.Type], map[string]any{
			"from": r.From.Value, "to": r.To.Value, "key": r.Key, "props": r.Props})
	}
	types := make([]string, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, name := range types {
		rt, ok := model.RelByName(name)
		if !ok {
			return fmt.Errorf("upsert: unknown relationship type %q", name)
		}
		q, err := relCypher(rt)
		if err != nil {
			return err
		}
		if err := run(ctx, tx, q, map[string]any{"rows": byType[name], "src": w.Source}); err != nil {
			return fmt.Errorf("upsert %s relationships: %w", name, err)
		}
	}
	if len(recs) > 0 {
		rows := make([]any, 0, len(recs))
		for _, r := range recs {
			id, err := change.NewID(r.At)
			if err != nil {
				return err
			}
			rows = append(rows, map[string]any{
				"id": id, "entityKey": r.EntityKey, "type": r.Type, "field": r.Field,
				"oldValue": r.OldValue, "newValue": r.NewValue, "source": r.Source,
				"runId": r.RunID, "at": r.At.Format(time.RFC3339Nano)})
		}
		if err := run(ctx, tx, cypherChanges, map[string]any{"rows": rows}); err != nil {
			return fmt.Errorf("upsert change records: %w", err)
		}
	}
	if _, err := RecomputeExploitability(ctx, tx, w.RecomputeCVEs); err != nil {
		return fmt.Errorf("recompute exploitability: %w", err)
	}
	return nil
}
