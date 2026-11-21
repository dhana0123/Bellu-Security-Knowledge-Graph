import type { GraphData } from './merge';

export interface Hidden {
  nodeTypes: ReadonlySet<string>;
  relTypes: ReadonlySet<string>;
}

/** Visible node and edge ids after hiding types. An edge is hidden when its type or either end is hidden. */
export function visibility(g: GraphData, hidden: Hidden): { nodes: Set<string>; edges: Set<string> } {
  const nodes = new Set(g.nodes.filter((n) => !hidden.nodeTypes.has(n.type)).map((n) => n.id));
  const edges = new Set(
    g.edges.filter((e) => !hidden.relTypes.has(e.type) && nodes.has(e.source) && nodes.has(e.target)).map((e) => e.id),
  );
  return { nodes, edges };
}

export function typesOf(items: { type: string }[]): string[] {
  return [...new Set(items.map((i) => i.type))].sort();
}

export function toggle(set: ReadonlySet<string>, v: string): Set<string> {
  const n = new Set(set);
  if (n.has(v)) n.delete(v);
  else n.add(v);
  return n;
}
