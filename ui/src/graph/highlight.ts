import { collapseEdges } from './build';
import type { GraphData } from './merge';

export interface Selection {
  selected: string;
  nodes: ReadonlySet<string>;
  edges: ReadonlySet<string>;
}

/** The selected node, its direct neighbours (either edge direction) and the drawn edges (collapseEdges keys) touching it. Null when the node is not in the graph. */
export function selectionFor(g: GraphData, id: string): Selection | null {
  if (!g.nodes.some((n) => n.id === id)) return null;
  const nodes = new Set<string>([id]);
  const edges = new Set<string>();
  for (const e of collapseEdges(g.edges)) {
    if (e.source !== id && e.target !== id) continue;
    edges.add(e.key);
    nodes.add(e.source);
    nodes.add(e.target);
  }
  return { selected: id, nodes, edges };
}

export type Emphasis = 'normal' | 'selected' | 'neighbour' | 'dim';

export function nodeEmphasis(sel: Selection | null, id: string): Emphasis {
  if (!sel) return 'normal';
  if (id === sel.selected) return 'selected';
  return sel.nodes.has(id) ? 'neighbour' : 'dim';
}

export function edgeEmphasis(sel: Selection | null, id: string): 'normal' | 'neighbour' | 'dim' {
  if (!sel) return 'normal';
  return sel.edges.has(id) ? 'neighbour' : 'dim';
}
