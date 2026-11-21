import type { GraphEdge, GraphNode, Neighborhood } from '../api/types';

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export const MAX_NODES = 300;

/**
 * Merges an incoming neighborhood into the displayed graph.
 * Existing nodes are kept; new nodes are added in incoming order until max are shown;
 * edges are added only between displayed nodes. `limited` is true when a new node was
 * dropped or the response was truncated.
 */
export function merge(
  current: GraphData,
  incoming: Neighborhood,
  max = MAX_NODES,
): { graph: GraphData; limited: boolean } {
  const nodes = [...current.nodes];
  const ids = new Set(nodes.map((n) => n.id));
  let limited = incoming.truncated;
  for (const n of incoming.nodes) {
    if (ids.has(n.id)) continue;
    if (nodes.length >= max) {
      limited = true;
      continue;
    }
    nodes.push(n);
    ids.add(n.id);
  }
  const edges = [...current.edges];
  const edgeIds = new Set(edges.map((e) => e.id));
  for (const e of incoming.edges) {
    if (edgeIds.has(e.id) || !ids.has(e.source) || !ids.has(e.target)) continue;
    edges.push(e);
    edgeIds.add(e.id);
  }
  return { graph: { nodes, edges }, limited };
}
