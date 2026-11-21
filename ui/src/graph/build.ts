import Graph from 'graphology';
import forceAtlas2 from 'graphology-layout-forceatlas2';
import type { GraphEdge } from '../api/types';
import type { GraphData } from './merge';
import { EDGE_COLOR, captionFor, colorFor } from './style';

export const NODE_SIZE = 18;

export interface NodeAttrs {
  x: number;
  y: number;
  size: number;
  color: string;
  label: string;
  type: string;
  key: string;
}
export interface EdgeAttrs {
  size: number;
  color: string;
  label: string;
}
export type BskgGraph = Graph<NodeAttrs, EdgeAttrs>;

export interface DisplayEdge {
  key: string;
  source: string;
  target: string;
  label: string;
}

/**
 * One drawn edge per ordered node pair: self-loops are dropped, and several relationships
 * in the same direction are merged into one edge labelled with all their types.
 */
export function collapseEdges(edges: readonly GraphEdge[]): DisplayEdge[] {
  const byPair = new Map<string, { key: string; source: string; target: string; types: string[] }>();
  for (const e of edges) {
    if (e.source === e.target) continue;
    const pair = `${e.source}>${e.target}`;
    const cur = byPair.get(pair);
    if (!cur) byPair.set(pair, { key: pair, source: e.source, target: e.target, types: [e.type] });
    else if (!cur.types.includes(e.type)) cur.types.push(e.type);
  }
  return [...byPair.values()].map((p) => ({ key: p.key, source: p.source, target: p.target, label: p.types.join(', ') }));
}

/** Deterministic pseudo-random point in [0,1) pair from a string, so layouts repeat across loads. */
function hash2(id: string): [number, number] {
  let h = 2166136261;
  for (let i = 0; i < id.length; i++) h = Math.imul(h ^ id.charCodeAt(i), 16777619);
  const a = (h >>> 0) / 4294967296;
  h = Math.imul(h ^ (h >>> 15), 2246822507);
  const b = (h >>> 0) / 4294967296;
  return [a, b];
}

/** Start position for a new node: near an already placed neighbour if there is one, otherwise on a ring around the origin. */
export function seedPosition(id: string, anchor?: { x: number; y: number }): { x: number; y: number } {
  const [a, b] = hash2(id);
  const angle = a * Math.PI * 2;
  if (anchor) {
    const r = 20 + b * 30;
    return { x: anchor.x + r * Math.cos(angle), y: anchor.y + r * Math.sin(angle) };
  }
  const r = 40 + b * 160;
  return { x: r * Math.cos(angle), y: r * Math.sin(angle) };
}

export function newGraph(): BskgGraph {
  return new Graph<NodeAttrs, EdgeAttrs>({ type: 'directed', multi: false });
}

/**
 * Brings the graphology graph in line with the API data in place. Existing nodes keep their
 * positions, new nodes are seeded next to a neighbour, and nodes or edges that are no longer
 * in the data are removed. Returns the ids of the nodes that were added.
 */
export function syncGraph(graph: BskgGraph, data: GraphData): string[] {
  const want = new Set(data.nodes.map((n) => n.id));
  const wantEdges = collapseEdges(data.edges.filter((e) => want.has(e.source) && want.has(e.target)));
  const wantKeys = new Set(wantEdges.map((e) => e.key));
  for (const k of graph.edges().filter((k) => !wantKeys.has(k))) graph.dropEdge(k);
  for (const id of graph.nodes().filter((id) => !want.has(id))) graph.dropNode(id);

  const added: string[] = [];
  const neighbourOf = new Map<string, string>();
  for (const e of wantEdges) {
    if (!neighbourOf.has(e.source)) neighbourOf.set(e.source, e.target);
    if (!neighbourOf.has(e.target)) neighbourOf.set(e.target, e.source);
  }
  for (const n of data.nodes) {
    if (graph.hasNode(n.id)) continue;
    const other = neighbourOf.get(n.id);
    const anchor = other && graph.hasNode(other) ? graph.getNodeAttributes(other) : undefined;
    graph.addNode(n.id, {
      ...seedPosition(n.id, anchor),
      size: NODE_SIZE,
      color: colorFor(n.type),
      label: captionFor(n),
      type: n.type,
      key: n.key,
    });
    added.push(n.id);
  }
  for (const e of wantEdges) {
    if (graph.hasEdge(e.key)) continue;
    graph.addDirectedEdgeWithKey(e.key, e.source, e.target, { size: 1.5, color: EDGE_COLOR, label: e.label });
  }
  return added;
}

export function buildGraph(data: GraphData): BskgGraph {
  const g = newGraph();
  syncGraph(g, data);
  return g;
}

/** Bounded synchronous ForceAtlas2 iteration count: no worker is used because the CSP forbids blob: workers. */
export function layoutIterations(order: number): number {
  if (order < 2) return 0;
  return order <= 150 ? 300 : 150;
}

/** Runs ForceAtlas2 from the current positions. Synchronous and bounded. */
export function runLayout(graph: BskgGraph): void {
  const iterations = layoutIterations(graph.order);
  if (iterations === 0) return;
  const settings = {
    ...forceAtlas2.inferSettings(graph),
    gravity: 0.15,
    scalingRatio: 120,
    slowDown: 3,
    strongGravityMode: false,
  };
  forceAtlas2.assign(graph, { iterations, settings });
}
