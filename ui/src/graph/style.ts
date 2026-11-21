import type { GraphNode } from '../api/types';

/** One fixed colour per node label, in the style of the VulKG / Neo4j Browser graph. */
export const LABEL_COLORS: Readonly<Record<string, string>> = {
  Vulnerability: '#e5484d',
  Exploit: '#f76b15',
  Author: '#8e4ec6',
  Weakness: '#30a46c',
  Product: '#3e63dd',
  Vendor: '#12a594',
  Domain: '#8b8d98',
};
export const FALLBACK_COLOR = '#687076';
export const LABEL_ORDER: readonly string[] = Object.keys(LABEL_COLORS);
export const EDGE_COLOR = '#5b6577';
export const DIM_COLOR = '#262c38';

export const colorFor = (type: string): string => LABEL_COLORS[type] ?? FALLBACK_COLOR;

/** Caption drawn on a node: its label (or key), shortened to max characters. */
export function captionFor(node: Pick<GraphNode, 'label' | 'key'>, max = 14): string {
  const text = (node.label || node.key || '').trim();
  return text.length <= max ? text : `${text.slice(0, Math.max(1, max - 1))}…`;
}

export interface LegendEntry {
  type: string;
  color: string;
  count: number;
  hidden: boolean;
}

/** Legend chips: the known labels first in a fixed order, then any other label alphabetically. Only labels present are listed. */
export function legendCounts(nodes: readonly { type: string }[], hidden: ReadonlySet<string>): LegendEntry[] {
  const counts = new Map<string, number>();
  for (const n of nodes) counts.set(n.type, (counts.get(n.type) ?? 0) + 1);
  const known = LABEL_ORDER.filter((t) => counts.has(t));
  const other = [...counts.keys()].filter((t) => !LABEL_ORDER.includes(t)).sort();
  return [...known, ...other].map((type) => ({
    type,
    color: colorFor(type),
    count: counts.get(type) ?? 0,
    hidden: hidden.has(type),
  }));
}
