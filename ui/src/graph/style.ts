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
  Repository: '#d6409f',
  FixCommit: '#c9a227',
  Package: '#0091ff',
  AttackPattern: '#ab4aba',
  Technique: '#e93d82',
  AtlasTechnique: '#00a2c7',
};
export const FALLBACK_COLOR = '#687076';
export const LABEL_ORDER: readonly string[] = Object.keys(LABEL_COLORS);
export const EDGE_COLOR = '#5b6577';
export const DIM_COLOR = '#262c38';

export const colorFor = (type: string): string => LABEL_COLORS[type] ?? FALLBACK_COLOR;

/** The "owner/repo" part of a repository URL, or the input when it is not a URL. */
export function repoPath(url: string): string {
  try {
    const p = new URL(url).pathname.replace(/^\/+|\/+$/g, '');
    return p || url;
  } catch {
    return url;
  }
}

/** First 7 characters of a commit sha, taken from the sha property or from the "repoUrl@sha" key. */
export function shortSha(node: Pick<GraphNode, 'key' | 'properties'>): string {
  const prop = node.properties?.sha;
  const sha = typeof prop === 'string' && prop !== '' ? prop : node.key.slice(node.key.lastIndexOf('@') + 1);
  return sha.slice(0, 7);
}

function truncateCaption(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, Math.max(1, max - 1))}…`;
}
/** Caption drawn on a node: its label (or key), shortened to max characters. Repository and FixCommit use their own form. */
export function captionFor(node: Pick<GraphNode, 'label' | 'key'> & Partial<Pick<GraphNode, 'type' | 'properties'>>, max = 14): string {
  if (node.type === 'Repository') {
    const p = repoPath(node.key || node.label);
    return p.length <= 28 ? p : `${p.slice(0, 27)}…`;
  }
  if (node.type === 'FixCommit') return shortSha({ key: node.key, properties: node.properties });
  if (node.type === 'AttackPattern' || node.type === 'Technique' || node.type === 'AtlasTechnique') {
    return truncateCaption((node.key || node.label || '').trim(), max + 4);
  }
  if (node.type === 'Package') {
    const name = node.properties?.name;
    const text = typeof name === 'string' && name.trim() !== '' ? name.trim() : (node.label || node.key || '').trim();
    return truncateCaption(text, max + 4);
  }
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
