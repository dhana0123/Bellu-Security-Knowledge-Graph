import { describe, expect, it } from 'vitest';
import { merge } from './merge';
import { toggle, visibility } from './filter';
import type { GraphNode } from '../api/types';

const n = (id: string, type = 'Vulnerability'): GraphNode => ({ id, type, key: id, label: id });
const e = (s: string, t: string, type = 'REL') => ({ id: `${s}|${type}|${t}`, source: s, target: t, type });

describe('merge', () => {
  it('keeps existing nodes, dedupes, and adds only edges between displayed nodes', () => {
    const cur = { nodes: [n('a')], edges: [] };
    const r = merge(cur, { nodes: [n('a'), n('b')], edges: [e('a', 'b'), e('a', 'zz'), e('a', 'b')], truncated: false });
    expect(r.graph.nodes.map((x) => x.id)).toEqual(['a', 'b']);
    expect(r.graph.edges).toHaveLength(1);
    expect(r.limited).toBe(false);
  });
  it('drops new nodes beyond max and reports limited', () => {
    const cur = { nodes: [n('a'), n('b')], edges: [] };
    const r = merge(cur, { nodes: [n('c'), n('d')], edges: [e('a', 'd')], truncated: false }, 3);
    expect(r.graph.nodes.map((x) => x.id)).toEqual(['a', 'b', 'c']);
    expect(r.graph.edges).toHaveLength(0);
    expect(r.limited).toBe(true);
  });
  it('is limited when the response was truncated', () => {
    expect(merge({ nodes: [], edges: [] }, { nodes: [n('a')], edges: [], truncated: true }).limited).toBe(true);
  });
});

describe('visibility', () => {
  it('hides nodes, relationships, and edges touching hidden nodes', () => {
    const g = { nodes: [n('a'), n('b', 'Exploit')], edges: [e('a', 'b', 'X'), e('a', 'a', 'Y')] };
    const v = visibility(g, { nodeTypes: new Set(['Exploit']), relTypes: new Set() });
    expect([...v.nodes]).toEqual(['a']);
    expect([...v.edges]).toEqual(['a|Y|a']);
    expect([...visibility(g, { nodeTypes: new Set(), relTypes: new Set(['X']) }).edges]).toEqual(['a|Y|a']);
  });
  it('toggle adds and removes', () => {
    expect([...toggle(new Set(['a']), 'a')]).toEqual([]);
    expect([...toggle(new Set(), 'a')]).toEqual(['a']);
  });
});
