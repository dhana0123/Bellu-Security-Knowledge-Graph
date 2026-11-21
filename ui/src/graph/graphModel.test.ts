import { describe, expect, it } from 'vitest';
import type { GraphNode } from '../api/types';
import { buildGraph, collapseEdges, layoutIterations, runLayout, seedPosition, syncGraph } from './build';
import { normalizeCveId } from './entry';
import { edgeEmphasis, nodeEmphasis, selectionFor } from './highlight';
import { FALLBACK_COLOR, LABEL_COLORS, captionFor, colorFor, legendCounts } from './style';
import { severityOf } from '../common/severity';

const n = (id: string, type = 'Vulnerability', label = id): GraphNode => ({ id, type, key: id, label });
const e = (s: string, t: string, type = 'REL') => ({ id: `${s}|${type}|${t}`, source: s, target: t, type });

describe('colour and caption mapping', () => {
  it('has a fixed colour per known label and a fallback for others', () => {
    for (const t of ['Vulnerability', 'Exploit', 'Author', 'Weakness', 'Product', 'Vendor', 'Domain']) {
      expect(colorFor(t)).toBe(LABEL_COLORS[t]);
    }
    expect(new Set(Object.values(LABEL_COLORS)).size).toBe(7);
    expect(colorFor('Mystery')).toBe(FALLBACK_COLOR);
  });
  it('shortens long captions and falls back to the key', () => {
    expect(captionFor({ label: 'CVE-2021-44228', key: 'k' })).toBe('CVE-2021-44228');
    expect(captionFor({ label: 'Apache HTTP Server', key: 'k' })).toBe('Apache HTTP S…');
    expect(captionFor({ label: 'short', key: 'k' })).toBe('short');
    expect(captionFor({ label: '', key: 'key1' })).toBe('key1');
  });
});

describe('legendCounts', () => {
  it('counts per label in a fixed order, marks hidden ones, and lists unknown labels last', () => {
    const nodes = [n('a', 'Product'), n('b', 'Vulnerability'), n('c', 'Vulnerability'), n('d', 'Zed'), n('e', 'Alpha')];
    const l = legendCounts(nodes, new Set(['Product']));
    expect(l.map((x) => [x.type, x.count, x.hidden])).toEqual([
      ['Vulnerability', 2, false],
      ['Product', 1, true],
      ['Alpha', 1, false],
      ['Zed', 1, false],
    ]);
    expect(l[0]?.color).toBe(LABEL_COLORS.Vulnerability);
  });
});

describe('neighbour highlight', () => {
  const g = { nodes: [n('a'), n('b'), n('c'), n('d')], edges: [e('a', 'b'), e('c', 'a', 'X'), e('b', 'd')] };
  it('selects the node, both-direction neighbours and incident edges only', () => {
    const s = selectionFor(g, 'a');
    expect([...(s?.nodes ?? [])].sort()).toEqual(['a', 'b', 'c']);
    expect([...(s?.edges ?? [])].sort()).toEqual(['a>b', 'c>a']);
  });
  it('returns null for an unknown node', () => {
    expect(selectionFor(g, 'zz')).toBeNull();
  });
  it('classifies emphasis', () => {
    const s = selectionFor(g, 'a');
    expect(nodeEmphasis(s, 'a')).toBe('selected');
    expect(nodeEmphasis(s, 'b')).toBe('neighbour');
    expect(nodeEmphasis(s, 'd')).toBe('dim');
    expect(nodeEmphasis(null, 'd')).toBe('normal');
    expect(edgeEmphasis(s, 'a>b')).toBe('neighbour');
    expect(edgeEmphasis(s, 'b>d')).toBe('dim');
    expect(edgeEmphasis(null, 'b>d')).toBe('normal');
  });
});

describe('graphology graph building', () => {
  it('builds typed nodes with colour, caption, finite positions and labelled directed edges', () => {
    const g = buildGraph({ nodes: [n('a', 'Vulnerability', 'CVE-1'), n('b', 'Exploit')], edges: [e('a', 'b', 'HAS_EXPLOIT')] });
    expect(g.order).toBe(2);
    expect(g.getNodeAttribute('a', 'color')).toBe(LABEL_COLORS.Vulnerability);
    expect(g.getNodeAttribute('b', 'type')).toBe('Exploit');
    expect(Number.isFinite(g.getNodeAttribute('a', 'x'))).toBe(true);
    expect(g.type).toBe('directed');
    expect(g.getEdgeAttribute('a>b', 'label')).toBe('HAS_EXPLOIT');
    expect(g.source('a>b')).toBe('a');
  });
  it('drops self-loops and merges parallel same-direction edges into one label', () => {
    const c = collapseEdges([e('a', 'a', 'S'), e('a', 'b', 'X'), e('a', 'b', 'Y'), e('b', 'a', 'Z')]);
    expect(c.map((x) => [x.key, x.label])).toEqual([
      ['a>b', 'X, Y'],
      ['b>a', 'Z'],
    ]);
  });
  it('keeps existing positions on sync, seeds new nodes near a neighbour, and removes stale nodes', () => {
    const g = buildGraph({ nodes: [n('a')], edges: [] });
    g.setNodeAttribute('a', 'x', 500);
    g.setNodeAttribute('a', 'y', -300);
    const added = syncGraph(g, { nodes: [n('a'), n('b')], edges: [e('a', 'b')] });
    expect(added).toEqual(['b']);
    expect(g.getNodeAttribute('a', 'x')).toBe(500);
    expect(Math.hypot(g.getNodeAttribute('b', 'x') - 500, g.getNodeAttribute('b', 'y') + 300)).toBeLessThan(60);
    syncGraph(g, { nodes: [n('b')], edges: [] });
    expect(g.nodes()).toEqual(['b']);
    expect(g.size).toBe(0);
  });
  it('seeds deterministically', () => {
    expect(seedPosition('x')).toEqual(seedPosition('x'));
    expect(seedPosition('x')).not.toEqual(seedPosition('y'));
  });
  it('runs a bounded synchronous layout from current positions without NaN', () => {
    const g = buildGraph({ nodes: [n('a'), n('b'), n('c')], edges: [e('a', 'b'), e('b', 'c')] });
    runLayout(g);
    g.forEachNode((_, at) => {
      expect(Number.isFinite(at.x) && Number.isFinite(at.y)).toBe(true);
    });
    expect(layoutIterations(1)).toBe(0);
    expect(layoutIterations(300)).toBeLessThan(layoutIterations(10));
  });
});

describe('graph entry and severity', () => {
  it('normalizes CVE ids', () => {
    expect(normalizeCveId(' cve-2021-44228 ')).toBe('CVE-2021-44228');
    expect(normalizeCveId('CVE-21-1')).toBeNull();
    expect(normalizeCveId('foo')).toBeNull();
  });
  it('maps CVSS v3 scores to severities', () => {
    expect([9.8, 9, 7, 4, 0.1, 0, null, undefined].map(severityOf)).toEqual([
      'CRITICAL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNSCORED', 'UNSCORED', 'UNSCORED',
    ]);
  });
});
