import { describe, expect, it } from 'vitest';
import type { GraphNode } from '../api/types';
import { buildGraph, syncGraph, newGraph } from './build';
import type { BskgGraph } from './build';
import {
  MAX_NODE_SIZE,
  MIN_NODE_SIZE,
  applyDegreeSizes,
  degreeSize,
  overviewIterations,
  packIsolated,
  planLayout,
  runLayoutAsync,
  seedGrouped,
} from './layout';
import type { LayoutEnv } from './layout';

const n = (id: string, type = 'Vulnerability'): GraphNode => ({ id, type, key: id, label: id });
const e = (s: string, t: string) => ({ id: `${s}|R|${t}`, source: s, target: t, type: 'R' });

describe('degreeSize', () => {
  it('starts at the minimum, grows with degree and is bounded', () => {
    expect(degreeSize(0)).toBe(MIN_NODE_SIZE);
    const sizes = [0, 1, 2, 5, 20, 100, 10_000].map(degreeSize);
    for (let i = 1; i < sizes.length; i++) expect(sizes[i]).toBeGreaterThanOrEqual(sizes[i - 1] as number);
    expect(degreeSize(1_000_000)).toBe(MAX_NODE_SIZE);
    expect(degreeSize(-3)).toBe(MIN_NODE_SIZE);
    expect(degreeSize(Number.NaN)).toBe(MIN_NODE_SIZE);
  });

  it('applies to every node of a graph, counting both edge directions', () => {
    const g = buildGraph({ nodes: [n('hub'), n('a'), n('b'), n('c'), n('lone')], edges: [e('hub', 'a'), e('b', 'hub'), e('hub', 'c')] });
    applyDegreeSizes(g);
    expect(g.getNodeAttribute('hub', 'size')).toBe(degreeSize(3));
    expect(g.getNodeAttribute('a', 'size')).toBe(degreeSize(1));
    expect(g.getNodeAttribute('lone', 'size')).toBe(MIN_NODE_SIZE);
    expect(g.getNodeAttribute('hub', 'size')).toBeGreaterThan(g.getNodeAttribute('a', 'size'));
  });

  it('syncGraph with sizeByDegree and edgeSize', () => {
    const g = newGraph();
    syncGraph(g, { nodes: [n('a'), n('b')], edges: [e('a', 'b')] }, { sizeByDegree: true, edgeSize: 0.7 });
    expect(g.getNodeAttribute('a', 'size')).toBe(degreeSize(1));
    expect(g.getEdgeAttribute('a>b', 'size')).toBe(0.7);
    const plain = buildGraph({ nodes: [n('a')], edges: [] });
    expect(plain.getNodeAttribute('a', 'size')).toBe(18);
  });
});

describe('seedGrouped', () => {
  const nodes = [
    ...Array.from({ length: 200 }, (_, i) => n(`v${i}`, 'Vulnerability')),
    ...Array.from({ length: 80 }, (_, i) => n(`p${i}`, 'Product')),
    ...Array.from({ length: 5 }, (_, i) => n(`z${i}`, 'Zed')),
  ];

  it('places every node once at a finite position, deterministically', () => {
    const a = seedGrouped(nodes);
    expect(a.size).toBe(nodes.length);
    for (const p of a.values()) expect(Number.isFinite(p.x) && Number.isFinite(p.y)).toBe(true);
    expect([...seedGrouped(nodes)]).toEqual([...a]);
  });

  it('does not overlap nodes', () => {
    const pts = [...seedGrouped(nodes).values()];
    let min = Infinity;
    for (let i = 0; i < pts.length; i++)
      for (let j = i + 1; j < pts.length; j++) min = Math.min(min, Math.hypot(pts[i]!.x - pts[j]!.x, pts[i]!.y - pts[j]!.y));
    expect(min).toBeGreaterThan(1);
  });

  it('groups by label: each label is closer to its own centroid than to the others', () => {
    const pos = seedGrouped(nodes);
    const centroid = (prefix: string) => {
      const ps = [...pos].filter(([id]) => id.startsWith(prefix)).map(([, p]) => p);
      return { x: ps.reduce((s, p) => s + p.x, 0) / ps.length, y: ps.reduce((s, p) => s + p.y, 0) / ps.length };
    };
    const cv = centroid('v');
    const cp = centroid('p');
    expect(Math.hypot(cv.x - cp.x, cv.y - cp.y)).toBeGreaterThan(20);
    const own = pos.get('v0')!;
    expect(Math.hypot(own.x - cv.x, own.y - cv.y)).toBeLessThan(Math.hypot(own.x - cp.x, own.y - cp.y));
  });

  it('handles empty input and a single label', () => {
    expect(seedGrouped([]).size).toBe(0);
    const one = seedGrouped([n('a'), n('b')]);
    expect(one.size).toBe(2);
    expect(Number.isFinite(one.get('a')!.x)).toBe(true);
  });
});

describe('overviewIterations', () => {
  it('scales down with size and is zero for fewer than two nodes', () => {
    expect(overviewIterations(0)).toBe(0);
    expect(overviewIterations(1)).toBe(0);
    const it5 = [10, 500, 2000, 5000].map(overviewIterations);
    expect(it5.every((v, i) => i === 0 || v <= (it5[i - 1] as number))).toBe(true);
    expect(it5[3]).toBeGreaterThan(0);
  });
});

describe('planLayout', () => {
  it('runs blocking when the estimate is within the budget', () => {
    expect(planLayout(10, 100, 2000)).toEqual({ chunked: false, chunk: 100 });
    expect(planLayout(20, 100, 2000).chunked).toBe(false); // exactly at the budget
  });
  it('chunks when it would block longer than the budget, about one frame worth per chunk', () => {
    expect(planLayout(40, 100, 2000, 24)).toEqual({ chunked: true, chunk: 1 });
    expect(planLayout(2, 2000, 2000, 24)).toEqual({ chunked: true, chunk: 12 });
  });
  it('handles zero work and unusable measurements', () => {
    expect(planLayout(5, 0)).toEqual({ chunked: false, chunk: 0 });
    expect(planLayout(0, 100).chunked).toBe(false);
    expect(planLayout(Number.NaN, 100).chunked).toBe(false);
  });
});

/** A fake clock where each ForceAtlas2 iteration costs msPerIter, and frames run when flushed. */
function fakeEnv(msPerIter: number) {
  let t = 0;
  let nextId = 1;
  const frames = new Map<number, () => void>();
  const calls: number[] = [];
  const env: LayoutEnv = {
    now: () => t,
    requestFrame: (cb) => {
      frames.set(nextId, cb);
      return nextId++;
    },
    cancelFrame: (h) => void frames.delete(h),
  };
  const step = (_g: BskgGraph, iterations: number) => {
    calls.push(iterations);
    t += iterations * msPerIter;
  };
  const flush = () => {
    const [id, cb] = [...frames][0] ?? [];
    if (id === undefined || !cb) return false;
    frames.delete(id);
    cb();
    return true;
  };
  return { env, step, calls, frames, flush };
}

const ring = (count: number): BskgGraph => {
  const nodes = Array.from({ length: count }, (_, i) => n(`n${i}`));
  const edges = nodes.slice(1).map((x, i) => e(`n${i}`, x.id));
  return buildGraph({ nodes, edges });
};

describe('runLayoutAsync', () => {
  it('runs synchronously when cheap', async () => {
    const f = fakeEnv(1);
    const frames: number[] = [];
    const run = runLayoutAsync(ring(10), 100, { env: f.env, step: f.step, onFrame: (d) => frames.push(d) });
    expect(await run.done).toBe(true);
    expect(run.chunked).toBe(false);
    expect(f.calls).toEqual([5, 95]);
    expect(f.frames.size).toBe(0);
    expect(frames).toEqual([100]);
    expect(run.elapsedMs).toBe(100);
  });

  it('uses animation-frame chunks when it would block for more than the budget', async () => {
    const f = fakeEnv(30); // 100 iterations = 3 s
    const progress: number[] = [];
    const run = runLayoutAsync(ring(10), 100, { env: f.env, step: f.step, onFrame: (d) => progress.push(d) });
    expect(run.chunked).toBe(true);
    expect(f.calls).toEqual([5]); // only the probe ran before the first frame
    expect(f.frames.size).toBe(1);
    let frames = 0;
    while (f.flush()) frames++;
    expect(await run.done).toBe(true);
    expect(frames).toBeGreaterThan(1);
    expect(f.calls.reduce((a, b) => a + b, 0)).toBe(100);
    expect(Math.max(...f.calls.slice(1))).toBe(1); // one iteration per 24 ms frame at 30 ms each
    expect(progress.at(-1)).toBe(100);
    expect(progress).toEqual([...progress].sort((a, b) => a - b));
  });

  it('can be cancelled between frames', async () => {
    const f = fakeEnv(30);
    const run = runLayoutAsync(ring(10), 100, { env: f.env, step: f.step });
    f.flush();
    const before = f.calls.length;
    run.cancel();
    expect(f.frames.size).toBe(0);
    expect(await run.done).toBe(false);
    expect(f.flush()).toBe(false);
    expect(f.calls.length).toBe(before);
  });

  it('does nothing for no iterations or fewer than two nodes', async () => {
    const f = fakeEnv(1);
    expect(await runLayoutAsync(ring(10), 0, { env: f.env, step: f.step }).done).toBe(true);
    expect(await runLayoutAsync(ring(1), 50, { env: f.env, step: f.step }).done).toBe(true);
    expect(f.calls).toEqual([]);
  });

  it('runs real ForceAtlas2 on a graph without NaN', async () => {
    const g = ring(60);
    const nodes = g.nodes().map((id) => ({ id, type: 'Vulnerability' }));
    for (const [id, p] of seedGrouped(nodes)) {
      g.setNodeAttribute(id, 'x', p.x);
      g.setNodeAttribute(id, 'y', p.y);
    }
    const run = runLayoutAsync(g, 30);
    expect(await run.done).toBe(true);
    g.forEachNode((_, a) => expect(Number.isFinite(a.x) && Number.isFinite(a.y)).toBe(true));
  });
});

describe('packIsolated', () => {
  it('moves edgeless nodes next to the connected part and leaves connected nodes alone', () => {
    const g = buildGraph({ nodes: [n('a'), n('b'), n('lone1'), n('lone2')], edges: [e('a', 'b')] });
    g.setNodeAttribute('a', 'x', 0);
    g.setNodeAttribute('a', 'y', 0);
    g.setNodeAttribute('b', 'x', 10);
    g.setNodeAttribute('b', 'y', 0);
    g.setNodeAttribute('lone1', 'x', 5000);
    g.setNodeAttribute('lone1', 'y', 5000);
    packIsolated(g);
    expect(g.getNodeAttribute('a', 'x')).toBe(0);
    expect(g.getNodeAttribute('b', 'x')).toBe(10);
    for (const id of ['lone1', 'lone2']) {
      const d = Math.hypot(g.getNodeAttribute(id, 'x') - 5, g.getNodeAttribute(id, 'y'));
      expect(d).toBeLessThan(60);
    }
    expect(g.getNodeAttribute('lone1', 'x')).not.toBe(g.getNodeAttribute('lone2', 'x'));
  });
  it('does nothing when every node is isolated or none is', () => {
    const g = buildGraph({ nodes: [n('a'), n('b')], edges: [] });
    const before = g.getNodeAttributes('a');
    packIsolated(g);
    expect(g.getNodeAttributes('a')).toEqual(before);
  });
});
