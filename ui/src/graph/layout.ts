import forceAtlas2 from 'graphology-layout-forceatlas2';
import type { BskgGraph } from './build';
import { LABEL_ORDER } from './style';

// Layout helpers for the whole-graph overview (up to 5,000 nodes). Everything here runs on the
// main thread: the CSP forbids blob: workers, so ForceAtlas2 runs synchronously when it is cheap
// and in requestAnimationFrame chunks when it would block the page for too long.

/** Smallest and largest node radius for the overview, in screen pixels. */
export const MIN_NODE_SIZE = 3;
export const MAX_NODE_SIZE = 20;

/** Node size from its degree: grows with log2(1 + degree) and is bounded. */
export function degreeSize(degree: number): number {
  const d = Number.isFinite(degree) && degree > 0 ? degree : 0;
  return Math.min(MAX_NODE_SIZE, MIN_NODE_SIZE + 2.5 * Math.log2(1 + d));
}

/** Sets every node's size from its degree. */
export function applyDegreeSizes(graph: BskgGraph): void {
  graph.forEachNode((id) => {
    graph.setNodeAttribute(id, 'size', degreeSize(graph.degree(id)));
  });
}

const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));
/** Distance between neighbouring seeds inside one group, in layout units. */
const SEED_SPACING = 5;

/** Group order: the known labels first in their fixed order, then others alphabetically. */
function groupOrder(types: Iterable<string>): string[] {
  const present = new Set(types);
  const known = LABEL_ORDER.filter((t) => present.has(t));
  const other = [...present].filter((t) => !LABEL_ORDER.includes(t)).sort();
  return [...known, ...other];
}

/**
 * Cheap deterministic start positions: one disc per label, the discs spaced evenly on a ring, and
 * the nodes of a label spread over its disc on a sunflower (golden angle) spiral. No two nodes
 * overlap, which ForceAtlas2 needs, and the result does not depend on random numbers.
 */
export function seedGrouped(nodes: readonly { id: string; type: string }[]): Map<string, { x: number; y: number }> {
  const byType = new Map<string, string[]>();
  for (const n of nodes) {
    const list = byType.get(n.type);
    if (list) list.push(n.id);
    else byType.set(n.type, [n.id]);
  }
  const order = groupOrder(byType.keys());
  const radius = (count: number) => SEED_SPACING * Math.sqrt(count);
  const maxR = Math.max(0, ...order.map((t) => radius(byType.get(t)?.length ?? 0)));
  const ring = order.length > 1 ? (maxR * 1.15) / Math.sin(Math.PI / order.length) : 0;
  const out = new Map<string, { x: number; y: number }>();
  order.forEach((t, gi) => {
    const a = (gi / order.length) * Math.PI * 2;
    const cx = ring * Math.cos(a);
    const cy = ring * Math.sin(a);
    (byType.get(t) ?? []).forEach((id, i) => {
      const r = SEED_SPACING * Math.sqrt(i + 0.5);
      const th = i * GOLDEN_ANGLE;
      out.set(id, { x: cx + r * Math.cos(th), y: cy + r * Math.sin(th) });
    });
  });
  return out;
}

/**
 * Moves nodes without any edge onto a sunflower spiral just outside the connected part, so a few
 * orphans seeded far away do not shrink the rest when the camera fits the graph.
 */
export function packIsolated(graph: BskgGraph): void {
  const lone: string[] = [];
  let sx = 0;
  let sy = 0;
  let n = 0;
  graph.forEachNode((id, a) => {
    if (graph.degree(id) === 0) lone.push(id);
    else {
      sx += a.x;
      sy += a.y;
      n++;
    }
  });
  if (lone.length === 0 || n === 0) return;
  const cx = sx / n;
  const cy = sy / n;
  const dists: number[] = [];
  graph.forEachNode((id, a) => {
    if (graph.degree(id) > 0) dists.push(Math.hypot(a.x - cx, a.y - cy));
  });
  dists.sort((a, b) => a - b);
  // The 95th percentile, so a few far-flung leaves do not push the orphans out of view.
  const reach = dists[Math.floor(dists.length * 0.95)] ?? 0;
  const start = reach * 1.1 + SEED_SPACING;
  lone.sort().forEach((id, i) => {
    const th = i * GOLDEN_ANGLE;
    const r = start + SEED_SPACING * Math.sqrt(i + 0.5) * 0.5;
    graph.setNodeAttribute(id, 'x', cx + r * Math.cos(th));
    graph.setNodeAttribute(id, 'y', cy + r * Math.sin(th));
  });
}

/** Above this many nodes the overview uses Barnes-Hut and the inferred settings. */
const LARGE = 150;

/** ForceAtlas2 iterations for a graph of the given size (more iterations for small graphs, which are cheap). */
export function overviewIterations(order: number): number {
  if (order < 2) return 0;
  if (order <= LARGE) return 300;
  if (order <= 1000) return 250;
  if (order <= 3000) return 200;
  return 150;
}

export function layoutSettingsFor(graph: BskgGraph) {
  const inferred = forceAtlas2.inferSettings(graph);
  if (graph.order <= LARGE) {
    return { ...inferred, gravity: 0.15, scalingRatio: 120, slowDown: 3, strongGravityMode: false };
  }
  return { ...inferred, gravity: 1, scalingRatio: 10, slowDown: 2, strongGravityMode: false, barnesHutOptimize: graph.order > 300 };
}

export interface LayoutPlan {
  /** True when the remaining iterations must be spread over animation frames. */
  chunked: boolean;
  /** Iterations to run per animation frame (the whole remainder when not chunked). */
  chunk: number;
}

/** Time budget for a blocking layout, in milliseconds. */
export const SYNC_BUDGET_MS = 2000;
/** Target duration of one animation-frame chunk, in milliseconds. */
export const FRAME_BUDGET_MS = 24;

/**
 * Decides between a blocking run and animation-frame chunks from the measured cost of one iteration.
 * A run is blocking when its estimated duration stays within the budget.
 */
export function planLayout(
  perIterationMs: number,
  iterations: number,
  budgetMs: number = SYNC_BUDGET_MS,
  frameMs: number = FRAME_BUDGET_MS,
): LayoutPlan {
  const per = Number.isFinite(perIterationMs) && perIterationMs > 0 ? perIterationMs : 0;
  if (iterations <= 0 || per * iterations <= budgetMs) return { chunked: false, chunk: Math.max(0, iterations) };
  return { chunked: true, chunk: Math.max(1, Math.floor(frameMs / per)) };
}

export interface LayoutEnv {
  now(): number;
  requestFrame(cb: () => void): number;
  cancelFrame(handle: number): void;
}

export const browserEnv: LayoutEnv = {
  now: () => performance.now(),
  requestFrame: (cb) => requestAnimationFrame(() => cb()),
  cancelFrame: (h) => cancelAnimationFrame(h),
};

export interface LayoutRun {
  /** Resolves true when all iterations ran, false when cancelled. */
  done: Promise<boolean>;
  cancel(): void;
  /** Milliseconds spent running ForceAtlas2 on the main thread so far. */
  readonly elapsedMs: number;
  /** True when the run used animation-frame chunks. */
  readonly chunked: boolean;
}

/** Iterations used to measure the cost of one iteration. */
const PROBE_ITERATIONS = 5;

/**
 * Runs ForceAtlas2 for `iterations` from the current positions. A few probe iterations measure the
 * per-iteration cost; if the rest would block the main thread for more than the budget, they run in
 * animation-frame chunks and `onFrame(done, total)` is called after each one so the caller can redraw.
 */
export function runLayoutAsync(
  graph: BskgGraph,
  iterations: number,
  opts: {
    env?: LayoutEnv;
    budgetMs?: number;
    frameMs?: number;
    onFrame?: (done: number, total: number) => void;
    step?: (graph: BskgGraph, iterations: number) => void;
  } = {},
): LayoutRun {
  const env = opts.env ?? browserEnv;
  const settings = layoutSettingsFor(graph);
  const step = opts.step ?? ((g, n) => forceAtlas2.assign(g, { iterations: n, settings }));
  let cancelled = false;
  let handle: number | null = null;
  let elapsed = 0;
  let chunked = false;
  let resolveRaw: (v: boolean) => void = () => undefined;
  const done = new Promise<boolean>((r) => {
    resolveRaw = r;
  });
  const resolve = (v: boolean) => {
    if (v) packIsolated(graph);
    resolveRaw(v);
  };
  const timed = (n: number) => {
    const t0 = env.now();
    step(graph, n);
    const dt = env.now() - t0;
    elapsed += dt;
    return dt;
  };
  const total = Math.max(0, Math.floor(iterations));
  if (total === 0 || graph.order < 2) {
    resolve(true);
  } else {
    const probe = Math.min(total, PROBE_ITERATIONS);
    const perIter = timed(probe) / probe;
    let ran = probe;
    const plan = planLayout(perIter, total - probe, opts.budgetMs, opts.frameMs);
    if (!plan.chunked) {
      if (total > probe) timed(total - probe);
      opts.onFrame?.(total, total);
      resolve(true);
    } else {
      chunked = true;
      const frame = () => {
        handle = null;
        if (cancelled) return;
        const n = Math.min(plan.chunk, total - ran);
        timed(n);
        ran += n;
        opts.onFrame?.(ran, total);
        if (ran >= total) resolve(true);
        else handle = env.requestFrame(frame);
      };
      opts.onFrame?.(ran, total);
      handle = env.requestFrame(frame);
    }
  }
  return {
    done,
    cancel() {
      if (cancelled) return;
      cancelled = true;
      if (handle !== null) env.cancelFrame(handle);
      handle = null;
      resolve(false);
    },
    get elapsedMs() {
      return elapsed;
    },
    get chunked() {
      return chunked;
    },
  };
}
