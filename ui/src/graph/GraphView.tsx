import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { ApiError } from '../api/errors';
import { useAuth } from '../auth/AuthContext';
import { btn, btnPrimary, card, link, muted, td } from '../common/classes';
import { ErrorMessage, Loading } from '../common/ErrorMessage';
import { graphPath } from '../cve/links';
import { newGraph, runLayout, syncGraph } from './build';
import { CveShortcut } from './GraphEntry';
import { overviewIterations, runLayoutAsync, seedGrouped } from './layout';
import type { LayoutRun } from './layout';
import type { BskgGraph } from './build';
import { toggle, visibility } from './filter';
import { selectionFor } from './highlight';
import { MAX_NODES, merge } from './merge';
import type { GraphData } from './merge';
import { mountRenderer } from './renderer';
import type { Renderer } from './renderer';
import { colorFor, legendCounts } from './style';

const EMPTY: GraphData = { nodes: [], edges: [] };
const NO_RELS: ReadonlySet<string> = new Set();
/** The node list next to the canvas shows at most this many entries. */
const LIST_MAX = 200;
/** Nodes added by one expansion of the overview (the neighborhood request limit). */
const EXPAND_STEP = 300;
/** Thin edges keep the whole-graph view readable. */
const OVERVIEW_EDGE_SIZE = 0.7;
/** Expansions of a large graph only get a short layout pass. */
const EXPAND_ITERATIONS = 40;

interface OverviewInfo {
  truncated: boolean;
  total: { nodes: number; relationships: number };
}

function show(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

export function GraphView() {
  const { type = '', id = '' } = useParams();
  const overviewMode = !type || !id;
  const nav = useNavigate();
  const { client } = useAuth();
  const [graph, setGraph] = useState<GraphData>(EMPTY);
  const [limited, setLimited] = useState(false);
  const [overview, setOverview] = useState<OverviewInfo | null>(null);
  const [depth, setDepth] = useState<1 | 2>(1);
  const [hidden, setHidden] = useState<ReadonlySet<string>>(new Set());
  const [selected, setSelected] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [layoutPct, setLayoutPct] = useState<number | null>(null);
  const [layoutMs, setLayoutMs] = useState<number | null>(null);
  const hostRef = useRef<HTMLDivElement>(null);
  const rendererRef = useRef<Renderer | null>(null);
  const ggRef = useRef<BskgGraph | null>(null);
  const reqId = useRef(0);
  const graphRef = useRef<GraphData>(EMPTY);
  const fitNext = useRef(true);
  /** The next graph state replaces the drawn graph: clear it and seed every node. */
  const freshNext = useRef(true);
  /** The displayed graph is the whole-graph overview (large rendering and layout settings). */
  const largeRef = useRef(false);
  const layoutRef = useRef<LayoutRun | null>(null);
  const expandRef = useRef<(nodeId: string) => void>(() => undefined);

  const loadOverview = useCallback(async () => {
    const my = ++reqId.current;
    setLoading(true);
    try {
      const res = await client.overview(5000);
      if (my !== reqId.current) return; // stale response
      const data: GraphData = { nodes: res.nodes, edges: res.edges };
      graphRef.current = data;
      largeRef.current = true;
      freshNext.current = true;
      fitNext.current = true;
      setOverview({ truncated: res.truncated, total: res.total });
      setLimited(false);
      setGraph(data);
      setError(null);
    } catch (e) {
      if (my !== reqId.current) return;
      setError(e instanceof ApiError ? e : new ApiError('graph overview', 'network error'));
    } finally {
      if (my === reqId.current) setLoading(false);
    }
  }, [client]);

  const load = useCallback(
    async (nodeType: string, key: string, d: 1 | 2, reset: boolean, grow = false) => {
      const my = ++reqId.current;
      setLoading(true);
      try {
        const res = await client.neighborhood({ id: key, type: nodeType, depth: d, limit: EXPAND_STEP });
        if (my !== reqId.current) return; // stale response
        const max = grow ? graphRef.current.nodes.length + EXPAND_STEP : MAX_NODES;
        const m = merge(reset ? EMPTY : graphRef.current, res, max);
        graphRef.current = m.graph;
        if (reset) {
          largeRef.current = false;
          freshNext.current = true;
          fitNext.current = true;
          setOverview(null);
        }
        setGraph(m.graph);
        setLimited((l) => (reset ? m.limited : l || m.limited));
        setError(null);
      } catch (e) {
        if (my !== reqId.current) return;
        setError(e instanceof ApiError ? e : new ApiError('graph', 'network error'));
      } finally {
        if (my === reqId.current) setLoading(false);
      }
    },
    [client],
  );

  // New route or depth: reload from scratch. /graph without parameters loads the whole-graph overview.
  useEffect(() => {
    setSelected(null);
    if (overviewMode) void loadOverview();
    else void load(type, id, depth, true);
    return () => {
      // eslint-disable-next-line react-hooks/exhaustive-deps -- invalidates in-flight responses
      reqId.current++;
    };
  }, [overviewMode, type, id, depth, load, loadOverview]);

  // Create the WebGL renderer once.
  useEffect(() => {
    if (!hostRef.current) return;
    const gg = newGraph();
    ggRef.current = gg;
    const r = mountRenderer(hostRef.current, gg, {
      onSelect: (nodeId) => setSelected(nodeId),
      onExpand: (nodeId) => expandRef.current(nodeId),
    });
    rendererRef.current = r;
    return () => {
      layoutRef.current?.cancel();
      r.kill();
      rendererRef.current = null;
      ggRef.current = null;
    };
  }, []);

  // Merge data into the graphology graph and lay it out. Small graphs: synchronous ForceAtlas2 from the
  // current positions. Overview: grouped seed positions, then ForceAtlas2 (animation-frame chunks if slow).
  useEffect(() => {
    const gg = ggRef.current;
    const r = rendererRef.current;
    if (!gg || !r) return;
    layoutRef.current?.cancel();
    layoutRef.current = null;
    const large = largeRef.current;
    const fresh = freshNext.current;
    freshNext.current = false;
    if (fresh) gg.clear();
    r.setLarge(large);
    const added = syncGraph(
      gg,
      graph,
      large
        ? {
            sizeByDegree: true,
            edgeSize: OVERVIEW_EDGE_SIZE,
            positions: fresh ? seedGrouped(graph.nodes) : undefined,
          }
        : {},
    );
    const finish = () => {
      r.refresh();
      if (fitNext.current && graph.nodes.length > 0) {
        fitNext.current = false;
        r.fit();
      }
    };
    if (added.length === 0 || !large) {
      if (added.length > 0) runLayout(gg);
      setLayoutPct(null);
      finish();
      return;
    }
    const full = overviewIterations(gg.order);
    const run = runLayoutAsync(gg, fresh ? full : Math.min(full, EXPAND_ITERATIONS), {
      onFrame: (done, total) => {
        if (done < total) {
          setLayoutPct(Math.round((done / total) * 100));
          r.refresh();
        }
      },
    });
    layoutRef.current = run;
    void run.done.then((ok) => {
      if (!ok) return;
      setLayoutPct(null);
      setLayoutMs(Math.round(run.elapsedMs));
      finish();
    });
  }, [graph]);

  const selection = useMemo(() => (selected ? selectionFor(graph, selected) : null), [graph, selected]);
  useEffect(() => rendererRef.current?.setSelection(selection), [selection]);
  useEffect(() => rendererRef.current?.setHiddenTypes(hidden), [hidden]);

  const expand = useCallback(
    (nodeId: string) => {
      const n = graphRef.current.nodes.find((x) => x.id === nodeId);
      if (n) void load(n.type, n.key, 1, false, largeRef.current);
    },
    [load],
  );
  useEffect(() => {
    expandRef.current = expand;
  }, [expand]);

  function resetToOverview() {
    if (overviewMode) {
      setSelected(null);
      void loadOverview();
    } else {
      nav('/graph');
    }
  }

  const legend = useMemo(() => legendCounts(graph.nodes, hidden), [graph.nodes, hidden]);
  const shown = useMemo(() => {
    const vis = visibility(graph, { nodeTypes: hidden, relTypes: NO_RELS });
    return graph.nodes.filter((n) => vis.nodes.has(n.id));
  }, [graph, hidden]);
  const sel = graph.nodes.find((n) => n.id === selected) ?? null;
  const props = sel?.properties ? Object.entries(sel.properties) : [];
  return (
    <section>
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold text-slate-50">{overviewMode ? 'Graph' : `Graph: ${type} ${id}`}</h1>
        {type === 'Vulnerability' && !overviewMode && (
          <Link className={link} to={`/cve/${encodeURIComponent(id)}`}>
            Back to CVE detail
          </Link>
        )}
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <CveShortcut />
          {!overviewMode && (
            <>
              <label htmlFor="depth" className="text-sm text-slate-300">
                Depth
              </label>
              <select
                id="depth"
                className="rounded-md border border-slate-600 bg-slate-900 px-2 py-1 text-sm text-slate-100"
                value={depth}
                disabled={loading}
                onChange={(e) => setDepth(e.target.value === '2' ? 2 : 1)}
              >
                <option value="1">1</option>
                <option value="2">2</option>
              </select>
            </>
          )}
          <button type="button" className={btn} disabled={loading} onClick={resetToOverview}>
            Reset to overview
          </button>
          <button type="button" className={btn} onClick={() => rendererRef.current?.fit()}>
            Fit
          </button>
        </div>
      </div>
      <Loading active={loading} />
      <ErrorMessage error={error} />
      {overview && (
        <p role="status" className={`${muted} mb-2 text-sm`}>
          Showing {graph.nodes.length.toLocaleString('en-US')} of {Math.max(overview.total.nodes, graph.nodes.length).toLocaleString('en-US')} nodes
          {layoutPct !== null && ` · arranging the layout, ${layoutPct}%`}
          {layoutPct === null && layoutMs !== null && ` · layout took ${(layoutMs / 1000).toFixed(1)} s`}
        </p>
      )}
      {overview?.truncated && (
        <p role="status" className="mb-2 rounded-md border border-amber-700 bg-amber-950 px-3 py-2 text-sm text-amber-200">
          The graph is larger than the display limit, so this is a subset: the vulnerabilities with the highest exploitability and
          CVSS scores, with the nodes directly connected to them. Enter a CVE id in the toolbar, or double-click a node to load its
          neighbours.
        </p>
      )}
      {overview && !loading && !error && graph.nodes.length === 0 && (
        <p role="status" className={`${muted} mb-2 text-sm`}>
          The graph has no nodes yet.
        </p>
      )}
      {limited && (
        <p role="status" className="mb-2 rounded-md border border-amber-700 bg-amber-950 px-3 py-2 text-sm text-amber-200">
          {overview
            ? 'Some neighbours of the last expanded node were not loaded: it has more neighbours than one request returns.'
            : `Showing a limited view: the graph has more nodes than the ${MAX_NODES} that are displayed.`}
        </p>
      )}
      <ul aria-label="Legend" className="mb-3 flex flex-wrap gap-2">
        {legend.map((l) => (
          <li key={l.type}>
            <button
              type="button"
              aria-pressed={!l.hidden}
              onClick={() => setHidden(toggle(hidden, l.type))}
              className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-sm focus-visible:outline-2 focus-visible:outline-sky-400 ${
                l.hidden ? 'border-slate-700 text-slate-500 line-through' : 'border-slate-500 text-slate-100'
              }`}
            >
              <span aria-hidden="true" className="inline-block size-3 rounded-full border border-white" style={{ backgroundColor: l.color }} />
              {l.type} ({l.count})
            </button>
          </li>
        ))}
      </ul>
      <div className="flex flex-col gap-4 lg:flex-row">
        <div
          ref={hostRef}
          role="img"
          aria-label="Graph canvas. Use the node list for keyboard access."
          className="relative h-[70vh] min-h-[34rem] min-w-0 flex-1 overflow-hidden rounded-lg border border-slate-800 bg-slate-950"
        />
        <aside className="w-full shrink-0 space-y-4 lg:w-80" aria-label="Details">
          {sel ? (
            <div className={card}>
              <p className="flex items-center gap-2 text-xs uppercase tracking-wide text-slate-400">
                <span aria-hidden="true" className="inline-block size-3 rounded-full border border-white" style={{ backgroundColor: colorFor(sel.type) }} />
                {sel.type}
              </p>
              <h2 className="mb-2 break-words text-lg font-semibold text-slate-50">{sel.label || sel.key}</h2>
              <p className={`${muted} mb-2 break-all text-sm`}>Selected: {sel.type} {sel.key}</p>
              <div className="mb-3 flex flex-wrap gap-2">
                <button type="button" className={btnPrimary} disabled={loading} onClick={() => expand(sel.id)}>
                  Expand
                </button>
                <Link className={btn} to={graphPath(sel.type, sel.key)}>
                  Open
                </Link>
                {sel.type === 'Vulnerability' && (
                  <Link className={btn} to={`/cve/${encodeURIComponent(sel.key)}`}>
                    Detail
                  </Link>
                )}
              </div>
              {props.length > 0 && (
                <table className="w-full text-sm" aria-label="Properties">
                  <tbody>
                    {props.map(([k, v]) => (
                      <tr key={k}>
                        <th scope="row" className="py-1 pr-2 text-left align-top font-medium text-slate-400">
                          {k}
                        </th>
                        <td className={`${td} break-words py-1`}>{show(v)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          ) : (
            <p className={`${muted} text-sm`}>Click a node to highlight it and its neighbours and see its details. Double-click a node, or press Expand, to load its neighbours.</p>
          )}
          <div className={card}>
            <h2 className="mb-2 text-sm font-semibold text-slate-200">
              Nodes ({shown.length.toLocaleString('en-US')})
            </h2>
            <ul role="listbox" aria-label="Displayed nodes" className="max-h-72 overflow-auto text-sm">
              {shown.slice(0, LIST_MAX).map((n) => (
                <li
                  key={n.id}
                  role="option"
                  aria-selected={n.id === selected}
                  tabIndex={0}
                  className="flex cursor-pointer items-center gap-2 rounded px-2 py-1 text-slate-300 hover:bg-slate-800 focus-visible:outline-2 focus-visible:outline-sky-400 aria-selected:bg-slate-800 aria-selected:font-semibold aria-selected:text-white"
                  onClick={() => setSelected(n.id)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      setSelected(n.id);
                    }
                  }}
                >
                  <span aria-hidden="true" className="inline-block size-2.5 shrink-0 rounded-full" style={{ backgroundColor: colorFor(n.type) }} />
                  {n.type}: {n.label}
                </li>
              ))}
            </ul>
            {shown.length > LIST_MAX && <p className={`${muted} mt-2 text-xs`}>The list shows the first {LIST_MAX}. Click a node on the canvas to select any other.</p>}
          </div>
        </aside>
      </div>
    </section>
  );
}
