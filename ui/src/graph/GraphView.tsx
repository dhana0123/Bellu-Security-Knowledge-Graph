import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useParams } from 'react-router';
import { ApiError } from '../api/errors';
import { useAuth } from '../auth/AuthContext';
import { btn, btnPrimary, card, link, muted, td } from '../common/classes';
import { ErrorMessage, Loading } from '../common/ErrorMessage';
import { graphPath } from '../cve/links';
import { newGraph, runLayout, syncGraph } from './build';
import type { BskgGraph } from './build';
import { toggle, visibility } from './filter';
import { selectionFor } from './highlight';
import { merge } from './merge';
import type { GraphData } from './merge';
import { mountRenderer } from './renderer';
import type { Renderer } from './renderer';
import { colorFor, legendCounts } from './style';

const EMPTY: GraphData = { nodes: [], edges: [] };
const NO_RELS: ReadonlySet<string> = new Set();

function show(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

export function GraphView() {
  const { type = '', id = '' } = useParams();
  const { client } = useAuth();
  const [graph, setGraph] = useState<GraphData>(EMPTY);
  const [limited, setLimited] = useState(false);
  const [depth, setDepth] = useState<1 | 2>(1);
  const [hidden, setHidden] = useState<ReadonlySet<string>>(new Set());
  const [selected, setSelected] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const hostRef = useRef<HTMLDivElement>(null);
  const rendererRef = useRef<Renderer | null>(null);
  const ggRef = useRef<BskgGraph | null>(null);
  const reqId = useRef(0);
  const graphRef = useRef<GraphData>(EMPTY);
  const fitNext = useRef(true);
  const expandRef = useRef<(nodeId: string) => void>(() => undefined);

  const load = useCallback(
    async (nodeType: string, key: string, d: 1 | 2, reset: boolean) => {
      const my = ++reqId.current;
      setLoading(true);
      try {
        const res = await client.neighborhood({ id: key, type: nodeType, depth: d, limit: 300 });
        if (my !== reqId.current) return; // stale response
        const m = merge(reset ? EMPTY : graphRef.current, res);
        graphRef.current = m.graph;
        if (reset) fitNext.current = true;
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

  // New start node or depth: reload from scratch.
  useEffect(() => {
    setSelected(null);
    void load(type, id, depth, true);
    return () => {
      // eslint-disable-next-line react-hooks/exhaustive-deps -- invalidates in-flight responses
      reqId.current++;
    };
  }, [type, id, depth, load]);

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
      r.kill();
      rendererRef.current = null;
      ggRef.current = null;
    };
  }, []);

  // Merge data into the graphology graph, re-run the layout from current positions.
  useEffect(() => {
    const gg = ggRef.current;
    const r = rendererRef.current;
    if (!gg || !r) return;
    const added = syncGraph(gg, graph);
    if (added.length > 0) runLayout(gg);
    r.refresh();
    if (fitNext.current && graph.nodes.length > 0) {
      fitNext.current = false;
      r.fit();
    }
  }, [graph]);

  const selection = useMemo(() => (selected ? selectionFor(graph, selected) : null), [graph, selected]);
  useEffect(() => rendererRef.current?.setSelection(selection), [selection]);
  useEffect(() => rendererRef.current?.setHiddenTypes(hidden), [hidden]);

  const expand = useCallback(
    (nodeId: string) => {
      const n = graphRef.current.nodes.find((x) => x.id === nodeId);
      if (n) void load(n.type, n.key, 1, false);
    },
    [load],
  );
  useEffect(() => {
    expandRef.current = expand;
  }, [expand]);

  const legend = legendCounts(graph.nodes, hidden);
  const vis = visibility(graph, { nodeTypes: hidden, relTypes: NO_RELS });
  const shown = graph.nodes.filter((n) => vis.nodes.has(n.id));
  const sel = graph.nodes.find((n) => n.id === selected) ?? null;
  const props = sel?.properties ? Object.entries(sel.properties) : [];

  return (
    <section>
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold text-slate-50">
          Graph: {type} {id}
        </h1>
        {type === 'Vulnerability' && (
          <Link className={link} to={`/cve/${encodeURIComponent(id)}`}>
            Back to CVE detail
          </Link>
        )}
        <div className="ml-auto flex items-center gap-2">
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
          <button type="button" className={btn} onClick={() => rendererRef.current?.fit()}>
            Fit
          </button>
        </div>
      </div>
      <Loading active={loading} />
      <ErrorMessage error={error} />
      {limited && (
        <p role="status" className="mb-2 rounded-md border border-amber-700 bg-amber-950 px-3 py-2 text-sm text-amber-200">
          Showing a limited view: the graph has more nodes than the 300 that are displayed.
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
          className="relative h-[34rem] min-w-0 flex-1 overflow-hidden rounded-lg border border-slate-800 bg-slate-950"
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
            <p className={`${muted} text-sm`}>Click a node for details. Double-click a node to load its neighbours.</p>
          )}
          <div className={card}>
            <h2 className="mb-2 text-sm font-semibold text-slate-200">Nodes ({shown.length})</h2>
            <ul role="listbox" aria-label="Displayed nodes" className="max-h-72 overflow-auto text-sm">
              {shown.map((n) => (
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
          </div>
        </aside>
      </div>
    </section>
  );
}
