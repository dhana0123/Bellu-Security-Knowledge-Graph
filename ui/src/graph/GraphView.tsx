import { useCallback, useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import type { Core } from 'cytoscape';
import { Link, useParams } from 'react-router';
import { ApiError } from '../api/errors';
import { useAuth } from '../auth/AuthContext';
import { ErrorMessage, Loading } from '../common/ErrorMessage';
import { graphPath } from '../cve/links';
import { toggle, typesOf, visibility } from './filter';
import { merge } from './merge';
import type { GraphData } from './merge';
import { NODE_STYLES, styleFor } from './nodeStyle';

const EMPTY: GraphData = { nodes: [], edges: [] };

export function GraphView() {
  const { type = '', id = '' } = useParams();
  const { client } = useAuth();
  const [graph, setGraph] = useState<GraphData>(EMPTY);
  const [limited, setLimited] = useState(false);
  const [depth, setDepth] = useState<1 | 2>(1);
  const [hiddenNodes, setHiddenNodes] = useState<ReadonlySet<string>>(new Set());
  const [hiddenRels, setHiddenRels] = useState<ReadonlySet<string>>(new Set());
  const [selected, setSelected] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const hostRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const reqId = useRef(0);
  const graphRef = useRef<GraphData>(EMPTY);

  const load = useCallback(
    async (nodeType: string, key: string, d: 1 | 2, reset: boolean) => {
      const my = ++reqId.current;
      setLoading(true);
      try {
        const res = await client.neighborhood({ id: key, type: nodeType, depth: d, limit: 300 });
        if (my !== reqId.current) return; // stale response
        const m = merge(reset ? EMPTY : graphRef.current, res);
        graphRef.current = m.graph;
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

  // Create the canvas once.
  useEffect(() => {
    if (!hostRef.current) return;
    const cy = cytoscape({
      container: hostRef.current,
      elements: [],
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            'font-size': 9,
            'text-valign': 'bottom',
            'text-margin-y': 3,
            width: 22,
            height: 22,
            'background-color': 'data(color)',
            shape: 'data(shape)' as unknown as cytoscape.Css.Node['shape'],
            color: '#1a1a1a',
          },
        },
        {
          selector: 'edge',
          style: {
            width: 1,
            'line-color': '#767676',
            'target-arrow-color': '#767676',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            label: 'data(type)',
            'font-size': 7,
            color: '#4a4a4a',
          },
        },
        { selector: '.hidden', style: { display: 'none' } },
        { selector: 'node.sel', style: { 'border-width': 3, 'border-color': '#000000' } },
      ],
    });
    cy.on('tap', 'node', (ev) => setSelected(ev.target.id() as string));
    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, []);

  // Sync elements and visibility with state (visibility is local, no request).
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const vis = visibility(graph, { nodeTypes: hiddenNodes, relTypes: hiddenRels });
    let added = false;
    cy.batch(() => {
      const keep = new Set(graph.nodes.map((n) => n.id));
      cy.nodes().forEach((n) => {
        if (!keep.has(n.id())) n.remove();
      });
      for (const n of graph.nodes) {
        if (cy.getElementById(n.id).empty()) {
          const s = styleFor(n.type);
          cy.add({ group: 'nodes', data: { id: n.id, label: n.label, shape: s.shape, color: s.color } });
          added = true;
        }
      }
      for (const e of graph.edges) {
        if (cy.getElementById(e.id).empty()) {
          cy.add({ group: 'edges', data: { id: e.id, source: e.source, target: e.target, type: e.type } });
        }
      }
      cy.nodes().forEach((n) => {
        n.toggleClass('hidden', !vis.nodes.has(n.id()));
        n.toggleClass('sel', n.id() === selected);
      });
      cy.edges().forEach((e) => {
        e.toggleClass('hidden', !vis.edges.has(e.id()));
      });
    });
    if (added) cy.layout({ name: 'cose', animate: false, fit: true }).run();
  }, [graph, hiddenNodes, hiddenRels, selected]);

  const nodeTypes = typesOf(graph.nodes);
  const relTypes = typesOf(graph.edges);
  const vis = visibility(graph, { nodeTypes: hiddenNodes, relTypes: hiddenRels });
  const shown = graph.nodes.filter((n) => vis.nodes.has(n.id));
  const sel = graph.nodes.find((n) => n.id === selected) ?? null;

  return (
    <section>
      <h1>
        Graph: {type} {id}
      </h1>
      <p>
        {type === 'Vulnerability' && <Link to={`/cve/${encodeURIComponent(id)}`}>Back to CVE detail</Link>}
      </p>
      <label htmlFor="depth">Depth</label>
      <select id="depth" value={depth} disabled={loading} onChange={(e) => setDepth(e.target.value === '2' ? 2 : 1)}>
        <option value="1">1</option>
        <option value="2">2</option>
      </select>
      <Loading active={loading} />
      <ErrorMessage error={error} />
      {limited && (
        <p role="status">Showing a limited view: the graph has more nodes than the 300 that are displayed.</p>
      )}
      <fieldset>
        <legend>Node types</legend>
        {nodeTypes.map((t) => (
          <label key={t}>
            <input type="checkbox" checked={!hiddenNodes.has(t)} onChange={() => setHiddenNodes(toggle(hiddenNodes, t))} /> {t}
          </label>
        ))}
      </fieldset>
      <fieldset>
        <legend>Relationship types</legend>
        {relTypes.map((t) => (
          <label key={t}>
            <input type="checkbox" checked={!hiddenRels.has(t)} onChange={() => setHiddenRels(toggle(hiddenRels, t))} /> {t}
          </label>
        ))}
      </fieldset>
      <div className="graph-wrap">
        <div className="canvas" ref={hostRef} role="img" aria-label="Graph canvas. Use the node list for keyboard access." />
        <div className="side">
          <h2>Legend</h2>
          <ul aria-label="Legend">
            {Object.entries(NODE_STYLES).map(([t, s]) => (
              <li key={t}>
                {t}: {s.shapeName}
              </li>
            ))}
          </ul>
          <h2>Nodes ({shown.length})</h2>
          <ul role="listbox" aria-label="Displayed nodes">
            {shown.map((n) => (
              <li
                key={n.id}
                role="option"
                aria-selected={n.id === selected}
                tabIndex={0}
                onClick={() => setSelected(n.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    setSelected(n.id);
                  }
                }}
              >
                {n.type}: {n.label}
              </li>
            ))}
          </ul>
          {sel && (
            <div>
              <p>
                Selected: {sel.type} {sel.key}
              </p>
              <button type="button" disabled={loading} onClick={() => void load(sel.type, sel.key, 1, false)}>
                Expand
              </button>{' '}
              <Link to={graphPath(sel.type, sel.key)}>Open</Link>
              {sel.type === 'Vulnerability' && (
                <>
                  {' '}
                  <Link to={`/cve/${encodeURIComponent(sel.key)}`}>Detail</Link>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
