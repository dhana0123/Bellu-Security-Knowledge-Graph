import Sigma, { DEFAULT_STYLES } from 'sigma';
import { extremityArrow, layerFill, layerPlain, pathLine, sdfCircle } from 'sigma/rendering';
import type { BskgGraph } from './build';
import { edgeEmphasis, nodeEmphasis } from './highlight';
import type { Selection } from './highlight';
import { DIM_COLOR } from './style';

export interface RendererCallbacks {
  /** A node was clicked (id) or the empty canvas was clicked (null). */
  onSelect(id: string | null): void;
  /** A node was double-clicked. */
  onExpand(id: string): void;
}

export interface Renderer {
  setSelection(sel: Selection | null): void;
  setHiddenTypes(hidden: ReadonlySet<string>): void;
  /**
   * Large (whole-graph) mode: node captions only show once a node is drawn big enough (zoomed in),
   * edge labels only show when zoomed in, and edges and labels are hidden while moving the camera.
   */
  setLarge(large: boolean): void;
  /** Re-reads node positions and attributes from the graph. */
  refresh(): void;
  fit(): void;
  kill(): void;
}

/**
 * Draws the graph with Sigma (WebGL). Sigma and the programs used here inject no <style>
 * elements: node and edge colours, arrowheads and labels are all drawn in WebGL or on a canvas.
 * Highlighting and hiding use nodeReducer / edgeReducer over a small mutable view state.
 */
/** Rendered node radius (px) from which a caption is drawn in large mode. */
export const LARGE_LABEL_SIZE_THRESHOLD = 9;
/** Camera ratio below which edge labels are drawn in large mode (smaller ratio = more zoomed in). */
export const LARGE_EDGE_LABEL_RATIO = 0.4;

export function mountRenderer(container: HTMLElement, graph: BskgGraph, cb: RendererCallbacks): Renderer {
  const view: { selection: Selection | null; hidden: ReadonlySet<string> } = { selection: null, hidden: new Set() };
  const line = pathLine();
  const arrow = extremityArrow({ lengthRatio: 7, widthRatio: 5.5 });

  const sigma = new Sigma(graph, container, {
    primitives: {
      nodes: { shapes: [sdfCircle()], layers: [layerFill()] },
      edges: { paths: [line], extremities: [arrow], layers: [layerPlain()] },
    },
    styles: {
      nodes: [
        DEFAULT_STYLES.nodes,
        {
          size: { attribute: 'size', defaultValue: 18 },
          color: { attribute: 'color' },
          label: { attribute: 'label' },
          labelPosition: 'over',
          labelSize: 10,
          labelColor: '#ffffff',
          labelVisibility: 'visible',
          // A white backdrop limited to the node area is the white border around the circle.
          backdropVisibility: 'visible',
          backdropArea: 'node',
          backdropColor: '#ffffff',
          backdropShadowBlur: 0,
          backdropPadding: 2,
        },
      ],
      edges: [
        DEFAULT_STYLES.edges,
        {
          size: { attribute: 'size', defaultValue: 1.5 },
          color: { attribute: 'color' },
          label: { attribute: 'label' },
          labelColor: '#a1a9b8',
          labelSize: 9,
          labelPosition: 'above',
          labelVisibility: 'auto',
          head: arrow.name,
          path: line.name,
        },
      ],
      stage: { background: 'transparent', cursor: 'grab' },
    },
    settings: {
      renderLabels: true,
      renderEdgeLabels: true,
      enableEdgeEvents: false,
      enableNodeDrag: true,
      gestureTarget: 'graph',
      itemSizesReference: 'screen',
      stagePadding: 70,
      minCameraRatio: 0.1,
      maxCameraRatio: 10,
      labelRenderedSizeThreshold: 0,
      labelDensity: 2,
    },
    nodeReducer: (id, data, attrs) => {
      if (view.hidden.has(attrs.type)) return { visibility: 'hidden', labelVisibility: 'hidden' };
      switch (nodeEmphasis(view.selection, id)) {
        case 'selected':
          return { size: data.size + 4, zIndex: 2, backdropColor: '#ffd43b', backdropPadding: 3 };
        case 'neighbour':
          return { zIndex: 1 };
        case 'dim':
          return { color: DIM_COLOR, labelColor: '#556070', backdropColor: '#3a4150', zIndex: 0 };
        default:
          return {};
      }
    },
    edgeReducer: (id, data) => {
      const g = sigma.getGraph();
      const hiddenEnd =
        view.hidden.has(g.getNodeAttribute(g.source(id), 'type')) || view.hidden.has(g.getNodeAttribute(g.target(id), 'type'));
      if (hiddenEnd) return { visibility: 'hidden', labelVisibility: 'hidden' };
      if (edgeEmphasis(view.selection, id) === 'dim') return { opacity: 0.12, labelVisibility: 'hidden', zIndex: 0 };
      return view.selection ? { size: data.size + 0.5, zIndex: 1, labelColor: '#d6dbe6' } : {};
    },
  });

  let large = false;
  let edgeLabels = true;
  const syncEdgeLabels = () => {
    const want = !large || sigma.getCamera().ratio < LARGE_EDGE_LABEL_RATIO;
    if (want === edgeLabels) return;
    edgeLabels = want;
    sigma.setSetting('renderEdgeLabels', want);
  };
  sigma.getCamera().on('updated', syncEdgeLabels);
  sigma.on('clickNode', (p) => cb.onSelect(p.node));
  sigma.on('clickStage', () => cb.onSelect(null));
  sigma.on('doubleClickNode', (p) => {
    p.preventSigmaDefault();
    cb.onExpand(p.node);
  });

  return {
    setSelection(sel) {
      view.selection = sel;
      sigma.refresh();
    },
    setHiddenTypes(hidden) {
      view.hidden = hidden;
      sigma.refresh();
    },
    setLarge(l) {
      large = l;
      sigma.setSetting('labelRenderedSizeThreshold', l ? LARGE_LABEL_SIZE_THRESHOLD : 0);
      sigma.setSetting('hideEdgesOnMove', l);
      sigma.setSetting('hideLabelsOnMove', l);
      syncEdgeLabels();
    },
    refresh() {
      sigma.refresh();
    },
    fit() {
      void sigma.getCamera().animate({ x: 0.5, y: 0.5, ratio: 1, angle: 0 }, { duration: 300 });
    },
    kill() {
      sigma.kill();
    },
  };
}
