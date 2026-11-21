import { matchRoutes } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import { GraphView } from './graph/GraphView';
import { Search } from './search/Search';
import { appRoutes } from './routes';

// sigma needs WebGL at import time; routing does not render the graph.
vi.mock('./graph/renderer', () => ({ mountRenderer: vi.fn() }));

function leaf(path: string) {
  const m = matchRoutes(appRoutes, path);
  const last = m?.[m.length - 1];
  const el = last?.route.element as { type: unknown } | undefined;
  return { type: el?.type, params: last?.params };
}

describe('routes', () => {
  it('renders the graph overview at the index', () => expect(leaf('/').type).toBe(GraphView));
  it('renders the graph overview at /graph', () => expect(leaf('/graph').type).toBe(GraphView));
  it('renders the neighbourhood at /graph/:type/:id', () => {
    const l = leaf('/graph/Vulnerability/CVE-2021-44228');
    expect(l.type).toBe(GraphView);
    expect(l.params).toMatchObject({ type: 'Vulnerability', id: 'CVE-2021-44228' });
  });
  it('renders Search at /search', () => expect(leaf('/search').type).toBe(Search));
  it('renders the overview for unknown paths', () => expect(leaf('/nope').type).toBe(GraphView));
});
