import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildQuery, createClient, normalizeDetail, normalizeOverview, normalizeStats, parseEnvelope } from './client';
import { ApiError } from './errors';
import { clearKey, loadKey, saveKey } from './session';

const graph = { version: '1', buildState: 'nvd_catch_up', buildMode: 'sample', stale: false, sources: {} };
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

afterEach(() => clearKey());

describe('client', () => {
  it('sends the key only in the Authorization header and reports the envelope', async () => {
    const f = vi.fn().mockResolvedValue(json(200, { items: [{ cveID: 'CVE-2024-0001' }], limit: 50, nextCursor: 'n', graph }));
    const onGraph = vi.fn();
    const c = createClient({ getKey: () => 'bskg_secret', fetchImpl: f as unknown as typeof fetch, onGraph });
    const page = await c.search({ q: 'x y', kev: true }, 50, 'cur');
    const [url, init] = f.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/v1/vulnerabilities?q=x+y&kev=true&limit=50&cursor=cur');
    expect(url).not.toContain('secret');
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer bskg_secret');
    expect(page.nextCursor).toBe('n');
    expect(onGraph).toHaveBeenCalledWith(expect.objectContaining({ buildState: 'nvd_catch_up', buildMode: 'sample' }));
  });

  it('clears via callback on 401 and maps the failure', async () => {
    const f = vi.fn().mockResolvedValue(json(401, { error: { code: 'unauthorized', message: 'no' }, graph }));
    const onUnauthorized = vi.fn();
    const c = createClient({ getKey: () => 'k', fetchImpl: f as unknown as typeof fetch, onUnauthorized });
    await expect(c.stats()).rejects.toMatchObject({ status: 401, message: 'stats failed: HTTP 401' });
    expect(onUnauthorized).toHaveBeenCalled();
  });

  it('maps network errors and timeouts', async () => {
    const down = createClient({ getKey: () => 'k', fetchImpl: (() => Promise.reject(new Error('x'))) as unknown as typeof fetch });
    await expect(down.stats()).rejects.toMatchObject({ status: 'network error' });
    const slow = createClient({
      getKey: () => 'k',
      timeoutMs: 5,
      fetchImpl: ((_u: string, init: RequestInit) =>
        new Promise((_r, rej) => init.signal?.addEventListener('abort', () => rej(new Error('abort'))))) as unknown as typeof fetch,
    });
    const err = await slow.stats().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe('timeout');
    expect((err as ApiError).message).toBe('stats failed: timeout');
  });

  it('login makes one call with the candidate key', async () => {
    const f = vi.fn().mockResolvedValue(json(200, { graph }));
    const c = createClient({ getKey: () => null, fetchImpl: f as unknown as typeof fetch });
    await c.login('bskg_new');
    expect(f).toHaveBeenCalledTimes(1);
    expect(f.mock.calls[0][0]).toBe('/v1/status');
    expect((f.mock.calls[0][1].headers as Record<string, string>).Authorization).toBe('Bearer bskg_new');
  });

  it('normalizes neighborhood and sources', async () => {
    const f = vi
      .fn()
      .mockResolvedValueOnce(json(200, { nodes: [{ id: 'Vulnerability:CVE-1', type: 'Vulnerability', key: 'CVE-1', label: 'CVE-1' }], edges: [], truncated: true, graph }))
      .mockResolvedValueOnce(json(200, { sources: [{ name: 'nvd', license: 'PD', attribution: 'NVD text' }], graph }));
    const c = createClient({ getKey: () => 'k', fetchImpl: f as unknown as typeof fetch });
    const n = await c.neighborhood({ id: 'CVE-1', type: 'Vulnerability', depth: 1, limit: 300 });
    expect(n.truncated).toBe(true);
    expect(n.nodes[0].key).toBe('CVE-1');
    expect(await c.sources()).toEqual([{ name: 'nvd', license: 'PD', attribution: 'NVD text' }]);
  });
});

describe('graph overview', () => {
  it('requests /v1/graph/overview with the limit and normalizes the body', async () => {
    const f = vi.fn().mockResolvedValue(
      json(200, {
        nodes: [
          { id: 'Vulnerability:CVE-1', type: 'Vulnerability', key: 'CVE-1', label: 'CVE-1', properties: { v3baseScore: 9.8 } },
          { id: 'Product:p', type: 'Product', key: 'p' },
        ],
        edges: [{ id: 'Vulnerability:CVE-1|AFFECTS|Product:p', source: 'Vulnerability:CVE-1', target: 'Product:p', type: 'AFFECTS' }],
        truncated: true,
        total: { nodes: 1200000, relationships: 3400000 },
        graph,
      }),
    );
    const c = createClient({ getKey: () => 'k', fetchImpl: f as unknown as typeof fetch });
    const o = await c.overview(2000);
    expect((f.mock.calls[0] as [string])[0]).toBe('/v1/graph/overview?limit=2000');
    expect(o.truncated).toBe(true);
    expect(o.total).toEqual({ nodes: 1200000, relationships: 3400000 });
    expect(o.nodes[0]).toMatchObject({ id: 'Vulnerability:CVE-1', type: 'Vulnerability', properties: { v3baseScore: 9.8 } });
    expect(o.nodes[1]?.label).toBe('p'); // label falls back to the key
    expect(o.edges).toEqual([
      { id: 'Vulnerability:CVE-1|AFFECTS|Product:p', source: 'Vulnerability:CVE-1', target: 'Product:p', type: 'AFFECTS', viewID: undefined },
    ]);
  });

  it('defaults the limit to 5000', async () => {
    const f = vi.fn().mockResolvedValue(json(200, { nodes: [], edges: [], truncated: false, total: { nodes: 0, relationships: 0 }, graph }));
    const c = createClient({ getKey: () => 'k', fetchImpl: f as unknown as typeof fetch });
    await c.overview();
    expect((f.mock.calls[0] as [string])[0]).toBe('/v1/graph/overview?limit=5000');
  });

  it('tolerates missing or malformed fields', () => {
    const o = normalizeOverview({ nodes: [{ id: 'a', type: 'T', key: 'a', label: 'a' }, 7, null], edges: 'x', total: { nodes: 'many', relationships: -4 } });
    expect(o.nodes).toHaveLength(1);
    expect(o.edges).toEqual([]);
    expect(o.truncated).toBe(false);
    expect(o.total).toEqual({ nodes: 1, relationships: 0 }); // non-numeric -> returned count; negative -> 0
    expect(normalizeOverview({}).total).toEqual({ nodes: 0, relationships: 0 });
  });

  it('maps a 504 to an ApiError', async () => {
    const f = vi.fn().mockResolvedValue(json(504, { error: { code: 'timeout', message: 'slow' }, graph }));
    const c = createClient({ getKey: () => 'k', fetchImpl: f as unknown as typeof fetch });
    await expect(c.overview()).rejects.toMatchObject({ status: 504, message: 'graph overview failed: HTTP 504' });
  });
});

describe('helpers', () => {
  it('buildQuery skips empty values', () => {
    expect(buildQuery({ a: '', b: undefined, c: 1, d: false })).toBe('?c=1');
    expect(buildQuery({})).toBe('');
  });
  it('normalizeStats follows docs/api-shapes.md', () => {
    const s = normalizeStats({
      statsStale: true,
      labels: [{ label: 'Vulnerability', count: 3 }],
      relationships: [{ type: 'AFFECTS', count: 2 }],
      cvesByYear: [{ year: 2023, count: 1 }, { year: 2024, count: 2 }],
      cvssDistribution: [{ severity: 'UNSCORED', count: 1 }, { severity: 'HIGH', count: 4 }],
      topWeaknesses: [{ key: 'CWE-79', count: 3 }],
      exploitedShare: { exploited: 1, total: 4, ratio: 0.25 },
      sync: [
        { source: 'cwe', neverRun: false, lastRun: { status: 'succeeded' }, lastSuccess: '2025-01-09T03:00:00Z', deadLetters: 1 },
        { source: 'nvd', neverRun: true, lastRun: null, lastSuccess: null, deadLetters: 0 },
      ],
    });
    expect(s.statsStale).toBe(true);
    expect(s.labelCounts).toEqual([{ name: 'Vulnerability', count: 3 }]);
    expect(s.relationshipCounts).toEqual([{ name: 'AFFECTS', count: 2 }]);
    expect(s.byYear.map((y) => y.name)).toEqual(['2023', '2024']);
    expect(s.bySeverity.map((y) => y.name)).toEqual(['UNSCORED', 'HIGH']);
    expect(s.topWeaknesses).toEqual([{ key: 'CWE-79', count: 3 }]);
    expect(s.exploited.ratio).toBe(0.25);
    expect(s.sync).toEqual([
      { source: 'cwe', status: 'succeeded', lastSuccess: '2025-01-09T03:00:00Z', deadLetters: 1 },
      { source: 'nvd', status: 'never run', lastSuccess: null, deadLetters: 0 },
    ]);
  });
  it('normalizeStats reads the coverage block', () => {
    const s = normalizeStats({
      coverage: [
        { source: 'nvd', upstream: { cves: 10, cvesNotRejected: 9, bad: 'x' }, upstreamAt: '2025-01-01T00:00:00Z', inGraph: { cves: 8 } },
        { source: 'cwe', upstream: null, upstreamAt: null, inGraph: null },
        'junk',
      ],
    });
    expect(s.coverage).toEqual([
      { source: 'nvd', upstream: { cves: 10, cvesNotRejected: 9 }, upstreamAt: '2025-01-01T00:00:00Z', inGraph: { cves: 8 } },
      { source: 'cwe', upstream: null, upstreamAt: null, inGraph: null },
    ]);
    expect(normalizeStats({}).coverage).toEqual([]);
  });
  it('parseEnvelope keeps a null buildMode and per-source lastSuccess', () => {
    const e = parseEnvelope({ graph: { version: 'dev', buildState: 'ready', buildMode: null, stale: false, sources: { nvd: { lastSuccess: null }, cwe: { lastSuccess: 'x' } } } });
    expect(e).toEqual({ version: 'dev', buildState: 'ready', buildMode: null, stale: false, sources: { nvd: { lastSuccess: null }, cwe: { lastSuccess: 'x' } } });
  });
});

describe('session', () => {
  it('stores the key in sessionStorage and clears it', () => {
    saveKey('k1');
    expect(sessionStorage.getItem('bskg.key')).toBe('k1');
    expect(loadKey()).toBe('k1');
    clearKey();
    expect(sessionStorage.getItem('bskg.key')).toBeNull();
    expect(loadKey()).toBeNull();
  });
});

describe('normalizeDetail repositories and fix commits', () => {
  it('reads the new arrays', () => {
    const d = normalizeDetail({
      vulnerability: { cveID: 'CVE-1' },
      repositories: [{ url: 'https://github.com/o/r', host: 'github.com' }, 'junk'],
      fixCommits: [{ sha: 'a'.repeat(40), repoUrl: 'https://github.com/o/r', url: 'https://github.com/o/r/commit/' + 'a'.repeat(40) }],
    });
    expect(d.repositories).toEqual([{ url: 'https://github.com/o/r', host: 'github.com' }]);
    expect(d.fixCommits).toHaveLength(1);
    expect(d.fixCommits[0]).toMatchObject({ sha: 'a'.repeat(40), repoUrl: 'https://github.com/o/r' });
  });
  it('treats absent or malformed fields as empty', () => {
    expect(normalizeDetail({ vulnerability: {} })).toMatchObject({ repositories: [], fixCommits: [] });
    expect(normalizeDetail({ repositories: 'x', fixCommits: null })).toMatchObject({ repositories: [], fixCommits: [] });
  });
  it('passes unknown labels and relationship types through stats', () => {
    const s = normalizeStats({
      labels: [{ label: 'Repository', count: 2 }, { label: 'FixCommit', count: 3 }],
      relationships: [{ type: 'HAS_FIX_COMMIT', count: 3 }],
    });
    expect(s.labelCounts).toEqual([{ name: 'Repository', count: 2 }, { name: 'FixCommit', count: 3 }]);
    expect(s.relationshipCounts).toEqual([{ name: 'HAS_FIX_COMMIT', count: 3 }]);
  });
});
