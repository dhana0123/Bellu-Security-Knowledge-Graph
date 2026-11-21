import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildQuery, createClient, normalizeStats, parseEnvelope } from './client';
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
