// The only module that calls fetch. All response-shape knowledge lives here and in types.ts.
import { ApiError } from './errors';
import type {
  AtlasTechniqueDetail,
  AttackPatternDetail,
  AttackPatternRef,
  CoItem,
  CoPage,
  CountEntry,
  CoverageEntry,
  CveDetailData,
  ExploitRef,
  FixCommitRef,
  GraphEnvelope,
  GraphOverview,
  Neighborhood,
  PackageDetail,
  PackageRef,
  ProductRef,
  RepositoryRef,
  SearchFilters,
  SearchPage,
  SourceInfo,
  StatsData,
  SyncEntry,
  TechniqueDetail,
  TechniqueRef,
  TopEntry,
} from './types';

export interface ClientOptions {
  getKey: () => string | null;
  /** Called on every HTTP 401. */
  onUnauthorized?: () => void;
  /** Called with the `graph` envelope of every response that carries one. */
  onGraph?: (g: GraphEnvelope) => void;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

type Params = Record<string, string | number | boolean | undefined | null>;
type Json = Record<string, unknown>;

/** Builds a query string, skipping empty values. Never put credentials in here. */
export function buildQuery(params: Params): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '' || v === false) continue;
    sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : '';
}

const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown, d = ''): string => (typeof v === 'string' ? v : v == null ? d : String(v));
const num = (v: unknown, d = 0): number => (typeof v === 'number' && Number.isFinite(v) ? v : d);
const optStr = (v: unknown): string | null => (v == null || v === '' ? null : str(v));
const optNum = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const strList = (v: unknown): string[] => arr(v).map((x) => str(x)).filter((x) => x !== '');

function normalizeEnvSources(v: Json): NonNullable<GraphEnvelope['sources']> {
  const out: NonNullable<GraphEnvelope['sources']> = {};
  for (const [k, o] of Object.entries(v)) {
    out[k] = { lastSuccess: isObj(o) && o.lastSuccess != null ? str(o.lastSuccess) : null };
  }
  return out;
}

export function parseEnvelope(body: unknown): GraphEnvelope | null {
  if (!isObj(body) || !isObj(body.graph)) return null;
  const g = body.graph;
  return {
    version: typeof g.version === 'string' ? g.version : undefined,
    buildState: str(g.buildState, 'unknown'),
    buildMode: typeof g.buildMode === 'string' ? g.buildMode : null,
    stale: typeof g.stale === 'boolean' ? g.stale : undefined,
    sources: isObj(g.sources) ? normalizeEnvSources(g.sources) : undefined,
  };
}

function toCounts(v: unknown, nameKey: string): CountEntry[] {
  return arr(v)
    .filter(isObj)
    .map((o) => ({ name: str(o[nameKey]), count: num(o.count) }));
}

function toTop(v: unknown): TopEntry[] {
  return arr(v)
    .filter(isObj)
    .map((o) => ({ key: str(o.key), count: num(o.count) }));
}

/** One /v1/status "sources" entry (also used by /v1/stats "sync"). */
function toSync(o: Json): SyncEntry {
  const last = isObj(o.lastRun) ? o.lastRun : null;
  return {
    source: str(o.source),
    status: o.neverRun === true || !last ? 'never run' : str(last.status, 'unknown'),
    lastSuccess: o.lastSuccess == null ? null : str(o.lastSuccess),
    deadLetters: o.deadLetters == null ? null : num(o.deadLetters),
  };
}

/** A name-to-count object; null when absent or not an object. Non-numeric values are dropped. */
function toMetrics(v: unknown): Record<string, number> | null {
  if (!isObj(v)) return null;
  const out: Record<string, number> = {};
  for (const [k, n] of Object.entries(v)) {
    if (typeof n === 'number' && Number.isFinite(n)) out[k] = n;
  }
  return out;
}
function toCoverage(o: Json): CoverageEntry {
  return {
    source: str(o.source),
    upstream: toMetrics(o.upstream),
    upstreamAt: o.upstreamAt == null ? null : str(o.upstreamAt),
    inGraph: toMetrics(o.inGraph),
  };
}
/** Matches docs/api-shapes.md, GET /v1/stats. */
export function normalizeStats(body: Json): StatsData {
  const ex = isObj(body.exploitedShare) ? body.exploitedShare : {};
  return {
    generatedAt: body.generatedAt == null ? null : str(body.generatedAt),
    statsStale: body.statsStale === true,
    labelCounts: toCounts(body.labels, 'label'),
    relationshipCounts: toCounts(body.relationships, 'type'),
    byYear: toCounts(body.cvesByYear, 'year'),
    bySeverity: toCounts(body.cvssDistribution, 'severity'),
    exploited: { exploited: num(ex.exploited), total: num(ex.total), ratio: num(ex.ratio) },
    topWeaknesses: toTop(body.topWeaknesses),
    topVendors: toTop(body.topVendors),
    topProducts: toTop(body.topProducts),
    sync: arr(body.sync).filter(isObj).map(toSync),
    coverage: arr(body.coverage).filter(isObj).map(toCoverage),
    kevCount: typeof body.kevCount === 'number' && Number.isFinite(body.kevCount) ? body.kevCount : null,
    epssHigh: typeof body.epssHigh === 'number' && Number.isFinite(body.epssHigh) ? body.epssHigh : null,
  };
}

export function normalizeSources(body: unknown): SourceInfo[] {
  const list = isObj(body) ? arr(body.sources) : [];
  return list.filter(isObj).map((o) => ({
    name: str(o.name),
    license: str(o.license),
    attribution: str(o.attribution),
  }));
}

export function normalizeDetail(body: Json): CveDetailData {
  return {
    vulnerability: isObj(body.vulnerability) ? body.vulnerability : {},
    sources: strList(body.sources),
    weaknesses: strList(body.weaknesses),
    exploits: arr(body.exploits)
      .filter(isObj)
      .map(
        (o): ExploitRef => ({
          eid: str(o.eid),
          exploitPublishDate: o.exploitPublishDate == null ? null : str(o.exploitPublishDate),
          exploitType: o.exploitType == null ? null : str(o.exploitType),
          platform: o.platform == null ? null : str(o.platform),
          authors: strList(o.authors),
        }),
      ),
    products: arr(body.products)
      .filter(isObj)
      .map(
        (o): ProductRef => ({
          productName: str(o.productName),
          productType: o.productType == null ? null : str(o.productType),
          affectedVersion: o.affectedVersion == null ? null : str(o.affectedVersion),
          numOfVersion: typeof o.numOfVersion === 'number' ? o.numOfVersion : null,
          vendors: strList(o.vendors),
        }),
      ),
    domains: strList(body.domains),
    repositories: arr(body.repositories)
      .filter(isObj)
      .map((o): RepositoryRef => ({ url: str(o.url), host: str(o.host) }))
      .filter((r) => r.url !== ''),
    fixCommits: arr(body.fixCommits)
      .filter(isObj)
      .map((o): FixCommitRef => ({ sha: str(o.sha), repoUrl: str(o.repoUrl), url: str(o.url) }))
      .filter((c) => c.sha !== ''),
    packages: arr(body.packages)
      .filter(isObj)
      .map(
        (o): PackageRef => ({
          purl: str(o.purl),
          ecosystem: str(o.ecosystem),
          name: str(o.name),
          introduced: optStr(o.introduced),
          fixed: optStr(o.fixed),
          lastAffected: optStr(o.lastAffected),
          affectedRanges: strList(o.affectedRanges),
        }),
      )
      .filter((p) => p.purl !== ''),
    attackPatterns: arr(body.attackPatterns)
      .filter(isObj)
      .map((o): AttackPatternRef => ({ capecID: str(o.capecID), name: str(o.name), viaWeakness: optStr(o.viaWeakness) }))
      .filter((a) => a.capecID !== ''),
    techniques: arr(body.techniques)
      .filter(isObj)
      .map((o): TechniqueRef => ({ attackID: str(o.attackID), name: str(o.name), viaAttackPattern: optStr(o.viaAttackPattern) }))
      .filter((t) => t.attackID !== ''),
  };
}
const pairs = <A extends string, B extends string>(v: unknown, a: A, b: B): Record<A | B, string>[] =>
  arr(v)
    .filter(isObj)
    .map((o) => ({ [a]: str(o[a]), [b]: str(o[b]) }) as Record<A | B, string>)
    .filter((o) => o[a] !== '');
const repos = (v: unknown): RepositoryRef[] =>
  arr(v)
    .filter(isObj)
    .map((o): RepositoryRef => ({ url: str(o.url), host: str(o.host) }))
    .filter((r) => r.url !== '');
export function normalizeCoPage(body: Json): CoPage {
  const items = arr(body.items)
    .filter(isObj)
    .map((o): CoItem => ({ cveID: str(o.cveID), shared: num(o.shared), v3baseScore: optNum(o.v3baseScore) }))
    .filter((i) => i.cveID !== '');
  return {
    found: num(body.found, items.length),
    limit: num(body.limit, items.length),
    items,
    skippedProducts: typeof body.skippedProducts === 'number' ? body.skippedProducts : undefined,
  };
}
export function normalizePackage(body: Json): PackageDetail {
  return {
    package: isObj(body.package) ? body.package : {},
    vulnerabilities: arr(body.vulnerabilities)
      .filter(isObj)
      .map((o) => ({ cveID: str(o.cveID), publishedDate: optStr(o.publishedDate), v3baseScore: optNum(o.v3baseScore) }))
      .filter((v) => v.cveID !== ''),
    repositories: repos(body.repositories),
  };
}
export function normalizeAttackPattern(body: Json): AttackPatternDetail {
  return {
    attackPattern: isObj(body.attackPattern) ? body.attackPattern : {},
    weaknesses: pairs(body.weaknesses, 'cweID', 'cweName'),
    techniques: pairs(body.techniques, 'attackID', 'name'),
  };
}
export function normalizeTechnique(body: Json): TechniqueDetail {
  return {
    technique: isObj(body.technique) ? body.technique : {},
    attackPatterns: pairs(body.attackPatterns, 'capecID', 'name'),
    atlasTechniques: pairs(body.atlasTechniques, 'atlasID', 'name'),
  };
}
export function normalizeAtlasTechnique(body: Json): AtlasTechniqueDetail {
  return {
    atlasTechnique: isObj(body.atlasTechnique) ? body.atlasTechnique : {},
    techniques: pairs(body.techniques, 'attackID', 'name'),
  };
}

export function normalizeNeighborhood(body: Json): Neighborhood {
  return {
    nodes: arr(body.nodes)
      .filter(isObj)
      .map((o) => ({
        id: str(o.id),
        type: str(o.type),
        key: str(o.key),
        label: str(o.label, str(o.key)),
        properties: isObj(o.properties) ? o.properties : undefined,
      })),
    edges: arr(body.edges)
      .filter(isObj)
      .map((o) => ({
        id: str(o.id),
        source: str(o.source),
        target: str(o.target),
        type: str(o.type),
        viewID: o.viewID == null ? undefined : str(o.viewID),
      })),
    truncated: body.truncated === true,
  };
}

/** Matches docs/api-shapes.md, GET /v1/graph/overview. A missing `total` falls back to the returned counts. */
export function normalizeOverview(body: Json): GraphOverview {
  const nb = normalizeNeighborhood(body);
  const t = isObj(body.total) ? body.total : {};
  return {
    ...nb,
    total: {
      nodes: Math.max(0, Math.trunc(num(t.nodes, nb.nodes.length))),
      relationships: Math.max(0, Math.trunc(num(t.relationships, nb.edges.length))),
    },
  };
}

export function createClient(opts: ClientOptions) {
  const doFetch = opts.fetchImpl ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const timeoutMs = opts.timeoutMs ?? 30_000;

  async function request(
    action: string,
    path: string,
    params: Params = {},
    keyOverride?: string,
    signal?: AbortSignal,
    timeoutOverrideMs?: number,
  ): Promise<Json> {
    const key = keyOverride ?? opts.getKey();
    const ctrl = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      ctrl.abort();
    }, timeoutOverrideMs ?? timeoutMs);
    signal?.addEventListener('abort', () => ctrl.abort(), { once: true });
    let res: Response;
    try {
      res = await doFetch(`/v1${path}${buildQuery(params)}`, {
        method: 'GET',
        headers: { Accept: 'application/json', ...(key ? { Authorization: `Bearer ${key}` } : {}) },
        signal: ctrl.signal,
        cache: 'no-store',
        credentials: 'omit',
      });
    } catch {
      throw new ApiError(action, timedOut ? 'timeout' : 'network error');
    } finally {
      clearTimeout(timer);
    }
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      body = null;
    }
    const env = parseEnvelope(body);
    if (env) opts.onGraph?.(env);
    if (res.status === 401) opts.onUnauthorized?.();
    if (!res.ok) {
      const e = isObj(body) && isObj(body.error) ? body.error : {};
      throw new ApiError(
        action,
        res.status,
        typeof e.code === 'string' ? e.code : undefined,
        typeof e.parameter === 'string' ? e.parameter : undefined,
        typeof e.message === 'string' ? e.message : undefined,
      );
    }
    return isObj(body) ? body : {};
  }

  async function coRelated(kind: 'co-exploited' | 'co-affected', id: string, signal?: AbortSignal): Promise<CoPage | null> {
    try {
      return normalizeCoPage(
        await request(kind, `/vulnerabilities/${encodeURIComponent(id)}/${kind}`, { limit: 10 }, undefined, signal),
      );
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null;
      throw e;
    }
  }
  return {
    /** Exactly one call; the caller stores the key only when this resolves. */
    async login(key: string): Promise<void> {
      await request('login', '/status', {}, key);
    },
    status: (signal?: AbortSignal) => request('status', '/status', {}, undefined, signal),
    async search(f: Partial<SearchFilters>, limit: number, cursor?: string, signal?: AbortSignal): Promise<SearchPage> {
      const b = await request(
        'search',
        '/vulnerabilities',
        { ...f, limit, cursor },
        undefined,
        signal,
      );
      return {
        items: arr(b.items)
          .filter(isObj)
          .map((o) => ({
            cveID: str(o.cveID),
            publishedDate: o.publishedDate == null ? null : str(o.publishedDate),
            description: o.description == null ? null : str(o.description),
            v3baseScore: typeof o.v3baseScore === 'number' ? o.v3baseScore : null,
            v3baseSeverity: o.v3baseSeverity == null ? null : str(o.v3baseSeverity),
            exploitability: o.exploitability == null ? null : str(o.exploitability),
            kev: typeof o.kev === 'boolean' ? o.kev : null,
            epssScore: optNum(o.epssScore),
            sources: strList(o.sources),
          })),
        limit: num(b.limit, limit),
        nextCursor: typeof b.nextCursor === 'string' && b.nextCursor ? b.nextCursor : undefined,
      };
    },
    async cve(id: string, signal?: AbortSignal): Promise<CveDetailData> {
      return normalizeDetail(
        await request('cve detail', `/vulnerabilities/${encodeURIComponent(id)}`, {}, undefined, signal),
      );
    },
    /** Resolves to null when the server answers 404 (feature flag off). */
    async coExploited(id: string, signal?: AbortSignal): Promise<CoPage | null> {
      return coRelated('co-exploited', id, signal);
    },
    async coAffected(id: string, signal?: AbortSignal): Promise<CoPage | null> {
      return coRelated('co-affected', id, signal);
    },
    async package(purl: string, signal?: AbortSignal): Promise<PackageDetail> {
      return normalizePackage(await request('package', `/packages/${encodeURIComponent(purl)}`, {}, undefined, signal));
    },
    async attackPattern(id: string, signal?: AbortSignal): Promise<AttackPatternDetail> {
      return normalizeAttackPattern(
        await request('attack pattern', `/attack-patterns/${encodeURIComponent(id)}`, {}, undefined, signal),
      );
    },
    async technique(id: string, signal?: AbortSignal): Promise<TechniqueDetail> {
      return normalizeTechnique(await request('technique', `/techniques/${encodeURIComponent(id)}`, {}, undefined, signal));
    },
    async atlasTechnique(id: string, signal?: AbortSignal): Promise<AtlasTechniqueDetail> {
      return normalizeAtlasTechnique(
        await request('atlas technique', `/atlas-techniques/${encodeURIComponent(id)}`, {}, undefined, signal),
      );
    },
    async sources(signal?: AbortSignal): Promise<SourceInfo[]> {
      return normalizeSources(await request('sources', '/sources', {}, undefined, signal));
    },
    async neighborhood(
      p: { id: string; type: string; depth: 1 | 2; limit: number },
      signal?: AbortSignal,
    ): Promise<Neighborhood> {
      return normalizeNeighborhood(await request('graph', '/graph/neighborhood', p, undefined, signal));
    },
    /** The whole graph up to `limit` nodes (the API default and maximum is 5000). The server may take up to its own 30 s query limit. */
    async overview(limit = 5000, signal?: AbortSignal): Promise<GraphOverview> {
      return normalizeOverview(
        await request('graph overview', '/graph/overview', { limit }, undefined, signal, timeoutMs + 15_000),
      );
    },
    async stats(signal?: AbortSignal): Promise<StatsData> {
      return normalizeStats(await request('stats', '/stats', {}, undefined, signal));
    },
  };
}

export type ApiClient = ReturnType<typeof createClient>;
