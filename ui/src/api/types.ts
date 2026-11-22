// Response shapes. Adjust here (and in client.ts normalizers) if the API changes.

// migrating | loading_cwe | nvd_catch_up | loading_exploits | ready (kept open: unknown values are shown as is)
export type BuildState = string;
// "sample" | "full", or null when unset (docs/api-shapes.md)
export type BuildMode = string | null;

export interface GraphEnvelope {
  version?: string;
  buildState: BuildState;
  buildMode: BuildMode;
  stale?: boolean;
  sources?: Record<string, { lastSuccess: string | null }>;
}

export interface SearchFilters {
  q: string;
  publishedFrom: string;
  publishedTo: string;
  cvssV3Min: string;
  cvssV3Max: string;
  exploitability: string;
  kev: boolean;
  epssMin: string;
  epssMax: string;
  ecosystem: string;
  cwe: string;
  includeRejected: boolean;
}

export interface VulnerabilityRow {
  cveID: string;
  publishedDate?: string | null;
  description?: string | null;
  v3baseScore?: number | null;
  v3baseSeverity?: string | null;
  exploitability?: string | null;
  kev?: boolean | null;
  epssScore?: number | null;
  sources?: string[];
}

export interface SearchPage {
  items: VulnerabilityRow[];
  limit: number;
  nextCursor?: string;
}

export interface ExploitRef {
  eid: string;
  exploitPublishDate?: string | null;
  exploitType?: string | null;
  platform?: string | null;
  authors: string[];
}

export interface ProductRef {
  productName: string;
  productType?: string | null;
  affectedVersion?: string | null;
  numOfVersion?: number | null;
  vendors: string[];
}

export interface RepositoryRef {
  url: string;
  host: string;
}
export interface FixCommitRef {
  sha: string;
  repoUrl: string;
  url: string;
}
export interface CveDetailData {
  vulnerability: Record<string, unknown>;
  sources: string[];
  weaknesses: string[];
  exploits: ExploitRef[];
  products: ProductRef[];
  domains: string[];
  repositories: RepositoryRef[];
  fixCommits: FixCommitRef[];
  packages: PackageRef[];
  attackPatterns: AttackPatternRef[];
  techniques: TechniqueRef[];
}

export interface SourceInfo {
  name: string;
  license: string;
  attribution: string;
}

export interface GraphNode {
  id: string;
  type: string;
  key: string;
  label: string;
  properties?: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  viewID?: string;
}

export interface Neighborhood {
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
}

/** GET /v1/graph/overview: a neighborhood-shaped graph plus the size of the whole graph. */
export interface GraphOverview extends Neighborhood {
  total: { nodes: number; relationships: number };
}

export interface CountEntry {
  name: string;
  count: number;
}

export interface TopEntry {
  key: string;
  count: number;
}

export interface SyncEntry {
  source: string;
  status: string;
  lastSuccess: string | null;
  deadLetters: number | null;
}

/** One /v1/stats "coverage" entry: upstream totals next to what the graph holds. */
export interface CoverageEntry {
  source: string;
  /** null until the source recorded totals. */
  upstream: Record<string, number> | null;
  upstreamAt: string | null;
  /** null when the server could not read the graph counts. */
  inGraph: Record<string, number> | null;
}
export interface StatsData {
  generatedAt: string | null;
  statsStale: boolean;
  labelCounts: CountEntry[];
  relationshipCounts: CountEntry[];
  byYear: CountEntry[];
  bySeverity: CountEntry[];
  exploited: { exploited: number; total: number; ratio: number };
  topWeaknesses: TopEntry[];
  topVendors: TopEntry[];
  topProducts: TopEntry[];
  sync: SyncEntry[];
  coverage: CoverageEntry[];
  kevCount: number | null;
  epssHigh: number | null;
}
export interface PackageRef {
  purl: string;
  ecosystem: string;
  name: string;
  introduced: string | null;
  fixed: string | null;
  lastAffected: string | null;
  affectedRanges: string[];
}
export interface AttackPatternRef {
  capecID: string;
  name: string;
  viaWeakness: string | null;
}
export interface TechniqueRef {
  attackID: string;
  name: string;
  viaAttackPattern: string | null;
}
/** GET /v1/vulnerabilities/{id}/co-exploited and /co-affected. */
export interface CoItem {
  cveID: string;
  shared: number;
  v3baseScore: number | null;
}
export interface CoPage {
  found: number;
  limit: number;
  items: CoItem[];
  skippedProducts?: number;
}
export interface PackageDetail {
  package: Record<string, unknown>;
  vulnerabilities: { cveID: string; publishedDate: string | null; v3baseScore: number | null }[];
  repositories: RepositoryRef[];
}
export interface AttackPatternDetail {
  attackPattern: Record<string, unknown>;
  weaknesses: { cweID: string; cweName: string }[];
  techniques: { attackID: string; name: string }[];
}
export interface TechniqueDetail {
  technique: Record<string, unknown>;
  attackPatterns: { capecID: string; name: string }[];
  atlasTechniques: { atlasID: string; name: string }[];
}
export interface AtlasTechniqueDetail {
  atlasTechnique: Record<string, unknown>;
  techniques: { attackID: string; name: string }[];
}
