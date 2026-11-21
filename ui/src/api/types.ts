// Response shapes. Adjust here (and in client.ts normalizers) if the API changes.

export type BuildState = string; // e.g. "ready", "building", "migrating"
export type BuildMode = string; // "sample" | "full"

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
  cwe: string;
  includeRejected: boolean;
}

export interface VulnerabilityRow {
  cveID: string;
  publishedDate?: string | null;
  description?: string | null;
  v3baseScore?: number | null;
  exploitability?: string | null;
  kev?: boolean | null;
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

export interface CveDetailData {
  vulnerability: Record<string, unknown>;
  sources: string[];
  weaknesses: string[];
  exploits: ExploitRef[];
  products: ProductRef[];
  domains: string[];
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
}
