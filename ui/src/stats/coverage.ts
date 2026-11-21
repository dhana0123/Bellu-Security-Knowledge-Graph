import type { CoverageEntry } from '../api/types';

export interface CoverageRow {
  key: string;
  source: string;
  metric: string;
  upstream: number | null;
  inGraph: number | null;
  upstreamAt: string | null;
}

interface MetricSpec {
  label: string;
  upstreamKey: string;
  graphKey: string;
}

/** Which upstream total is comparable with which graph count, per source. */
const SPECS: Record<string, MetricSpec[]> = {
  nvd: [
    { label: 'CVEs', upstreamKey: 'cves', graphKey: 'cves' },
    { label: 'CVEs, rejected excluded', upstreamKey: 'cvesNotRejected', graphKey: 'cvesNotRejected' },
  ],
  cwe: [{ label: 'Weaknesses', upstreamKey: 'weaknesses', graphKey: 'weaknesses' }],
  // Only rows with a CVE that exists in the graph become Exploit nodes.
  exploitdb: [{ label: 'Exploits (rows with a CVE)', upstreamKey: 'rowsWithCve', graphKey: 'exploits' }],
};

/** One row per comparable metric. A source without a spec compares equally named keys. */
export function coverageRows(entries: CoverageEntry[]): CoverageRow[] {
  const rows: CoverageRow[] = [];
  for (const e of entries) {
    let specs = SPECS[e.source];
    if (!specs) {
      const keys = [...new Set([...Object.keys(e.upstream ?? {}), ...Object.keys(e.inGraph ?? {})])].sort();
      specs = keys.map((k) => ({ label: k, upstreamKey: k, graphKey: k }));
    }
    if (specs.length === 0) specs = [{ label: '', upstreamKey: '', graphKey: '' }];
    for (const sp of specs) {
      rows.push({
        key: `${e.source}/${sp.graphKey}`,
        source: e.source,
        metric: sp.label,
        upstream: e.upstream && sp.upstreamKey in e.upstream ? (e.upstream[sp.upstreamKey] ?? null) : null,
        inGraph: e.inGraph && sp.graphKey in e.inGraph ? (e.inGraph[sp.graphKey] ?? null) : null,
        upstreamAt: e.upstreamAt,
      });
    }
  }
  return rows;
}

/**
 * Share of the upstream total that the graph holds, one decimal. Equal counts
 * give "100%". A shortfall is never rounded up to 100.0%. Null when there is
 * nothing to compare (a missing count or an upstream total of zero).
 */
export function coveragePercent(inGraph: number | null, upstream: number | null): string | null {
  if (inGraph === null || upstream === null || upstream <= 0) return null;
  if (inGraph === upstream) return '100%';
  const pct = (inGraph / upstream) * 100;
  const rounded = Math.round(pct * 10) / 10;
  if (inGraph < upstream && rounded >= 100) return '99.9%';
  return `${rounded.toFixed(1)}%`;
}
