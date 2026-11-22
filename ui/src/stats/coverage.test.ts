import { describe, expect, it } from 'vitest';
import { coveragePercent, coverageRows } from './coverage';

describe('coveragePercent', () => {
  it('shows 100% when equal and one decimal otherwise', () => {
    expect(coveragePercent(5, 5)).toBe('100%');
    expect(coveragePercent(0, 0)).toBeNull();
    expect(coveragePercent(1, 3)).toBe('33.3%');
    expect(coveragePercent(1, 2)).toBe('50.0%');
    expect(coveragePercent(0, 10)).toBe('0.0%');
  });
  it('never rounds a shortfall up to 100', () => {
    expect(coveragePercent(99999, 100000)).toBe('99.9%');
  });
  it('is null without both counts', () => {
    expect(coveragePercent(null, 5)).toBeNull();
    expect(coveragePercent(5, null)).toBeNull();
  });
});

describe('coverageRows', () => {
  it('renders new sources generically from their keys', () => {
    const rows = coverageRows([
      { source: 'kev', upstream: { kevEntries: 10 }, upstreamAt: 'T', inGraph: { kevEntries: 9 } },
      { source: 'capec', upstream: null, upstreamAt: null, inGraph: { attackPatterns: 5 } },
    ]);
    expect(rows.map((r) => [r.source, r.metric, r.upstream, r.inGraph])).toEqual([
      ['kev', 'kevEntries', 10, 9],
      ['capec', 'attackPatterns', null, 5],
    ]);
  });
  it('pairs the comparable metrics and tolerates a missing upstream', () => {
    const rows = coverageRows([
      { source: 'nvd', upstream: { cves: 10, cvesNotRejected: 9 }, upstreamAt: 'T', inGraph: { cves: 8, cvesNotRejected: 7 } },
      { source: 'exploitdb', upstream: { rows: 50, rowsWithCve: 40, invalidRows: 1 }, upstreamAt: 'T', inGraph: { exploits: 30 } },
      { source: 'cwe', upstream: null, upstreamAt: null, inGraph: { weaknesses: 4 } },
    ]);
    expect(rows.map((r) => [r.source, r.upstream, r.inGraph])).toEqual([
      ['nvd', 10, 8],
      ['nvd', 9, 7],
      ['exploitdb', 40, 30],
      ['cwe', null, 4],
    ]);
  });
  it('compares equally named keys of an unknown source', () => {
    const rows = coverageRows([{ source: 'x', upstream: { a: 2 }, upstreamAt: null, inGraph: { a: 1, b: 3 } }]);
    expect(rows.map((r) => [r.metric, r.upstream, r.inGraph])).toEqual([['a', 2, 1], ['b', null, 3]]);
  });
});
