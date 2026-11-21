import { describe, expect, it } from 'vitest';
import { emptyFilters, filtersToParams, validateFilters } from './validation';
import { canPrev, currentCursor, goNext, goPrev, initialPager } from './paging';
import { bannerMessage } from '../common/banner';
import { truncate } from '../common/text';

describe('validateFilters', () => {
  it('accepts empty filters', () => expect(validateFilters(emptyFilters)).toEqual({}));
  it('rejects scores out of range, min above max, date order, long text', () => {
    expect(validateFilters({ ...emptyFilters, cvssV3Min: '10.1' }).cvssV3Min).toBeDefined();
    expect(validateFilters({ ...emptyFilters, cvssV3Max: '-1' }).cvssV3Max).toBeDefined();
    expect(validateFilters({ ...emptyFilters, cvssV3Min: '7', cvssV3Max: '5' }).cvssV3Min).toBeDefined();
    expect(validateFilters({ ...emptyFilters, publishedFrom: '2024-02-01', publishedTo: '2024-01-01' }).publishedFrom).toBeDefined();
    expect(validateFilters({ ...emptyFilters, q: 'x'.repeat(501) }).q).toBeDefined();
    expect(validateFilters({ ...emptyFilters, q: 'x'.repeat(500) }).q).toBeUndefined();
  });
  it('drops empty values when building params', () => {
    expect(filtersToParams({ ...emptyFilters, q: ' log4j ', cwe: 'cwe-79', kev: true })).toEqual({ q: 'log4j', cwe: 'CWE-79', kev: true });
  });
});

describe('paging', () => {
  it('walks forward and back with a cursor stack', () => {
    expect(canPrev(initialPager)).toBe(false);
    const p1 = goNext({ ...initialPager, next: 'c1' });
    expect(currentCursor(p1)).toBe('c1');
    expect(canPrev(p1)).toBe(true);
    const p2 = goNext({ ...p1, next: 'c2' });
    expect(currentCursor(goPrev(p2))).toBe('c1');
    expect(currentCursor(goPrev(goPrev(p2)))).toBeUndefined();
    expect(goNext(initialPager)).toBe(initialPager);
  });
});

describe('bannerMessage', () => {
  const g = (buildState: string, buildMode: string) => ({ buildState, buildMode });
  it('is hidden only when ready and full', () => {
    expect(bannerMessage(null)).toBeNull();
    expect(bannerMessage(g('ready', 'full'))).toBeNull();
  });
  it('names both values otherwise', () => {
    const m = bannerMessage(g('building', 'full'));
    expect(m).toContain('building');
    expect(m).toContain('full');
    expect(bannerMessage(g('ready', 'sample'))).toContain('sample');
  });
});

describe('truncate', () => {
  it('cuts to the limit', () => {
    expect(truncate('abcdef', 3)).toBe('abc…');
    expect(truncate('abc', 3)).toBe('abc');
  });
});
