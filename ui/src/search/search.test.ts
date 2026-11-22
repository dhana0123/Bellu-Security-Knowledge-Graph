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

describe('EPSS and ecosystem filters', () => {
  const v = (o: Partial<typeof emptyFilters>) => validateFilters({ ...emptyFilters, ...o });
  it('accepts 0..1 inclusive', () => {
    expect(v({ epssMin: '0', epssMax: '1' })).toEqual({});
    expect(v({ epssMin: '0.5', epssMax: '.75' })).toEqual({});
  });
  it('rejects out of range, non-numeric and inverted bounds', () => {
    expect(v({ epssMin: '1.01' }).epssMin).toBeDefined();
    expect(v({ epssMax: '-0.1' }).epssMax).toBeDefined();
    expect(v({ epssMax: 'abc' }).epssMax).toBeDefined();
    expect(v({ epssMin: '1e-1' }).epssMin).toBeDefined();
    expect(v({ epssMin: '0.8', epssMax: '0.2' }).epssMin).toBeDefined();
  });
  it('limits the ecosystem to the known list and sends params', () => {
    expect(v({ ecosystem: 'PyPI' })).toEqual({});
    expect(v({ ecosystem: 'pypi' }).ecosystem).toBeDefined();
    expect(filtersToParams({ ...emptyFilters, epssMin: ' 0.1 ', ecosystem: 'npm' })).toEqual({ epssMin: '0.1', ecosystem: 'npm' });
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
  const g = (buildState: string, buildMode: string | null) => ({ buildState, buildMode });
  it('is hidden only when ready and full', () => {
    expect(bannerMessage(null)).toBeNull();
    expect(bannerMessage(g('ready', 'full'))).toBeNull();
    expect(bannerMessage(g('ready', null))).toBeNull();
  });
  it('names both values otherwise', () => {
    const m = bannerMessage(g('nvd_catch_up', 'full'));
    expect(m).toContain('nvd_catch_up');
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
