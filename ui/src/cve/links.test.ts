import { describe, expect, it } from 'vitest';
import { graphPath, safeExternalUrl } from './links';

describe('safeExternalUrl', () => {
  it.each([
    'https://github.com/o/r',
    'https://gitlab.com/o/r/-/commit/abc',
    'https://bitbucket.org/o/r/commits/abc',
  ])('allows %s', (u) => expect(safeExternalUrl(u)).toBe(u));
  it.each([
    'http://github.com/o/r',
    'javascript:alert(1)',
    'https://evil.example/github.com',
    'https://github.com.evil.example/o/r',
    'https://user:pw@github.com/o/r',
    'https://github.com:8443/o/r',
    'data:text/html,x',
    '//github.com/o/r',
    '',
    'not a url',
  ])('rejects %s', (u) => expect(safeExternalUrl(u)).toBeNull());
  it('rejects non-strings', () => {
    expect(safeExternalUrl(undefined)).toBeNull();
    expect(safeExternalUrl(5)).toBeNull();
  });
});

describe('graphPath', () => {
  it('encodes keys with / and @', () => {
    const key = `https://github.com/o/r@${'a'.repeat(40)}`;
    const p = graphPath('FixCommit', key);
    expect(p).toBe(`/graph/FixCommit/${encodeURIComponent(key)}`);
    expect(p.split('/')).toHaveLength(4);
  });
});
