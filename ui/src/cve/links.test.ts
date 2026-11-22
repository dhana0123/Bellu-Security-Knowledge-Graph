import { describe, expect, it } from 'vitest';
import { atlasTechniquePath, attackPatternPath, graphPath, packagePath, safeExternalUrl, techniquePath } from './links';

describe('safeExternalUrl', () => {
  it.each([
    'https://github.com/o/r',
    'https://gitlab.com/o/r/-/commit/abc',
    'https://bitbucket.org/o/r/commits/abc',
    'https://attack.mitre.org/techniques/T1059/',
    'https://capec.mitre.org/data/definitions/66.html',
    'https://atlas.mitre.org/techniques/AML.T0000',
    'https://osv.dev/vulnerability/GHSA-xxxx',
    'https://github.com/advisories/GHSA-xxxx',
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
    'http://attack.mitre.org/techniques/T1059/',
    'https://mitre.org/x',
    'https://attack.mitre.org.evil.example/x',
    'https://evil.example/attack.mitre.org',
    'https://osv.dev:444/x',
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

describe('entity paths', () => {
  it('encode keys', () => {
    const purl = 'pkg:npm/@scope/name@1.0.0?x=y#z';
    expect(packagePath(purl)).toBe(`/package/${encodeURIComponent(purl)}`);
    expect(packagePath(purl).split('/')).toHaveLength(3);
    expect(attackPatternPath('CAPEC-66')).toBe('/attack-pattern/CAPEC-66');
    expect(techniquePath('T1059.001')).toBe('/technique/T1059.001');
    expect(atlasTechniquePath('AML.T0000')).toBe('/atlas-technique/AML.T0000');
  });
});
