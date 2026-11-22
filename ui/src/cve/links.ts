/** Route for an entity's graph view. */
export function graphPath(type: string, id: string): string {
  return `/graph/${encodeURIComponent(type)}/${encodeURIComponent(id)}`;
}

const EXTERNAL_HOSTS: ReadonlySet<string> = new Set([
  'github.com', // includes github.com/advisories
  'gitlab.com',
  'bitbucket.org',
  'attack.mitre.org',
  'capec.mitre.org',
  'atlas.mitre.org',
  'osv.dev',
]);

/** Returns the URL when it is an https URL on a code host, a MITRE site (attack, capec, atlas) or osv.dev (no credentials, default port), otherwise null. */
export function safeExternalUrl(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  let u: URL;
  try {
    u = new URL(value.trim());
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || !EXTERNAL_HOSTS.has(u.hostname) || u.username || u.password || u.port) return null;
  return u.href;
}

export const packagePath = (purl: string): string => `/package/${encodeURIComponent(purl)}`;
export const attackPatternPath = (id: string): string => `/attack-pattern/${encodeURIComponent(id)}`;
export const techniquePath = (id: string): string => `/technique/${encodeURIComponent(id)}`;
export const atlasTechniquePath = (id: string): string => `/atlas-technique/${encodeURIComponent(id)}`;
export const cvePath = (id: string): string => `/cve/${encodeURIComponent(id)}`;
