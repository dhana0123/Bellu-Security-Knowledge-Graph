/** Route for an entity's graph view. */
export function graphPath(type: string, id: string): string {
  return `/graph/${encodeURIComponent(type)}/${encodeURIComponent(id)}`;
}

const EXTERNAL_HOSTS: ReadonlySet<string> = new Set(['github.com', 'gitlab.com', 'bitbucket.org']);

/** Returns the URL when it is an https URL on github.com, gitlab.com or bitbucket.org (no credentials, default port), otherwise null. */
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
