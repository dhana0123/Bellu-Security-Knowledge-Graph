import type { GraphEnvelope } from '../api/types';

/** Banner text when the build is not ready or is a sample build; null otherwise. */
export function bannerMessage(g: GraphEnvelope | null): string | null {
  if (!g) return null;
  if (g.buildState === 'ready' && g.buildMode !== 'sample') return null;
  return `Graph build state: ${g.buildState}. Build mode: ${g.buildMode ?? 'not set'}.${
    g.buildMode === 'sample' ? ' This is a sample build; data is incomplete.' : ''
  }`;
}
