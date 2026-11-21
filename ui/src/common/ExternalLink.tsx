import type { ReactNode } from 'react';
import { safeExternalUrl } from '../cve/links';
import { link } from './classes';

/** A link to an allowed code host (https on github.com, gitlab.com or bitbucket.org); anything else is plain text. */
export function ExternalLink({ href, children }: { href: unknown; children: ReactNode }) {
  const safe = safeExternalUrl(href);
  if (!safe) return <span className="break-all">{children}</span>;
  return (
    <a className={link} href={safe} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  );
}
