import { Link, useParams } from 'react-router';
import { useAuth } from '../auth/AuthContext';
import { card, h1, h2, link, muted, td, th } from '../common/classes';
import { ErrorMessage, Loading } from '../common/ErrorMessage';
import { ExternalLink } from '../common/ExternalLink';
import { SeverityBadge } from '../common/SeverityBadge';
import { useRequest } from '../common/useRequest';
import { repoPath } from '../graph/style';
import { KevBadge } from '../common/KevBadge';
import { attackPatternPath, graphPath, packagePath, techniquePath } from './links';
import type { CoPage } from '../api/types';

function show(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

const str = (v: unknown): string => (typeof v === 'string' ? v : '');
const text = (v: unknown): string => (typeof v === 'string' || typeof v === 'number' ? String(v) : '');

function KevPanel({ v }: { v: Record<string, unknown> }) {
  if (v.kev !== true) return null;
  return (
    <div role="status" className="mb-2 rounded-md border border-red-700 bg-red-950 px-3 py-2 text-sm text-red-100">
      <KevBadge label="Known exploited" />
      {str(v.kevVulnerabilityName) && <span className="ml-2">{str(v.kevVulnerabilityName)}</span>}
      <ul className="mt-1 list-inside list-disc">
        {str(v.kevDateAdded) && <li>Added to KEV: {str(v.kevDateAdded)}</li>}
        {str(v.kevDueDate) && <li>Remediation due: {str(v.kevDueDate)}</li>}
        {text(v.kevRansomwareUse) && <li>Known ransomware campaign use: {text(v.kevRansomwareUse)}</li>}
      </ul>
    </div>
  );
}
function EpssPanel({ v }: { v: Record<string, unknown> }) {
  if (typeof v.epssScore !== 'number') return null;
  const pct = typeof v.epssPercentile === 'number' ? v.epssPercentile : null;
  const width = Math.min(100, Math.max(0, v.epssScore * 100));
  return (
    <div className="mb-2 text-sm text-slate-300">
      EPSS {v.epssScore.toFixed(4)}
      {pct !== null ? `, percentile ${(pct * 100).toFixed(1)}%` : ''}
      {str(v.epssDate) ? ` (${str(v.epssDate)})` : ''}
      <div
        role="meter"
        aria-label="EPSS score"
        aria-valuemin={0}
        aria-valuemax={1}
        aria-valuenow={v.epssScore}
        className="mt-1 h-2 w-48 rounded bg-slate-800"
      >
        <div className="h-2 rounded bg-amber-400" style={{ width: `${width}%` }} />
      </div>
    </div>
  );
}
function CoSection({ title, req }: { title: string; req: { data: CoPage | null | undefined; loading: boolean; error: unknown } }) {
  if (req.loading || req.error || !req.data) return null; // null data: feature off (404), so no section
  const d = req.data;
  return (
    <>
      <h2 className={h2}>{title}</h2>
      {d.items.length === 0 ? <p className={muted}>None</p> : (
        <ul className="list-inside list-disc space-y-1">
          {d.items.slice(0, 10).map((i) => (
            <li key={i.cveID}>
              <Link className={link} to={`/cve/${encodeURIComponent(i.cveID)}`}>{i.cveID}</Link>
              {` shared ${i.shared}`} <SeverityBadge score={i.v3baseScore} />
            </li>
          ))}
        </ul>
      )}
      {d.found > d.items.length && <p className={`${muted} text-xs`}>{d.found} found, top {d.items.length} shown.</p>}
      {d.skippedProducts ? <p className={`${muted} text-xs`}>{d.skippedProducts} very common products were skipped.</p> : null}
    </>
  );
}
export function CveDetail() {
  const { id = '' } = useParams();
  const { client, sources: sourceInfo } = useAuth();
  const req = useRequest((signal) => client.cve(id, signal), [client, id]);
  const d = req.data;
  const coExploited = useRequest((signal) => client.coExploited(id, signal), [client, id]);
  const coAffected = useRequest((signal) => client.coAffected(id, signal), [client, id]);
  const aliases = Array.isArray(d?.vulnerability.aliases) ? (d.vulnerability.aliases as unknown[]).filter((a): a is string => typeof a === 'string') : [];

  return (
    <section className={`${card} space-y-1`}>
      <div className="mb-2 flex flex-wrap items-center gap-3">
        <h1 className={`${h1} mb-0`}>{id}</h1>
        <SeverityBadge score={typeof d?.vulnerability.v3baseScore === 'number' ? d.vulnerability.v3baseScore : null} />
      </div>
      <p className="mb-2">
        <Link className={link} to={graphPath('Vulnerability', id)}>
          Open in graph
        </Link>
      </p>
      <Loading active={req.loading} />
      <ErrorMessage error={req.error} />
      {d && (
        <>
          <KevPanel v={d.vulnerability} />
          <EpssPanel v={d.vulnerability} />
          {(str(d.vulnerability.osvSeverity) || str(d.vulnerability.ghsaSeverity) || str(d.vulnerability.ghsaSummary) || str(d.vulnerability.osvSummary)) && (
            <ul className="mb-2 list-inside list-disc text-sm text-slate-300">
              {str(d.vulnerability.osvSeverity) && <li>OSV severity: {str(d.vulnerability.osvSeverity)}</li>}
              {str(d.vulnerability.ghsaSeverity) && (
                <li>
                  GHSA severity: {str(d.vulnerability.ghsaSeverity)}
                  {text(d.vulnerability.ghsaCvssScore) ? ` (CVSS ${text(d.vulnerability.ghsaCvssScore)})` : ''}
                </li>
              )}
              {str(d.vulnerability.osvSummary) && <li>OSV: {str(d.vulnerability.osvSummary)}</li>}
              {str(d.vulnerability.ghsaSummary) && <li>GHSA: {str(d.vulnerability.ghsaSummary)}</li>}
            </ul>
          )}
          {aliases.length > 0 && (
            <p className="mb-2 text-sm text-slate-300">
              Aliases: {aliases.join(', ')}
            </p>
          )}
          <h2 className={h2}>Properties</h2>
          <table className="w-full border-collapse text-sm">
            <tbody>
              {Object.entries(d.vulnerability).map(([k, v]) => (
                <tr key={k}>
                  <th scope="row" className={`${th} w-48`}>
                    {k}
                  </th>
                  <td className={`${td} break-words`}>{show(v)}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h2 className={h2}>Packages</h2>
          {d.packages.length === 0 ? <p className={muted}>None</p> : (
            <ul className="list-inside list-disc space-y-1">
              {d.packages.map((p) => (
                <li key={p.purl}>
                  <Link className={link} to={packagePath(p.purl)}>{p.name || p.purl}</Link>
                  {p.ecosystem ? ` (${p.ecosystem})` : ''}
                  {p.introduced ? `, introduced ${p.introduced}` : ''}
                  {p.fixed ? `, fixed ${p.fixed}` : ''}
                  {p.lastAffected ? `, last affected ${p.lastAffected}` : ''}
                  {p.affectedRanges.length > 0 ? `, ranges ${p.affectedRanges.join('; ')}` : ''}
                  {' · '}
                  <Link className={link} to={graphPath('Package', p.purl)}>Open in graph</Link>
                </li>
              ))}
            </ul>
          )}
          <h2 className={h2}>Attack patterns</h2>
          {d.attackPatterns.length === 0 ? <p className={muted}>None</p> : (
            <ul className="list-inside list-disc space-y-1">
              {d.attackPatterns.map((a) => (
                <li key={a.capecID}>
                  <Link className={link} to={attackPatternPath(a.capecID)}>{a.capecID}</Link>
                  {a.name ? ` ${a.name}` : ''}
                  {a.viaWeakness ? ` (via ${a.viaWeakness})` : ''}
                </li>
              ))}
            </ul>
          )}
          <h2 className={h2}>ATT&amp;CK techniques</h2>
          {d.techniques.length === 0 ? <p className={muted}>None</p> : (
            <ul className="list-inside list-disc space-y-1">
              {d.techniques.map((t) => (
                <li key={t.attackID}>
                  <Link className={link} to={techniquePath(t.attackID)}>{t.attackID}</Link>
                  {t.name ? ` ${t.name}` : ''}
                  {t.viaAttackPattern ? ` (via ${t.viaAttackPattern})` : ''}
                </li>
              ))}
            </ul>
          )}
          <CoSection title="Co-exploited with" req={coExploited} />
          <CoSection title="Co-affected with" req={coAffected} />
          <h2 className={h2}>Weaknesses</h2>
          {d.weaknesses.length === 0 ? <p className={muted}>None</p> : (
            <ul className="list-inside list-disc space-y-1">
              {d.weaknesses.map((w) => (
                <li key={w}><Link className={link} to={graphPath('Weakness', w)}>{w}</Link></li>
              ))}
            </ul>
          )}

          <h2 className={h2}>Exploits</h2>
          {d.exploits.length === 0 ? <p className={muted}>None</p> : (
            <ul className="list-inside list-disc space-y-1">
              {d.exploits.map((x) => (
                <li key={x.eid}>
                  <Link className={link} to={graphPath('Exploit', x.eid)}>{x.eid}</Link>
                  {x.exploitType ? ` ${x.exploitType}` : ''}
                  {x.platform ? ` on ${x.platform}` : ''}
                  {x.exploitPublishDate ? `, published ${x.exploitPublishDate}` : ''}
                  {x.authors.length > 0 && (
                    <>
                      {' by '}
                      {x.authors.map((a, i) => (
                        <span key={a}>
                          {i > 0 && ', '}
                          <Link className={link} to={graphPath('Author', a)}>{a}</Link>
                        </span>
                      ))}
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}

          <h2 className={h2}>Products and vendors</h2>
          {d.products.length === 0 ? <p className={muted}>None</p> : (
            <ul className="list-inside list-disc space-y-1">
              {d.products.map((p, i) => (
                <li key={`${p.productName}-${i}`}>
                  <Link className={link} to={graphPath('Product', p.productName)}>{p.productName}</Link>
                  {p.affectedVersion ? ` (${p.affectedVersion})` : ''}
                  {p.vendors.length > 0 && (
                    <>
                      {' from '}
                      {p.vendors.map((v, j) => (
                        <span key={v}>
                          {j > 0 && ', '}
                          <Link className={link} to={graphPath('Vendor', v)}>{v}</Link>
                        </span>
                      ))}
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}

          <h2 className={h2}>Domains</h2>
          {d.domains.length === 0 ? <p className={muted}>None</p> : (
            <ul className="list-inside list-disc space-y-1">
              {d.domains.map((x) => (
                <li key={x}><Link className={link} to={graphPath('Domain', x)}>{x}</Link></li>
              ))}
            </ul>
          )}

          <h2 className={h2}>Repositories</h2>
          {d.repositories.length === 0 ? <p className={muted}>None</p> : (
            <ul className="list-inside list-disc space-y-1">
              {d.repositories.map((r) => (
                <li key={r.url}>
                  <ExternalLink href={r.url}>{repoPath(r.url)}</ExternalLink>
                  {r.host ? ` (${r.host})` : ''}
                  {' · '}
                  <Link className={link} to={graphPath('Repository', r.url)}>Open in graph</Link>
                </li>
              ))}
            </ul>
          )}
          <h2 className={h2}>Fix commits</h2>
          {d.fixCommits.length === 0 ? <p className={muted}>None</p> : (
            <ul className="list-inside list-disc space-y-1">
              {d.fixCommits.map((c) => (
                <li key={`${c.repoUrl}@${c.sha}`}>
                  <ExternalLink href={c.url || c.repoUrl}>{c.sha.slice(0, 7)}</ExternalLink>
                  {c.repoUrl ? ` in ${repoPath(c.repoUrl)}` : ''}
                  {' · '}
                  <Link className={link} to={graphPath('FixCommit', `${c.repoUrl}@${c.sha}`)}>Open in graph</Link>
                </li>
              ))}
            </ul>
          )}
          <h2 className={h2}>Sources</h2>
          <ul className="list-inside list-disc space-y-1">
            {d.sources.map((s) => {
              const info = sourceInfo.find((i) => i.name.toLowerCase() === s.toLowerCase());
              return (
                <li key={s}>
                  <strong>{s}</strong>
                  {info?.license ? ` (${info.license})` : ''}
                  {info?.attribution ? <p className={muted}>{info.attribution}</p> : null}
                </li>
              );
            })}
          </ul>
        </>
      )}
    </section>
  );
}
