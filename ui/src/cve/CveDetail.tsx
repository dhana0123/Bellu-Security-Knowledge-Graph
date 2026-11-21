import { Link, useParams } from 'react-router';
import { useAuth } from '../auth/AuthContext';
import { card, h1, h2, link, muted, td, th } from '../common/classes';
import { ErrorMessage, Loading } from '../common/ErrorMessage';
import { SeverityBadge } from '../common/SeverityBadge';
import { useRequest } from '../common/useRequest';
import { graphPath } from './links';

function show(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

export function CveDetail() {
  const { id = '' } = useParams();
  const { client, sources: sourceInfo } = useAuth();
  const req = useRequest((signal) => client.cve(id, signal), [client, id]);
  const d = req.data;

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
