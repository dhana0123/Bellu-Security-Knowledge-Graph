import { Link, useParams } from 'react-router';
import { useAuth } from '../auth/AuthContext';
import { ErrorMessage, Loading } from '../common/ErrorMessage';
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
    <section>
      <h1>{id}</h1>
      <p>
        <Link to={graphPath('Vulnerability', id)}>Open in graph</Link>
      </p>
      <Loading active={req.loading} />
      <ErrorMessage error={req.error} />
      {d && (
        <>
          <h2>Properties</h2>
          <table>
            <tbody>
              {Object.entries(d.vulnerability).map(([k, v]) => (
                <tr key={k}>
                  <th scope="row">{k}</th>
                  <td>{show(v)}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h2>Weaknesses</h2>
          {d.weaknesses.length === 0 ? <p className="muted">None</p> : (
            <ul>
              {d.weaknesses.map((w) => (
                <li key={w}><Link to={graphPath('Weakness', w)}>{w}</Link></li>
              ))}
            </ul>
          )}

          <h2>Exploits</h2>
          {d.exploits.length === 0 ? <p className="muted">None</p> : (
            <ul>
              {d.exploits.map((x) => (
                <li key={x.eid}>
                  <Link to={graphPath('Exploit', x.eid)}>{x.eid}</Link>
                  {x.exploitType ? ` ${x.exploitType}` : ''}
                  {x.platform ? ` on ${x.platform}` : ''}
                  {x.exploitPublishDate ? `, published ${x.exploitPublishDate}` : ''}
                  {x.authors.length > 0 && (
                    <>
                      {' by '}
                      {x.authors.map((a, i) => (
                        <span key={a}>
                          {i > 0 && ', '}
                          <Link to={graphPath('Author', a)}>{a}</Link>
                        </span>
                      ))}
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}

          <h2>Products and vendors</h2>
          {d.products.length === 0 ? <p className="muted">None</p> : (
            <ul>
              {d.products.map((p, i) => (
                <li key={`${p.productName}-${i}`}>
                  <Link to={graphPath('Product', p.productName)}>{p.productName}</Link>
                  {p.affectedVersion ? ` (${p.affectedVersion})` : ''}
                  {p.vendors.length > 0 && (
                    <>
                      {' from '}
                      {p.vendors.map((v, j) => (
                        <span key={v}>
                          {j > 0 && ', '}
                          <Link to={graphPath('Vendor', v)}>{v}</Link>
                        </span>
                      ))}
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}

          <h2>Domains</h2>
          {d.domains.length === 0 ? <p className="muted">None</p> : (
            <ul>
              {d.domains.map((x) => (
                <li key={x}><Link to={graphPath('Domain', x)}>{x}</Link></li>
              ))}
            </ul>
          )}

          <h2>Sources</h2>
          <ul>
            {d.sources.map((s) => {
              const info = sourceInfo.find((i) => i.name.toLowerCase() === s.toLowerCase());
              return (
                <li key={s}>
                  <strong>{s}</strong>
                  {info?.license ? ` (${info.license})` : ''}
                  {info?.attribution ? <p>{info.attribution}</p> : null}
                </li>
              );
            })}
          </ul>
        </>
      )}
    </section>
  );
}
