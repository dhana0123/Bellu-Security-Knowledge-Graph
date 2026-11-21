import { Link } from 'react-router';
import type { VulnerabilityRow } from '../api/types';
import { link, table, td, th } from '../common/classes';
import { SeverityBadge } from '../common/SeverityBadge';
import { truncate } from '../common/text';

export function Results({ items, page }: { items: VulnerabilityRow[]; page: number }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900">
      <table className={table} aria-label={`Results page ${page}`}>
        <thead>
          <tr>
            <th scope="col" className={th}>CVE</th>
            <th scope="col" className={th}>Published</th>
            <th scope="col" className={th}>CVSS v3</th>
            <th scope="col" className={th}>Exploitability</th>
            <th scope="col" className={th}>Description</th>
          </tr>
        </thead>
        <tbody>
          {items.map((r) => (
            <tr key={r.cveID} className="hover:bg-slate-800/40">
              <td className={`${td} whitespace-nowrap`}>
                <Link className={link} to={`/cve/${encodeURIComponent(r.cveID)}`}>
                  {r.cveID}
                </Link>
              </td>
              <td className={`${td} whitespace-nowrap`}>{r.publishedDate ?? ''}</td>
              <td className={`${td} whitespace-nowrap`}>
                <SeverityBadge score={r.v3baseScore} />
              </td>
              <td className={td}>{r.exploitability ?? ''}</td>
              <td className={td}>{truncate(r.description ?? '', 200)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
