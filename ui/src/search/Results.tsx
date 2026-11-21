import { Link } from 'react-router';
import type { VulnerabilityRow } from '../api/types';
import { truncate } from '../common/text';

export function Results({ items, page }: { items: VulnerabilityRow[]; page: number }) {
  return (
    <table aria-label={`Results page ${page}`}>
      <thead>
        <tr>
          <th scope="col">CVE</th>
          <th scope="col">Published</th>
          <th scope="col">CVSS v3</th>
          <th scope="col">Exploitability</th>
          <th scope="col">Description</th>
        </tr>
      </thead>
      <tbody>
        {items.map((r) => (
          <tr key={r.cveID}>
            <td>
              <Link to={`/cve/${encodeURIComponent(r.cveID)}`}>{r.cveID}</Link>
            </td>
            <td>{r.publishedDate ?? ''}</td>
            <td>{r.v3baseScore ?? ''}</td>
            <td>{r.exploitability ?? ''}</td>
            <td>{truncate(r.description ?? '', 200)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
