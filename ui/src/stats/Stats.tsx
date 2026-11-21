import { useAuth } from '../auth/AuthContext';
import type { CountEntry, TopEntry } from '../api/types';
import { ErrorMessage, Loading } from '../common/ErrorMessage';
import { formatPercent } from '../common/text';
import { useRequest } from '../common/useRequest';
import { BarChart } from './BarChart';

function CountTable({ title, rows }: { title: string; rows: CountEntry[] }) {
  return (
    <table aria-label={title}>
      <caption>{title}</caption>
      <tbody>
        {rows.map((r) => (
          <tr key={r.name}>
            <th scope="row">{r.name}</th>
            <td>{r.count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Top({ title, rows }: { title: string; rows: TopEntry[] }) {
  return (
    <div>
      <h3>{title}</h3>
      <ol>
        {rows.map((r) => (
          <li key={r.key}>
            {r.key}: {r.count}
          </li>
        ))}
      </ol>
    </div>
  );
}

export function Stats() {
  const { client, graph } = useAuth();
  const req = useRequest((signal) => client.stats(signal), [client]);
  const s = req.data;
  return (
    <section>
      <h1>Statistics</h1>
      <button type="button" disabled={req.loading} onClick={req.reload}>
        Refresh
      </button>
      <Loading active={req.loading} />
      <ErrorMessage error={req.error} />
      {s && (
        <>
          {s.statsStale && (
            <p role="status" className="banner">
              These statistics are stale: the latest computation failed and the previous result is shown.
            </p>
          )}
          <p>
            Build state: {graph?.buildState ?? 'unknown'}. Build mode: {graph?.buildMode ?? 'not set'}.
            {s.generatedAt ? ` Generated at ${s.generatedAt}.` : ''}
          </p>
          <p>
            Exploited share: {formatPercent(s.exploited.ratio)} ({s.exploited.exploited} of {s.exploited.total})
          </p>
          <BarChart title="CVEs by year" data={s.byYear} />
          <BarChart title="CVSS v3 severity distribution" data={s.bySeverity} />
          <h2>Top 10</h2>
          <Top title="Weaknesses" rows={s.topWeaknesses} />
          <Top title="Vendors" rows={s.topVendors} />
          <Top title="Products" rows={s.topProducts} />
          <h2>Counts</h2>
          <CountTable title="Nodes per type" rows={s.labelCounts} />
          <CountTable title="Relationships per type" rows={s.relationshipCounts} />
          <h2>Sync status per source</h2>
          <table aria-label="Sync status">
            <thead>
              <tr>
                <th scope="col">Source</th>
                <th scope="col">Status</th>
                <th scope="col">Last success</th>
                <th scope="col">Dead letters</th>
              </tr>
            </thead>
            <tbody>
              {s.sync.map((x) => (
                <tr key={x.source}>
                  <td>{x.source}</td>
                  <td>{x.status}</td>
                  <td>{x.lastSuccess ?? 'never'}</td>
                  <td>{x.deadLetters ?? ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}
