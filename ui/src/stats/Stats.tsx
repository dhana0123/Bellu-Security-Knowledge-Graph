import { useAuth } from '../auth/AuthContext';
import type { CountEntry, TopEntry } from '../api/types';
import { btn, card, h1, h2, td, th } from '../common/classes';
import { ErrorMessage, Loading } from '../common/ErrorMessage';
import { formatPercent } from '../common/text';
import { useRequest } from '../common/useRequest';
import { BarChart } from './BarChart';

function CountTable({ title, rows }: { title: string; rows: CountEntry[] }) {
  return (
    <table aria-label={title} className="w-full border-collapse text-sm">
      <caption className="mb-1 text-left font-semibold text-slate-200">{title}</caption>
      <tbody>
        {rows.map((r) => (
          <tr key={r.name}>
            <th scope="row" className={`${th} font-normal`}>
              {r.name}
            </th>
            <td className={td}>{r.count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Top({ title, rows }: { title: string; rows: TopEntry[] }) {
  return (
    <div className={card}>
      <h3 className="mb-2 font-semibold text-slate-100">{title}</h3>
      <ol className="list-inside list-decimal space-y-1 text-sm text-slate-300">
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
      <h1 className={h1}>Statistics</h1>
      <button type="button" className={btn} disabled={req.loading} onClick={req.reload}>
        Refresh
      </button>
      <Loading active={req.loading} />
      <ErrorMessage error={req.error} />
      {s && (
        <>
          {s.statsStale && (
            <p role="status" className="my-3 rounded-md bg-amber-400 px-3 py-2 text-sm font-semibold text-slate-950">
              These statistics are stale: the latest computation failed and the previous result is shown.
            </p>
          )}
          <p className="my-3 text-sm text-slate-300">
            Build state: {graph?.buildState ?? 'unknown'}. Build mode: {graph?.buildMode ?? 'not set'}.
            {s.generatedAt ? ` Generated at ${s.generatedAt}.` : ''}
          </p>
          <p className="my-3 text-sm text-slate-300">
            Exploited share: {formatPercent(s.exploited.ratio)} ({s.exploited.exploited} of {s.exploited.total})
          </p>
          <BarChart title="CVEs by year" data={s.byYear} />
          <BarChart title="CVSS v3 severity distribution" data={s.bySeverity} />
          <h2 className={h2}>Top 10</h2>
          <div className="grid gap-4 md:grid-cols-3">
            <Top title="Weaknesses" rows={s.topWeaknesses} />
          <Top title="Vendors" rows={s.topVendors} />
          <Top title="Products" rows={s.topProducts} />
          </div>
          <h2 className={h2}>Counts</h2>
          <div className="grid gap-6 md:grid-cols-2">
            <CountTable title="Nodes per type" rows={s.labelCounts} />
            <CountTable title="Relationships per type" rows={s.relationshipCounts} />
          </div>
          <h2 className={h2}>Sync status per source</h2>
          <table aria-label="Sync status" className="w-full border-collapse text-sm">
            <thead>
              <tr>
                <th scope="col" className={th}>Source</th>
                <th scope="col" className={th}>Status</th>
                <th scope="col" className={th}>Last success</th>
                <th scope="col" className={th}>Dead letters</th>
              </tr>
            </thead>
            <tbody>
              {s.sync.map((x) => (
                <tr key={x.source}>
                  <td className={td}>{x.source}</td>
                  <td className={td}>{x.status}</td>
                  <td className={td}>{x.lastSuccess ?? 'never'}</td>
                  <td className={td}>{x.deadLetters ?? ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}
