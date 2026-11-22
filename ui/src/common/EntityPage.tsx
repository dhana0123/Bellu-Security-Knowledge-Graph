import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { ApiError } from '../api/errors';
import { card, h1, h2, link, muted, td, th } from './classes';
import { ErrorMessage, Loading } from './ErrorMessage';
import { ExternalLink } from './ExternalLink';
import { graphPath } from '../cve/links';

function show(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}
/** Shared frame for the entity pages: title, graph link, properties table, then the page's lists. */
export function EntityPage(props: {
  title: string;
  graphType: string;
  graphKey: string;
  loading: boolean;
  error: ApiError | null;
  properties?: Record<string, unknown>;
  children?: ReactNode;
}) {
  const url = props.properties?.url;
  return (
    <section className={`${card} space-y-1`}>
      <h1 className={h1}>{props.title}</h1>
      <p className="mb-2">
        <Link className={link} to={graphPath(props.graphType, props.graphKey)}>
          Open in graph
        </Link>
        {typeof url === 'string' && (
          <>
            {' · '}
            <ExternalLink href={url}>External reference</ExternalLink>
          </>
        )}
      </p>
      <Loading active={props.loading} />
      <ErrorMessage error={props.error} />
      {props.properties && (
        <>
          <h2 className={h2}>Properties</h2>
          <table className="w-full border-collapse text-sm">
            <tbody>
              {Object.entries(props.properties).map(([k, v]) => (
                <tr key={k}>
                  <th scope="row" className={`${th} w-48`}>
                    {k}
                  </th>
                  <td className={`${td} break-words`}>{show(v)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      {props.children}
    </section>
  );
}
/** A titled list of links; "None" when empty. */
export function LinkList<T>({ title, items, render }: { title: string; items: T[]; render: (item: T) => ReactNode }) {
  return (
    <>
      <h2 className={h2}>{title}</h2>
      {items.length === 0 ? (
        <p className={muted}>None</p>
      ) : (
        <ul className="list-inside list-disc space-y-1">
          {items.map((it, i) => (
            <li key={i}>{render(it)}</li>
          ))}
        </ul>
      )}
    </>
  );
}
