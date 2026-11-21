import type { CountEntry } from '../api/types';

/** Horizontal bar chart drawn as SVG with attribute-only geometry (no inline CSS). */
export function BarChart({ title, data }: { title: string; data: CountEntry[] }) {
  const max = Math.max(1, ...data.map((d) => d.count));
  const row = 18;
  const labelW = 90;
  const barW = 400;
  const h = Math.max(1, data.length) * row;
  return (
    <figure className="mb-6">
      <figcaption className="mb-2 text-sm font-semibold text-slate-200">{title}</figcaption>
      {data.length === 0 ? (
        <p className="text-slate-400">No data</p>
      ) : (
        <svg role="img" aria-label={title} width={labelW + barW + 70} height={h}>
          {data.map((d, i) => (
            <g key={d.name} transform={`translate(0 ${i * row})`}>
              <text className="fill-slate-300 text-[11px]" x={labelW - 4} y={13} textAnchor="end">
                {d.name}
              </text>
              <rect className="fill-sky-500" x={labelW} y={2} height={row - 4} width={(d.count / max) * barW} />
              <text className="fill-slate-300 text-[11px]" x={labelW + (d.count / max) * barW + 4} y={13}>
                {d.count}
              </text>
            </g>
          ))}
        </svg>
      )}
    </figure>
  );
}
