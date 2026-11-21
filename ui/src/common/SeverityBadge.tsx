import { SEVERITY_CLASSES, severityOf } from './severity';
import type { Severity } from './severity';

export function SeverityBadge({ score, severity }: { score?: number | null; severity?: Severity }) {
  const s = severity ?? severityOf(score);
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ring-1 ring-inset ${SEVERITY_CLASSES[s]}`}>
      {s}
      {score !== null && score !== undefined && s !== 'UNSCORED' ? ` ${score}` : ''}
    </span>
  );
}
