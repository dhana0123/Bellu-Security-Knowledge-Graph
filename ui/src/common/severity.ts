export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNSCORED';

/** CVSS v3 qualitative rating of a base score; anything missing or not above zero is UNSCORED. */
export function severityOf(score: number | null | undefined): Severity {
  if (score === null || score === undefined || !Number.isFinite(score) || score <= 0) return 'UNSCORED';
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  return 'LOW';
}

export const SEVERITY_CLASSES: Record<Severity, string> = {
  CRITICAL: 'bg-red-600/20 text-red-300 ring-red-500/50',
  HIGH: 'bg-orange-500/20 text-orange-300 ring-orange-500/50',
  MEDIUM: 'bg-amber-400/20 text-amber-300 ring-amber-400/50',
  LOW: 'bg-green-500/20 text-green-300 ring-green-500/50',
  UNSCORED: 'bg-slate-500/20 text-slate-300 ring-slate-500/50',
};

/** Normalizes a severity name from the API (any case) to a Severity, UNSCORED when unknown. */
export function severityFromName(name: string): Severity {
  const up = name.trim().toUpperCase();
  return up in SEVERITY_CLASSES ? (up as Severity) : 'UNSCORED';
}
