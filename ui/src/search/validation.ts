import type { SearchFilters } from '../api/types';

export const emptyFilters: SearchFilters = {
  q: '',
  publishedFrom: '',
  publishedTo: '',
  cvssV3Min: '',
  cvssV3Max: '',
  exploitability: '',
  kev: false,
  epssMin: '',
  epssMax: '',
  ecosystem: '',
  cwe: '',
  includeRejected: false,
};

export type FilterErrors = Partial<Record<keyof SearchFilters, string>>;

const MAX_Q = 500;

function score(s: string): number | null | 'bad' {
  const t = s.trim();
  if (t === '') return null;
  if (!/^\d+(\.\d+)?$/.test(t)) return 'bad';
  const n = Number(t);
  return n >= 0 && n <= 10 ? n : 'bad';
}

/** OSV ecosystems the API accepts for the ecosystem filter. */
export const ECOSYSTEMS: readonly string[] = [
  'npm', 'PyPI', 'Go', 'Maven', 'crates.io', 'RubyGems', 'NuGet', 'Packagist', 'Pub', 'Hex', 'GitHub Actions', 'SwiftURL',
];
/** A probability from 0 to 1 as plain decimal text: null when empty, 'bad' when invalid. */
function prob(s: string): number | null | 'bad' {
  const t = s.trim();
  if (t === '') return null;
  if (!/^(\d+(\.\d+)?|\.\d+)$/.test(t)) return 'bad';
  const n = Number(t);
  return n >= 0 && n <= 1 ? n : 'bad';
}
/** Returns the violated rules by field. Empty object means the filters are valid. */
export function validateFilters(f: SearchFilters): FilterErrors {
  const e: FilterErrors = {};
  if ([...f.q].length > MAX_Q) e.q = `Text must be at most ${MAX_Q} characters`;
  const min = score(f.cvssV3Min);
  const max = score(f.cvssV3Max);
  if (min === 'bad') e.cvssV3Min = 'Score must be from 0.0 to 10.0';
  if (max === 'bad') e.cvssV3Max = 'Score must be from 0.0 to 10.0';
  if (typeof min === 'number' && typeof max === 'number' && min > max) {
    e.cvssV3Min = 'Minimum score must not be above the maximum';
  }
  const emin = prob(f.epssMin);
  const emax = prob(f.epssMax);
  if (emin === 'bad') e.epssMin = 'EPSS must be from 0 to 1';
  if (emax === 'bad') e.epssMax = 'EPSS must be from 0 to 1';
  if (typeof emin === 'number' && typeof emax === 'number' && emin > emax) {
    e.epssMin = 'Minimum EPSS must not be above the maximum';
  }
  if (f.ecosystem !== '' && !ECOSYSTEMS.includes(f.ecosystem)) e.ecosystem = 'Choose an ecosystem from the list';
  const dateOk = (s: string) => s === '' || /^\d{4}-\d{2}-\d{2}$/.test(s);
  if (!dateOk(f.publishedFrom)) e.publishedFrom = 'Use the format YYYY-MM-DD';
  if (!dateOk(f.publishedTo)) e.publishedTo = 'Use the format YYYY-MM-DD';
  if (!e.publishedFrom && !e.publishedTo && f.publishedFrom && f.publishedTo && f.publishedFrom > f.publishedTo) {
    e.publishedFrom = 'From date must not be after the to date';
  }
  if (f.cwe.trim() !== '' && !/^CWE-\d{1,9}$/i.test(f.cwe.trim())) e.cwe = 'Use the format CWE-79';
  return e;
}

/** Query parameters for a valid filter set: trimmed, empty values dropped. */
export function filtersToParams(f: SearchFilters): Partial<SearchFilters> {
  const out: Partial<SearchFilters> = {};
  if (f.q.trim()) out.q = f.q.trim();
  if (f.publishedFrom) out.publishedFrom = f.publishedFrom;
  if (f.publishedTo) out.publishedTo = f.publishedTo;
  if (f.cvssV3Min.trim()) out.cvssV3Min = f.cvssV3Min.trim();
  if (f.cvssV3Max.trim()) out.cvssV3Max = f.cvssV3Max.trim();
  if (f.exploitability) out.exploitability = f.exploitability;
  if (f.kev) out.kev = true;
  if (f.epssMin.trim()) out.epssMin = f.epssMin.trim();
  if (f.epssMax.trim()) out.epssMax = f.epssMax.trim();
  if (f.ecosystem) out.ecosystem = f.ecosystem;
  if (f.cwe.trim()) out.cwe = f.cwe.trim().toUpperCase();
  if (f.includeRejected) out.includeRejected = true;
  return out;
}
