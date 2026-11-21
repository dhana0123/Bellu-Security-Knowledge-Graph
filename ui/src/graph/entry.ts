/** Accepts a CVE id typed by the user (any case, surrounding spaces) and returns it in canonical form, or null when it is not one. */
export function normalizeCveId(input: string): string | null {
  const v = input.trim().toUpperCase();
  return /^CVE-\d{4}-\d{4,}$/.test(v) ? v : null;
}
