/** Red badge for a CVE on the CISA Known Exploited Vulnerabilities list. */
export function KevBadge({ label = 'KEV' }: { label?: string }) {
  return (
    <span className="ml-2 inline-block rounded bg-red-700 px-2 py-0.5 text-xs font-semibold text-white ring-1 ring-inset ring-red-400">
      {label}
    </span>
  );
}
