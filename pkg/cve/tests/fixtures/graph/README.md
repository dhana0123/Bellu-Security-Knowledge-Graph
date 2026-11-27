# Graph snapshot fixtures

Three snapshots S < T < U of OSV-format records (each file is a JSON array).
Scenarios:
- GHSA-fix-0001 (alias CVE-2024-1000): present in S, T and U. In T its CVSS differs between sources (OSV 9.8 vs nvd 5.3 on CVE-2024-1000).
- GHSA-wd-0002 (alias CVE-2024-2000): active in S and T, withdrawn in U.
- GHSA-bridge-0003: appears in T with aliases CVE-2024-3000 and CVE-2024-3001, bridging two previously separate CVEs (3000 in S, 3001 in S).
- GHSA-multi-0004: a multi-CVE advisory (CVE-2024-4000, CVE-2024-4001) added in U.
