# Phase results

Record one entry per phase: date, passed, failed, skipped test counts, and the
result. The next phase starts only after a pass or a waiver naming each failed
test.

| Phase | Date | Passed | Failed | Skipped | Result / waiver |
| --- | --- | --- | --- | --- | --- |
| Milestone 1 | | | | | |
| Milestone 2 | | | | | |
| Phase 2 | | | | | |
| Phase 3 | | | | | |

## 2026-11-21: Sample and full build on AWS (t4g.large, ap-south-1, Neo4j 2026.10.2)

| Run | Result | Notes |
|---|---|---|
| Sample, first 1000 CVEs | validation passed | 3,129 nodes, 5,302 relationships |
| Sample, latest 1000 CVEs (`BSKG_SAMPLE_ORDER=latest`) | validation passed | 2,398 nodes, 4,622 relationships; 217 fix commits, 128 repositories; no CPE or exploit data for 2026 CVEs yet |
| Full build (continued from the sample) | validation passed | 12 minutes: NVD 430,350 CVEs (0 failed), Exploit-DB 47,182 rows (474 rejected, source data defects), CWE kept |

Full graph: 697,401 domain nodes and 2,653,462 relationships. Vulnerability 430,350, Product 115,035, Vendor 36,607, Weakness 984, Exploit 27,220, Author 7,045, Domain 19,728, Repository 24,983, FixCommit 35,449. 24,944 CVEs (6.1 %) have a public exploit.

API on the full graph: stats 12.0 s cold (then cached 5 min), overview 4.7 s (5,000 of 697,401 nodes, truncated), search 0.17 s, CVE detail 0.32 s, validation 4.4 s.

Validation covers constraints, indexes, duplicates, endpoint labels, and REJECT descriptions; the smoke, exploit-data, exploitability, and unset-property checks (task 14.3) are not implemented yet. Unit tests pass; integration tests (Docker) were not run on the developer machine.

## 2026-11-22: Phase 2 and 3 sources on AWS

Migrations V101 (Package) and V201 (AttackPattern, Technique, AtlasTechnique) applied with `bskg migrate` (the worker skips a migrate job that already succeeded). Validation passed, 0 failed checks.

| Source | Run | Upstream | In graph |
|---|---|---|---|
| MITRE ATT&CK | 4 s, succeeded | 1,184 techniques | 1,184 |
| MITRE ATLAS | 2 s, succeeded | 221 techniques | 221 (48 ADAPTED_FROM links to ATT&CK) |
| MITRE CAPEC | 9 s, succeeded | 615 attack patterns | 615 (1,212 CWE links, 271 ATT&CK links) |
| CISA KEV | 9 s, succeeded | 1,790 entries | 1,790 CVEs flagged |
| FIRST EPSS | 3 min, succeeded | 410,919 scores | 410,919 (17,579 with score >= 0.1) |
| OSV (12 ecosystems) | 5 min, succeeded | 296,018 records | 256,646 packages, 295,829 AFFECTS_PACKAGE |
| GHSA | running | not available from the API | no `GITHUB_TOKEN`: 60 requests per hour, about 5 hours for the first run |

Graph after the load: 678,270 Vulnerability nodes, of which 430,578 are CVE-keyed (NVD 430,425 plus 153 CVEs that OSV or GHSA name before NVD publishes them) and the rest are advisory-only records (mostly OSV `MAL-*` malicious-package reports without a CVE). FixCommit 48,405, Repository 28,335.

Neo4j uses 5.1 GiB of its 5.5 GiB limit. Stats take 27 s cold (then cached). A 16 GB instance (`deploy/.env.16gb`) is recommended before the graph grows further.
