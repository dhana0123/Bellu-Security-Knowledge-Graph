# Design approval

No implementation code merges to main before this record is complete.

| Field | Value |
| --- | --- |
| Approver | _to be filled by the owner_ |
| Date | _to be filled by the owner_ |
| Design revision | _to be filled by the owner_ |
| Pinned Neo4j patch version | 2026.10.2 (latest official Community release on 2026-11-21; the design proposed 5.26.33. Schema uses Neo4j 5 syntax, to be confirmed on first run) |
| Neo4j image digest | `sha256:88458a76de0704f543bab66b7df1984b36ac3f24de3c2e2d74c8fa1972ebb8cf` (index of the official `neo4j:2026.10.2-community`, read from Docker Hub on 2026-11-21) |

## Items for owner review

1. Read-only database user (Requirement 17.13): no RBAC in Community.
2. Checkpoint after `--since` (Requirement 9.9).
3. REJECT check after NVD data exists (Requirement 5.9).
4. "Exactly seven constraints" (Requirement 2.4) applies to the VulKG schema.
5. Worker lock wait and restart catch-up run.
6. Neo4j patch version and image digest.
