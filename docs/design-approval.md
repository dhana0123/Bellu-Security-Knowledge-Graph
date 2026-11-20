# Design approval

No implementation code merges to main before this record is complete.

| Field | Value |
| --- | --- |
| Approver | _to be filled by the owner_ |
| Date | _to be filled by the owner_ |
| Design revision | _to be filled by the owner_ |
| Pinned Neo4j patch version | _to be filled by the owner_ (design proposes 5.26.33) |
| Neo4j image digest | _to be filled by the owner_ |

## Items for owner review

1. Read-only database user (Requirement 17.13): no RBAC in Community.
2. Checkpoint after `--since` (Requirement 9.9).
3. REJECT check after NVD data exists (Requirement 5.9).
4. "Exactly seven constraints" (Requirement 2.4) applies to the VulKG schema.
5. Baseline-derived rules to confirm against the real files.
6. Worker lock wait and restart catch-up run.
7. Neo4j patch version and image digest.
