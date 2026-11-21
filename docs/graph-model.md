# Graph model

BSKG uses the VulKG graph model (https://github.com/happyResearcher/VulKG,
DOI 10.1145/3671005) as its schema. Labels, relationship types, key
properties, and property names follow VulKG. Migration `V001` creates the
constraints and indexes, `V002` the bookkeeping constraints, `V003` the
`Repository` and `FixCommit` uniqueness constraints.

## Deviations from VulKG

- CVSS score properties are stored as decimals. VulKG casts several to
  integers.
- No range index on `Vulnerability.description`. A full-text index
  (`VulnerabilityDescriptionFullTextSchema`) serves text search.
- Empty source fields leave a property absent instead of storing an empty
  string.
- Provenance is stored as `p_<source>_run`, `p_<source>_at`, `p_<source>_ref`,
  and `sources` on nodes and relationships. Relationships carry a derived
  `removed` flag when every source dropped them.
- Phase 2 items moved to phase 1. NVD reference URLs supply git links, so
  `Repository` (key `url`, property `host`), `FixCommit` (key `fcKey`,
  properties `repoUrl`, `sha`, `url`) and the relationships
  `REFERS_TO_REPOSITORY` (Vulnerability to Repository), `HAS_FIX_COMMIT`
  (Repository to FixCommit) and `FIXES` (FixCommit to Vulnerability) are part
  of the phase 1 schema. `Package`, `AFFECTS_PACKAGE` and `HOSTED_IN` stay in
  phase 2. Constraints: `UniqueRepositoryUrl`, `UniqueFixCommitKey` (`V003`).
- Repository keys are canonical https URLs on github.com, gitlab.com or
  bitbucket.org: scheme and host lowercased; credentials, port, query,
  fragment, trailing `/` and `.git` removed; `git@host:o/r` and
  `ssh://git@host/o/r` become `https://host/o/r`. GitHub and Bitbucket keep
  `owner/repo`; GitLab keeps the group path up to `/-/`. A FixCommit key is
  `<repo url>@<40 lowercase hex sha>`; other shas are rejected with a warning.
  The anchor owns `REFERS_TO_REPOSITORY`; `HAS_FIX_COMMIT` and `FIXES` do not
  start at the anchor, so they are never marked removed.

- Phase 2 and 3 schema. Migration `V101` creates `UniquePackagePurl`
  (`Package.purl`); `V201` creates `UniqueAttackPatternID`
  (`AttackPattern.capecID`), `UniqueTechniqueID` (`Technique.attackID`) and
  `UniqueAtlasTechniqueID` (`AtlasTechnique.atlasID`). Version numbers may
  skip: the runner applies every embedded file that is not yet recorded, in
  ascending order. The API derives the schema phase from the highest applied
  migration (V1xx is phase 2, V2xx phase 3), at start and every 2 s, and
  `stats`, `overview`, `neighborhood` and the validator include only the labels
  and relationship types up to that phase.
- Added relationship `ADAPTED_FROM` (AtlasTechnique to Technique, phase 3).
  An ATLAS technique that cites an ATT&CK technique points at it. It is not
  part of the original design table.
- A Package is keyed by the canonical purl without version, qualifiers and
  subpath (`pkg:npm/%40scope/name`): one node per package. Affected and fixed
  versions are properties of `AFFECTS_PACKAGE`.
- A Vulnerability keyed by an advisory id (`GHSA-...`, `PYSEC-...`) holds the
  advisory id in `cveID` when the advisory has no CVE alias (Requirement 9.5).
  `aliases` (list of strings, at most 100) lists the other ids of a
  Vulnerability. With one CVE alias the advisory is attached to the CVE node
  and an existing advisory-keyed node is merged into it (Change record
  `vulnerabilityMerged`); with two or more CVE aliases the advisory attaches to
  each and a Change record `aliasConflict` names them (Requirements 9.4 to 9.9).
  `GET /v1/vulnerabilities/{id}` also finds a Vulnerability by an id in
  `aliases`.

The complete label and relationship table is in the design document
(`internal/model`, task 5.1).
