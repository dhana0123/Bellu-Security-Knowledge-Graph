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

The complete label and relationship table is in the design document
(`internal/model`, task 5.1).
