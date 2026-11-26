# AI Agents Don't Need More Security Data. They Need Connected Security Knowledge.

*By Santhosh Naik B. Code: [github.com/dhana0123/Bellu-Security-Knowledge-Graph](https://github.com/dhana0123/Bellu-Security-Knowledge-Graph)*

> Note: this post was rewritten with the help of AI. The author reviewed the content against the project's measurements in `docs/phase-results.md`.

## 1. The problem: fragmented security knowledge

A security question rarely lives in one dataset. "Is this CVE exploited, and what should I patch?" touches NVD (the CVE), CWE (the weakness), Exploit-DB (public exploits), CISA KEV (known exploitation), EPSS (exploit probability), OSV and GHSA (affected packages), and CAPEC and ATT&CK (attacker behavior). Each source has its own identifiers, formats, and update schedule. An agent that must answer from these sources has to join them itself, on every question, without any guarantee the join is correct.

## 2. Why conventional retrieval isn't enough

Vector search over documents finds text that looks similar to the question. It does not follow relationships. It cannot reliably answer "which fix commits belong to CVEs with a public exploit in this weakness class", because the answer spans several records that never appear together in one chunk. It also gives no provenance: you get a passage, not the source and run that produced it.

A graph stores those links explicitly. The agent traverses them and gets a path it can cite.

## 3. Building BSKG: architecture and design decisions

BSKG (Bellu Security Knowledge Graph) loads the pinned [VulKG](https://github.com/happyResearcher/VulKG) baseline into Neo4j Community and keeps it current from public sources.

- **One Go binary, three services.** `bskg` runs as `neo4j`, `bskg-api`, and `bskg-worker` in Docker Compose on a single AWS EC2 host.
- **Known schema.** Labels and relationship types follow VulKG, so the model is documented and citable. Deviations are listed in `docs/graph-model.md` (for example, CVSS scores stay decimals instead of being cast to integers).
- **Provenance on everything.** Nodes and relationships carry `p_<source>_run`, `p_<source>_at`, and `p_<source>_ref`, so every fact traces to a source and a run. A relationship dropped by every source is flagged `removed` rather than silently deleted.
- **Canonical keys.** Repository URLs are normalized (`git@host:o/r` and `https://host/o/r.git` become one key). Packages are keyed by purl without version. A fix commit is `<repo url>@<40-hex sha>`.
- **Alias merging.** An advisory with one CVE alias attaches to that CVE. With several, it attaches to each and records an `aliasConflict`.
- **Migrations and validation.** `bskg migrate` applies versioned schema files. `bskg validate` checks constraints, indexes, duplicates, and relationship endpoint labels.
- **REST API with API keys.** Search, entity detail, neighborhood, overview, and stats endpoints are described in `api/openapi.yaml`.

## 4. Following one vulnerability through the graph

Take a CVE from NVD. In the graph it is a `Vulnerability` node, and from there an agent can follow edges:

1. To its `Weakness` (CWE), and from the weakness to CAPEC attack patterns and ATT&CK techniques.
2. To `Exploit` nodes from Exploit-DB, if a public exploit exists.
3. To `Product` and `Vendor` nodes through affected-configuration data.
4. To `Repository` (`REFERS_TO_REPOSITORY`), then `FixCommit` (`HAS_FIX_COMMIT`, `FIXES`), which locates the actual patch.
5. To `Package` nodes (`AFFECTS_PACKAGE`) from OSV and GHSA, with affected and fixed versions on the edge.
6. To KEV and EPSS data on the CVE node: whether it is known exploited and how likely exploitation is.

One call to `GET /v1/vulnerabilities/{id}` returns the CVE, and the neighborhood endpoint returns the surrounding subgraph. Each element carries its source and run. An id such as a GHSA alias also resolves to the same node.

## 5. What 697,401 entities and 2.65 million relationships reveal

The first full build (NVD, CWE, Exploit-DB) produced **697,401 domain nodes and 2,653,462 relationships**:

| Label | Count |
| --- | --- |
| Vulnerability | 430,350 |
| Product | 115,035 |
| Vendor | 36,607 |
| FixCommit | 35,449 |
| Exploit | 27,220 |
| Repository | 24,983 |
| Domain | 19,728 |
| Author | 7,045 |
| Weakness | 984 |

Findings from the data:

- **24,944 CVEs (6.1%) have a public exploit.** Most of the graph has no exploit, which is why exploit links are useful for prioritization.
- **Fix commits are discoverable.** NVD reference URLs yield tens of thousands of fix commits across repositories, so patch lookup can be a traversal.
- **Sources disagree on timing.** After the phase 2 load, 153 CVEs were named by OSV or GHSA before NVD published them, and most advisory-only records are OSV `MAL-*` malicious-package reports with no CVE.

Phase 2 and 3 then added ATT&CK (1,184 techniques), ATLAS (221), CAPEC (615), KEV (1,790 flagged CVEs), EPSS (410,919 scores), OSV (256,646 packages), and GHSA (38,049 advisories).

## 6. Engineering challenges and lessons

- **Source data has defects.** 474 of 47,182 Exploit-DB rows were rejected. Reject and log, and don't let one bad row stop a build.
- **Identity is the hard part.** Merging one real-world entity from many sources (repo URLs, advisory aliases) took more design than loading the data.
- **Rate limits shape the pipeline.** GHSA without a token loaded 30,000 advisories in 4.4 hours. With `GITHUB_TOKEN`, the remaining 8,049 took 2 minutes. Cursors let the second run resume from where the first stopped.
- **Provenance costs storage but pays off.** It makes validation and debugging possible.
- **Memory is the limit.** Neo4j used 5.1 GiB of a 5.5 GiB limit on the `t4g.large` host. A 16 GB profile (`deploy/.env.16gb`) is recommended.

## 7. Performance measurements

Measured on AWS `t4g.large` (ap-south-1), Neo4j 2026.10.2, full phase 1 graph:

| Operation | Time |
| --- | --- |
| Full build (NVD, Exploit-DB, CWE) | 12 minutes |
| Search | 0.17 s |
| CVE detail | 0.32 s |
| Overview (5,000 of 697,401 nodes, truncated) | 4.7 s |
| Stats, cold (then cached 5 min) | 12.0 s |
| Validation | 4.4 s |

After phase 2 and 3, cold stats rose to 27 s. These are single-run measurements on one machine, not load tests.

## 8. What remains unproven

- **No agent benchmark yet.** There is no measurement showing an agent answers security questions better with BSKG than with plain retrieval. This is the central claim and it is untested.
- **Validation is incomplete.** The smoke, exploit-data, exploitability, and unset-property checks are not implemented.
- **Integration tests (Docker) were not run** on the developer machine.
- **Latency is untested under concurrency.** Cold stats and overview are slow, and the 5-minute cache hides that.
- **Single host.** Scale beyond the current graph size and one EC2 instance is unmeasured.

## 9. What's next: benchmarking and agent integration

1. Build a question set (exploitability, patch lookup, attack-technique mapping) and compare an agent with BSKG against the same agent with document retrieval.
2. Expose the graph to agents through a tool interface on top of the REST API, so answers return paths with provenance.
3. Finish the remaining validation checks and add load tests.
4. Move to the 16 GB profile before the graph grows further.

BSKG is Apache-2.0 licensed and builds on VulKG (see `NOTICE`). Source, docs, and issues: **[github.com/dhana0123/Bellu-Security-Knowledge-Graph](https://github.com/dhana0123/Bellu-Security-Knowledge-Graph)**.

---

*Written by Santhosh Naik B. This post was rewritten with the help of AI.*
