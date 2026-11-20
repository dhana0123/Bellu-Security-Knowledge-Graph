# Bellu Security Knowledge Graph (BSKG)

A lightweight vulnerability intelligence graph. BSKG loads the pinned VulKG
baseline into Neo4j Community, keeps it current through one modular pipeline,
and serves it through a REST API with API-key authentication.

Licensed under Apache-2.0. See `LICENSE` and `NOTICE` (VulKG attribution).

## Architecture

One Go module builds one `bskg` binary. A Docker Compose stack of three
services (`neo4j`, `bskg-api`, `bskg-worker`) runs on one AWS EC2 host.
TODO: expand (see the design document).

## Phases

1. Phase 1: VulKG baseline, NVD sync, REST API.
2. Phase 2: OSV, GHSA, CISA KEV, EPSS.
3. Phase 3: MITRE CWE, ATT&CK, ATLAS.

Results of each phase are recorded in `docs/phase-results.md`.

## Sources

Every data source, with license, attribution, and permitted use, is listed in
`docs/sources.md`.

## Commands

| Command | Purpose |
| --- | --- |
| `bskg migrate` | Apply schema migrations |
| `bskg baseline load` | Load the VulKG baseline |
| `bskg validate` | Run integrity validation |
| `bskg sync` | Run a source sync |
| `bskg worker` | Run the build queue and daily schedule |
| `bskg serve` | Run the REST API |
| `bskg apikey create\|revoke <name>` | Manage API keys |

Build and test: `go build ./...` and `go test ./...`.
Deployment notes: `docs/operations.md`.
