# Adapter contract

This is the contract for the Phase 2 and 3 source adapters (task 13.1 to 13.5):
CISA KEV, FIRST EPSS, OSV, GHSA, MITRE ATT&CK, MITRE ATLAS, CAPEC. It is the
reference for `internal/source`, `internal/resolve`, `internal/upsert`,
`internal/pipeline` and `internal/source/fetch`. The pipeline does all graph
work; an adapter only fetches records and maps them to entities and
relationships. The rules are the same as for the CWE, NVD and Exploit-DB
adapters.

## 1. Interface

```go
// internal/source
type Adapter interface {
    Name() string // ^[a-z][a-z0-9]{0,15}$, unique
    Fetch(ctx context.Context, cp Checkpoint, opts RunOptions) (Iterator, error)
    Normalize(rec Record) (Normalized, error) // pure: no I/O, no clock, no randomness
}
type Totaler interface { Totals(ctx context.Context) (map[string]int64, error) } // optional
```

- `Fetch` returns records changed since `cp` (all records when `cp.IsZero()`).
  `Iterator.Next` returns `io.EOF` at the end.
- A `Record` has `ID` (source record id, stored as the provenance `p_<src>_ref`),
  `Payload` (the raw record, normalized later by `Normalize`) and `Cursor` (the
  state AFTER the record is committed: `Resume`, `Watermark`, `Version`).
  A record with an empty `Payload` only moves the cursor (a cursor marker).
- `Cursor.Version` is a snapshot version (a SHA-256 of the file, a catalog
  version). The pipeline stores it after a full successful run, and passes it
  back in `Checkpoint.Version`; an adapter that sees the same version returns
  no records.
- `Normalize` errors send the record to the dead-letter list; the run goes on.
  A returned error must name the record id.
- `RunOptions.SampleLimit > 0` is a Sample_Build. Mode-specific sources (nvd,
  exploitdb, kev, epss, osv, ghsa) must honour it and return at most N
  records; cwe, attack, atlas and capec ignore it. `SampleOrder` is meaningful
  for NVD only.
- `Totaler` (optional): upstream counts, stored as `Checkpoint.upstream_<key>`
  after a successful run. Keys match `^[a-zA-Z][a-zA-Z0-9]*$`.

## 2. Registration and names

One line in `cmd/bskg/registry.go`, in `registerAdapters(cfg *config.Config)`:

```go
_ = pipeline.Default.Register(kev.New(kev.Options{CacheDir: cfg.CacheDir, Version: version}))
```

plus one complete row in `docs/sources.md` (name, URL, licence, attribution,
permitted use, verification date). The adapter's `Name()` is the name used
everywhere:

| `Name()` | `BSKG_ENABLED_SOURCES` entry | Queue job name | `buildState` | Mode-specific |
| --- | --- | --- | --- | --- |
| `cwe` | `cwe` | `cwe` | `loading_cwe` | no |
| `nvd` | `nvd` | `nvd-catch-up` | `nvd_catch_up` | yes |
| `exploitdb` | `exploitdb` | `exploitdb` | `loading_exploits` | yes |
| `attack` | `attack` | `attack` | `loading_attack` | no |
| `atlas` | `atlas` | `atlas` | `loading_atlas` | no |
| `capec` | `capec` | `capec` | `loading_capec` | no |
| `kev` | `kev` | `kev` | `loading_kev` | yes |
| `epss` | `epss` | `epss` | `loading_epss` | yes |
| `osv` | `osv` | `osv` | `loading_osv` | yes |
| `ghsa` | `ghsa` | `ghsa` | `loading_ghsa` | yes |

For every source except `nvd` the job name equals the adapter name. The table
lives in `internal/worker/sources.go` (`SourceJobs`); an adapter does not edit
it. Queue order: `migrate`, `cwe`, `nvd-catch-up`, `exploitdb`, then `attack`,
`atlas`, `capec`, `kev`, `epss`, `osv`, `ghsa`, each only when enabled AND
registered (a source that is enabled without an adapter is skipped with a
warning). The daily schedule runs every enabled registered source in the same
order; one failing source does not stop the others. `bskg sync --source <name>`
runs one adapter by name.

The adapter reads its settings from the constructor, not from the environment:
`cfg.CacheDir` (`BSKG_CACHE_DIR`), `cfg.OSVEcosystems` (`BSKG_OSV_ECOSYSTEMS`,
canonical spellings such as `PyPI`, `GitHub Actions`), `cfg.GitHubToken`
(`GITHUB_TOKEN`, a `config.Secret`: call `Value()` only to build a request
header, never log it, never put it in an error or a URL),
`cfg.EPSSChangeThreshold`. Outbound hosts go through an `httpx.AllowList`
client (`NewClient`) and the retry policies of `internal/httpx` (`OSVPolicy` for
OSV and GHSA).

## 3. Reference kinds

A `source.Ref{Kind, Raw, MustExist}` names a node by its raw source form. The
resolver (`resolve.Resolve`) is the only place that decides a key. Resolving a
canonical value again returns the same key. A malformed or unsupported value is
an error that names it; the pipeline counts it as rejected (a warning) and goes
on. `MustExist` means: never create the node; if it is absent the relationship
is dropped and counted unresolved.

| Kind | Raw input | Key (label, property, value) |
| --- | --- | --- |
| `RefCVE` | `cve-2021-44228`, trimmed | `Vulnerability`, `cveID`, `CVE-2021-44228` |
| `RefCWE` | `CWE-79`, `cwe-079`, `79` | `Weakness`, `cweID`, `CWE-79` |
| `RefPackage` | any purl, with or without version | `Package`, `purl`, canonical purl WITHOUT version, qualifiers, subpath, e.g. `pkg:npm/%40angular/core` |
| `RefAdvisory` | `GHSA-xxxx-xxxx-xxxx` or `<PREFIX>-<rest>` | `Vulnerability`, `cveID`, the advisory id (see section 4) |
| `RefCAPEC` | `CAPEC-0066`, `capec-66`, `66` | `AttackPattern`, `capecID`, `CAPEC-66` |
| `RefTechnique` | `t1059.001` | `Technique`, `attackID`, `T1059.001` (`T\d{4}(\.\d{3})?`) |
| `RefAtlas` | `aml.t0000.001` | `AtlasTechnique`, `atlasID`, `AML.T0000.001` (`AML\.T\d{4}(\.\d{3})?`) |

The Phase 1 kinds (`RefCPE`, `RefCPEVend`, `RefVendor`, `RefDomain`,
`RefExploit`, `RefAuthor`, `RefRepository`, `RefFixCommit`) are unchanged.

**Packages.** One `Package` per package: the key never carries a version.
Versions, ranges and fixed versions are properties of `AFFECTS_PACKAGE`
(`Vulnerability` to `Package`, no identity properties, so there is one
relationship per vulnerability and package). The resolver accepts these purl
types only (the OSV ecosystem in brackets): `npm` (npm), `pypi` (PyPI),
`golang` (Go), `maven` (Maven), `cargo` (crates.io), `gem` (RubyGems), `nuget`
(NuGet), `composer` (Packagist), `pub` (Pub), `hex` (Hex), `github` (GitHub
Actions), `swift` (SwiftURL). Anything else, or a malformed purl, is an error
that names the purl (Requirement 9.10, 9.11). npm names are lowercased; the
purl library lowercases PyPI, Go and GitHub names and maps `_` to `-` in PyPI.

Helpers for adapters:

```go
resolve.PurlFromOSV(ecosystem, name string) (string, error) // "PyPI","Django_Foo" -> "pkg:pypi/django-foo"
resolve.OSVEcosystems() []string                            // supported names, default order
resolve.OSVEcosystemType(name string) (purlType string, ok bool)
resolve.Package(raw) / resolve.Advisory(raw) / resolve.CAPEC(raw) / resolve.Technique(raw) / resolve.Atlas(raw)
```

`PurlFromOSV` splits the OSV name per ecosystem: npm `@scope/pkg`, Go
`host/owner/repo` (last segment is the name), Maven `group:artifact`, Packagist
`vendor/pkg`, GitHub Actions `owner/repo[/path]` (the path is dropped), SwiftURL
a URL or `host/owner/repo` (scheme and `.git` removed). An unsupported
ecosystem or an unusable name is an error naming both.

**Advisory ids.** `GHSA-` plus the lowercase body (`GHSA-c2f3-4gh5-wxmp`; the
body uses GitHub's alphabet `2-9cfghjmpqrvwx`). OSV ids are `<PREFIX>-<rest>`:
the prefix is trimmed and uppercased, the rest keeps its case (`PYSEC-2021-1`,
`GO-2021-0113`, `RUSTSEC-2020-0001`, `OSV-2020-111`, `MAL-2022-1`). A CVE id is
not an advisory id: use `RefCVE`.

**CAPEC, ATT&CK, ATLAS.** `RefCAPEC` accepts `CAPEC-<n>` or a bare number and
never has leading zeros; `CAPEC-0` is rejected. Technique ids are uppercase;
sub-techniques have a three-digit suffix. Tactics (`TA....`) and data
sources are not nodes in this schema.

## 4. Advisory aliases (Requirement 9.4 to 9.9)

An advisory adapter (OSV, GHSA) sets `Normalized.Advisory`:

```go
type Advisory struct {
    ID           string   // the advisory id as the source writes it
    CVEs         []string // CVE aliases; an invalid id is rejected (counted) and ignored
    OtherAliases []string // other ids: other advisories, vendor ids
}
```

and writes every entity and relationship of the record against
`Ref{Kind: RefAdvisory, Raw: <the advisory id>}`. The adapter never merges or
re-keys nodes, never looks the graph up and never branches on aliases. The
pipeline (`internal/upsert/alias.go`) rewrites the refs of the same record that
name `Advisory.ID` (entities, relationship endpoints, `Gate`, `Anchor`):

| `CVEs` (valid, deduplicated) | Target of the advisory refs | Aliases and records |
| --- | --- | --- |
| none | the Vulnerability keyed by the advisory id (created if missing, `exploitability` 0, `exploitDate` `[]`) | `OtherAliases` are added to its `aliases` |
| exactly one | that CVE's Vulnerability, created if NVD has not loaded it (`MustExist` is false); `sources` gets this source | `aliases` gains the advisory id and `OtherAliases` (no duplicates, at most 100). If a Vulnerability keyed by the advisory id exists it is merged into the CVE node in the same transaction: relationships move with their properties and provenance (those the CVE node already has with the same type, other end and identity are skipped), `aliases` and `sources` are unioned, missing properties are copied, the advisory node is deleted, and one Change record `vulnerabilityMerged` is written. If the merge fails the transaction rolls back and the error names both keys. |
| two or more | every CVE's Vulnerability, never merged; entities and relationships are repeated for each | `aliases` of each gains the advisory id; one Change record `aliasConflict` names the CVE ids; the Anchor is dropped for this record (no removal handling) |

Change records:

| Type | `entityKey` | `oldValue` | `newValue` |
| --- | --- | --- | --- |
| `vulnerabilityMerged` | surviving key, `Vulnerability:CVE-...` | JSON list of the two prior keys, `["Vulnerability:GHSA-...","Vulnerability:CVE-..."]` | JSON string of the surviving key |
| `aliasConflict` | `Vulnerability:<advisory id>` | empty | JSON list of the CVE ids; `field` is `aliases` |

Both are written once: a run over unchanged data writes neither. A merge is
idempotent: when the advisory node is gone the merge is skipped. Refs to a
different advisory id in the same record are not rewritten. A record without
`Advisory` resolves `RefAdvisory` to the advisory-keyed Vulnerability. Alias
storage: `aliases` is a list of strings on the Vulnerability, and
`GET /v1/vulnerabilities/{id}` finds a node by an id in `aliases` when no
`cveID` matches.

## 5. Entities, relationships, ownership

- `Normalized.Entities`: a node is created or updated. Only properties in
  `Props` change; `Clear` removes properties. Absent source fields leave a
  property absent (never an empty string). Do not write properties of another
  source on a shared node: if two sources can write the same property of the
  same node or relationship, give each source its own property name
  (`kevDateAdded`, `epssScore`), because the last writer wins.
- `Normalized.Rels`: `Type` must be in `internal/model` (`model.Rels`);
  endpoint labels must match; `Key` holds the identity properties (CHILD_OF has
  `viewID`; the new types have none). A relationship whose endpoint is
  missing is dropped and counted unresolved.
- `Gate`: process the record only if one of these refs exists in the graph,
  otherwise it is skipped and counted. KEV and EPSS gate on the CVE.
- `Anchor` and `Owned`: relationship types of the anchor that this source no
  longer asserts are marked removed (`p_<src>_removed`), never deleted.
- `Missing` marks a record that lacked a mappable field. `Notes` carry warnings
  and unresolved items (`Kind` `warning` or `unresolved`).
- Schema by phase: Phase 2 `Package`, `AFFECTS_PACKAGE` (Vulnerability to
  Package), `HOSTED_IN` (Package to Repository); Phase 3 `AttackPattern`,
  `Technique`, `AtlasTechnique`, `RELATED_ATTACK_PATTERN` (Weakness to
  AttackPattern), `MAPS_TO_TECHNIQUE` (AttackPattern to Technique),
  `ADAPTED_FROM` (AtlasTechnique to Technique, for an ATLAS technique that cites
  an ATT&CK technique). Migrations `V101` and `V201` create the constraints. A
  later phase label can be written only after its migration ran: the worker
  runs `migrate` first.

## 6. Cache helper

Large downloads go under `BSKG_CACHE_DIR` (`cfg.CacheDir`). The worker root file
system is read-only and `/tmp` is in RAM; the cache is the `bskg_cache` volume
(owned by 65532). Never load a download into memory: stream it from the file
(for a zip use `zip.OpenReader` on the path and read one entry at a time).

```go
// internal/source/fetch
func DownloadToCache(ctx context.Context, client *http.Client, url, cacheDir, name string,
    policy httpx.Policy, clock httpx.Clock) (Result, error)

func DownloadWith(ctx, client, url, cacheDir, name, policy, clock, opts Options) (Result, error)
type Options struct { Header http.Header; MaxBytes int64 } // Authorization, size limit
type Result  struct { Path string; Size int64; SHA256, ETag, LastModified string }
```

The body streams to `<cacheDir>/<name>.part`, is synced, and is renamed to
`<cacheDir>/<name>` only after the last byte arrived and the length matched, so
a failed download leaves an earlier `<name>` untouched and no `.part` behind.
Retries follow `policy` (network errors, truncated bodies, 403, 429 and 5xx,
honouring `Retry-After`); `clock` is `nil` or `httpx.RealClock{}` in
production and a fake in tests. `name` is a plain file name (no `/`, no `.part`
suffix); use one name per source file so the previous file is replaced. Use
`Result.SHA256` as `Cursor.Version` to skip an unchanged snapshot. Error text
does not contain the URL query or credentials.

## 7. Tests an adapter needs

- Table tests of `Normalize` on recorded fixtures (`testdata/`), including a
  malformed record, a missing field, and every ref kind it emits (the key must
  resolve with `resolve.Resolve`).
- Fetch tests with `httptest` and a fake `httpx.Clock`; no network.
- A test that `Name()` is valid and that `Normalize` is deterministic.
- For advisory sources: records with no CVE, one CVE and two CVEs (the
  pipeline tests cover the alias rules; the adapter only has to set
  `Advisory` correctly).
