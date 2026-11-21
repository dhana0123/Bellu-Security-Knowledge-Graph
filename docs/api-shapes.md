# API response shapes (for the Client_UI)

Every `/v1` response is JSON. Send the key only as `Authorization: Bearer <key>`.
A key (or a parameter named `apikey`, `api_key`, `api-key`, `key`, `token`,
`access_token`, `authorization`, or any value starting `bskg_<16 hex>_`) in the
URL gives `400 {"error":{"code":"key_in_url"}}`; treat such a key as exposed.
The API sends no `Access-Control-*` headers, so call it from the same origin
(`/ui/` is served by the API; the Vite dev server proxies `/v1` and `/healthz`).
`/v1` responses carry `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

## Envelope and errors

Every success and error body has a `graph` object:

```json
{"graph": {"version": "dev", "buildState": "ready", "buildMode": "sample",
           "stale": false,
           "sources": {"cwe": {"lastSuccess": "2025-01-09T03:00:00Z"},
                       "nvd": {"lastSuccess": null}, "exploitdb": {"lastSuccess": null}}}}
```

- `buildState`: `migrating`, `loading_cwe`, `nvd_catch_up`, `loading_exploits`, `ready`.
- `buildMode`: `"sample"`, `"full"`, or `null` when unset.
- `stale`: true when the last successful NVD run is older than `BSKG_STALE_AFTER_HOURS`
  or missing. Always false while `buildMode` is `sample`.

Errors: `{"error": {"code", "message", "parameter?"}, "graph": {...}}`.

| Status | `error.code` | When |
| --- | --- | --- |
| 400 | `invalid_parameter` (names `parameter`), `key_in_url` | bad input; key in URL |
| 401 | `unauthorized` | missing, malformed, unknown, or revoked key (one identical body) |
| 404 | `not_found` | unknown entity or route |
| 429 | `rate_limited` | per-key limit; `Retry-After` header (seconds, at least 1) |
| 500 | `internal` | unexpected failure |
| 503 | `unavailable`, `migrating` | graph store unreachable (neighborhood: also on timeout); migrations pending |
| 504 | `timeout` | query time limit (not used by neighborhood, which answers 503) |

`GET /healthz` (no auth): `200 {"status":"ok"}`, or `503 {"status":"unavailable"}` /
`503 {"status":"migrating"}`. It has no `graph` envelope.

## GET /v1/status

```json
{
  "buildState": "nvd_catch_up",
  "buildMode": "sample",              // "sample" | "full" | null
  "sampleLimit": 1000,                // null when not a sample build
  "sources": [
    {"source": "cwe", "neverRun": false,
     "checkpoint": {"found": true, "watermark": "2025-01-09T03:00:00Z", "resume": "", "version": "4.14"},
     "lastRun": {"status": "succeeded", "startedAt": "...", "step": "", "processed": 0, "total": 0, "error": ""},
     "lastSuccess": "2025-01-09T03:00:00Z",
     "deadLetters": 1}
  ],                                  // one entry per source, in configured order
  "queue": {"complete": false,
            "jobs": [{"name": "migrate|cwe|nvd-catch-up|exploitdb",
                      "state": "running|succeeded|failed", "attempts": 1, "error": "",
                      "mode": "sample", "limit": 1000,
                      "startedAt": "...", "endedAt": null}]},   // queue order
  "validation": {"status": "passed", "buildMode": "sample", "endedAt": "..."},  // or null
  "graph": {...}
}
```

A source that never ran has `neverRun: true`, `lastRun: null`, `lastSuccess: null`.
Progress of a running source is `lastRun.step`, `processed`, `total`.
All timestamps are RFC 3339 UTC or `null`.

## GET /v1/stats

Cached for `BSKG_STATS_TTL` (default 5m). `sync`, `buildState`, `buildMode` are read per request.

```json
{
  "generatedAt": "2025-01-10T12:00:00Z",
  "statsStale": false,                // true: last computation failed, previous result served
  "labels": [{"label": "Vulnerability", "count": 7}],        // domain labels
  "relationships": [{"type": "AFFECTS", "count": 7}],
  "cvesByYear": [{"year": 2020, "count": 3}],                // ascending, rejected CVEs excluded
  "cvssDistribution": [{"severity": "UNSCORED|NONE|LOW|MEDIUM|HIGH|CRITICAL", "count": 0}],  // always 6 entries in this order
  "topWeaknesses": [{"key": "CWE-79", "count": 3}],          // up to 10
  "topVendors": [{"key": "acme", "count": 3}],
  "topProducts": [{"key": "widget", "count": 3}],
  "exploitedShare": {"exploited": 2, "total": 6, "ratio": 0.3333},
  "sync": [ /* same objects as /v1/status "sources"; null if unavailable */ ],
  "buildState": "ready", "buildMode": "sample",              // omitted if the live read failed
  "graph": {...}
}
```

Failure with no cached result: 504 on timeout, 500 otherwise.

## GET /v1/graph/neighborhood

Query: `type` (required: `Vulnerability`, `Exploit`, `Author`, `Weakness`, `Domain`, `Product`, `Vendor`),
`id` (required, 1 to 256 chars; the plain key, CVE ids are upper-cased), `depth` (1 or 2, default 1),
`limit` (1 to 300, default 100), `nodeTypes` and `relTypes` (comma lists, at most 50 entries,
known names only; omitted or empty means no restriction).
`relTypes`: `WRITES, EXPLOITS, EXAMPLE_OF, REFERS_TO, AFFECTS, BELONGS_TO, CHILD_OF`.

```json
{
  "nodes": [{"id": "Vulnerability:CVE-2021-1", "type": "Vulnerability", "key": "CVE-2021-1",
             "label": "CVE-2021-1",            // key cut to 100 chars
             "properties": {"v3baseScore": 9.8, "publishedDate": "2021-01-02"}}],
                                              // scalars only, strings cut to 500 chars
  "edges": [{"id": "Exploit:42|EXPLOITS|Vulnerability:CVE-2021-1",
             "source": "Exploit:42", "target": "Vulnerability:CVE-2021-1",
             "type": "EXPLOITS", "viewID": "1000"}],   // viewID only on CHILD_OF; id then ends with |viewID
  "truncated": true,
  "graph": {...}
}
```

Node `id` is `Label:key` (a Vendor and a Product with the same name differ). Nodes and edges are sorted
by `id`. At most `limit` nodes (start node included). The start node is always returned. `truncated`
is true exactly when more nodes exist within `depth` than `limit` allows. 404 when the start node
does not exist; 503 on timeout or when the store is unreachable.

## Entity routes (already present)

- `GET /v1/vulnerabilities?q=&publishedFrom=&publishedTo=&cvssV3Min=&cvssV3Max=&exploitability=0|1&kev=&cwe=&includeRejected=&limit=&cursor=`
  returns `{"items":[{"cveID","publishedDate","description","v3baseScore","v3baseSeverity","exploitability","kev","sources"}],
  "limit":50,"nextCursor":"..."}` (`nextCursor` absent on the last page). Cursors are opaque and bound to the filters.
- `GET /v1/vulnerabilities/{id}` returns `{"vulnerability":{...},"sources":[],"provenance":[],"weaknesses":[],"exploits":[],"products":[],"domains":[]}`.
- `GET /v1/weaknesses/{cweID}`, `/v1/products/{name}`, `/v1/vendors/{name}`, `/v1/exploits/{eid}` return
  `{"weakness"|"product"|"vendor"|"exploit": {...}, ...}`; the three list routes `/v1/{weaknesses|products|vendors}/{key}/vulnerabilities`
  return `{"items":[{"cveID","publishedDate","v3baseScore"}],"limit","nextCursor?"}`.

## GET /v1/sources
Constant list copied from the License and Attribution columns of `docs/sources.md`
(`name` is the source id used in `sources` arrays; a cell that is still `TODO` there is sent as `Not recorded yet`).
```json
{"sources": [{"name": "cwe", "license": "...", "attribution": "..."}], "graph": {...}}
```
## /ui/

No auth. `/ui` redirects (301) to `/ui/`. Existing embedded files are served with an `ETag`; hashed files
under `assets/` get `Cache-Control: public, max-age=31536000, immutable`, everything else `no-cache`.
A missing `/ui/assets/*` file is 404; any other unknown path returns `index.html` with 200 (client routing).
Every response has a strict Content-Security-Policy (`script-src 'self'`, `style-src 'self'`,
`connect-src 'self'`, `img-src 'self' data:`, no inline script or style), `nosniff`, and `Referrer-Policy: no-referrer`.
