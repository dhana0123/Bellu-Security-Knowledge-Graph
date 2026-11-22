package api

import (
	"context"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
)

// Every Cypher statement the API runs is a constant in this file and is listed
// in allQueries, which the read-only lint test scans (Requirements 17.6, 17.13).
// Client input reaches Neo4j only as bound parameters. Queries run only through
// runRead, which uses graph.Client.Read (AccessModeRead, ExecuteRead).

const (
	// Graph metadata (envelope).
	cypherBuildMeta = `MATCH (b:BuildMeta {id: 'build'}) RETURN b.buildState AS state, b.buildMode AS mode`
	cypherLastRuns  = `MATCH (r:SyncRun) WHERE r.status IN ['succeeded', 'succeeded_with_errors'] RETURN r.source AS source, max(r.endedAt) AS at`

	// Vulnerability detail. $id is the canonical CVE id. Returns one row with
	// the node properties (which include sources and p_<src>_* provenance) and
	// the related entities.
	cypherVulnerabilityByID = `
MATCH (v:Vulnerability {cveID: $id})
RETURN properties(v) AS props,
  [(v)-[:EXAMPLE_OF]->(w:Weakness) | w.cweID] AS weaknesses,
  [(e:Exploit)-[:EXPLOITS]->(v) | {
      eid: e.eid, exploitPublishDate: e.exploitPublishDate,
      exploitType: e.exploitType, platform: e.platform,
      authors: [(a:Author)-[:WRITES]->(e) | a.authorName]}] AS exploits,
  [(v)-[r:AFFECTS]->(p:Product) | {
      productName: p.productName, productType: p.productType,
      numOfVersion: r.numOfVersion, affectedVersion: r.affectedVersion,
      vendors: [(p)-[:BELONGS_TO]->(vd:Vendor) | vd.vendorName]}] AS products,
  [(v)-[:REFERS_TO]->(d:Domain) | d.domainName] AS domains,
  [(v)-[:REFERS_TO_REPOSITORY]->(rp:Repository) | {url: rp.url, host: rp.host}] AS repositories,
  [(f:FixCommit)-[:FIXES]->(v) | {sha: f.sha, repoUrl: f.repoUrl, url: f.url}] AS fixCommits`

	// Alias lookup: the Vulnerability whose `aliases` list holds one of the
	// candidate ids (an advisory id or other alias). Used only when no node
	// has the id as cveID. The lowest cveID wins when several match.
	cypherVulnerabilityByAlias = `
MATCH (v:Vulnerability) WHERE any(a IN $aliases WHERE a IN v.aliases)
RETURN v.cveID AS cveID ORDER BY v.cveID ASC LIMIT 1`
	// Vulnerability existence and sources for history and as-of routes.
	cypherVulnerabilityExists = `MATCH (v:Vulnerability {cveID: $id}) RETURN v.cveID AS cveID, properties(v) AS props`

	// Weakness.
	cypherWeaknessByID  = `MATCH (w:Weakness {cweID: $id}) RETURN properties(w) AS props`
	cypherWeaknessVulns = `
MATCH (v:Vulnerability)-[:EXAMPLE_OF]->(:Weakness {cweID: $id})
WHERE ($includeRejected OR coalesce(v.rejected, false) = false)
  AND ($after IS NULL OR v.cveID > $after)
RETURN v.cveID AS cveID, v.publishedDate AS publishedDate, v.v3baseScore AS v3baseScore
ORDER BY v.cveID ASC LIMIT $limit`

	// Product. Exact key lookup first, then a bounded case-insensitive scan.
	cypherProductExact = `MATCH (p:Product {productName: $name}) RETURN p.productName AS key LIMIT 1`
	cypherProductFold  = `MATCH (p:Product) WHERE toLower(p.productName) = $lower RETURN p.productName AS key ORDER BY key LIMIT 1`
	cypherProductByKey = `
MATCH (p:Product {productName: $name})
RETURN properties(p) AS props, [(p)-[:BELONGS_TO]->(vd:Vendor) | vd.vendorName] AS vendors`
	cypherProductVulns = `
MATCH (v:Vulnerability)-[:AFFECTS]->(:Product {productName: $name})
WHERE ($includeRejected OR coalesce(v.rejected, false) = false)
  AND ($after IS NULL OR v.cveID > $after)
RETURN v.cveID AS cveID, v.publishedDate AS publishedDate, v.v3baseScore AS v3baseScore
ORDER BY v.cveID ASC LIMIT $limit`

	// Vendor.
	cypherVendorExact = `MATCH (vd:Vendor {vendorName: $name}) RETURN vd.vendorName AS key LIMIT 1`
	cypherVendorFold  = `MATCH (vd:Vendor) WHERE toLower(vd.vendorName) = $lower RETURN vd.vendorName AS key ORDER BY key LIMIT 1`
	cypherVendorByKey = `
MATCH (vd:Vendor {vendorName: $name})
RETURN properties(vd) AS props, [(p:Product)-[:BELONGS_TO]->(vd) | p.productName] AS products`
	cypherVendorVulns = `
MATCH (:Vendor {vendorName: $name})<-[:BELONGS_TO]-(:Product)<-[:AFFECTS]-(v:Vulnerability)
WHERE ($includeRejected OR coalesce(v.rejected, false) = false)
  AND ($after IS NULL OR v.cveID > $after)
WITH DISTINCT v
RETURN v.cveID AS cveID, v.publishedDate AS publishedDate, v.v3baseScore AS v3baseScore
ORDER BY v.cveID ASC LIMIT $limit`

	// Exploit (metadata only, Requirement 24.2).
	cypherExploitByID = `
MATCH (e:Exploit {eid: $id})
RETURN properties(e) AS props,
  [(a:Author)-[:WRITES]->(e) | a.authorName] AS authors,
  [(e)-[:EXPLOITS]->(v:Vulnerability) | v.cveID] AS vulnerabilities`

	// Search without free text: order publishedDate DESC, cveID DESC.
	// Parameters: publishedFrom, publishedTo (date or null), cvssV3Min,
	// cvssV3Max, exploitability, kev, epssMin, epssMax, ecosystem, cwe (null = no filter), includeRejected,
	// afterKey (date) and afterID (keyset cursor, null on the first page), limit.
	cypherSearch = `
MATCH (v:Vulnerability)
WITH v, coalesce(v.publishedDate, date('0001-01-01')) AS sk
WHERE ($includeRejected OR coalesce(v.rejected, false) = false)
  AND ($publishedFrom IS NULL OR sk >= $publishedFrom)
  AND ($publishedTo IS NULL OR sk <= $publishedTo)
  AND ($cvssV3Min IS NULL OR v.v3baseScore >= $cvssV3Min)
  AND ($cvssV3Max IS NULL OR v.v3baseScore <= $cvssV3Max)
  AND ($exploitability IS NULL OR v.exploitability = $exploitability)
  AND ($kev IS NULL OR coalesce(v.kev, false) = $kev)
  AND ($epssMin IS NULL OR v.epssScore >= $epssMin)
  AND ($epssMax IS NULL OR v.epssScore <= $epssMax)
  AND ($ecosystem IS NULL OR EXISTS {
    (v)-[ar:AFFECTS_PACKAGE]->(ap:Package)
    WHERE ap.ecosystem = $ecosystem AND coalesce(ar.removed, false) = false })
  AND ($cwe IS NULL OR EXISTS { (v)-[:EXAMPLE_OF]->(:Weakness {cweID: $cwe}) })
  AND ($afterID IS NULL OR sk < $afterKey OR (sk = $afterKey AND v.cveID < $afterID))
RETURN v.cveID AS cveID, v.publishedDate AS publishedDate, v.description AS description,
  v.v3baseScore AS v3baseScore, v.v3baseSeverity AS v3baseSeverity,
  v.exploitability AS exploitability, v.kev AS kev, v.epssScore AS epssScore, v.sources AS sources, sk AS sortKey
ORDER BY sk DESC, v.cveID DESC LIMIT $limit`

	// Search with free text: order score DESC, cveID DESC. $q is a
	// Lucene-escaped query string. afterKey is the float score.
	cypherSearchText = `
CALL db.index.fulltext.queryNodes('VulnerabilityDescriptionFullTextSchema', $q) YIELD node AS v, score
WITH v, score, coalesce(v.publishedDate, date('0001-01-01')) AS sk
WHERE ($includeRejected OR coalesce(v.rejected, false) = false)
  AND ($publishedFrom IS NULL OR sk >= $publishedFrom)
  AND ($publishedTo IS NULL OR sk <= $publishedTo)
  AND ($cvssV3Min IS NULL OR v.v3baseScore >= $cvssV3Min)
  AND ($cvssV3Max IS NULL OR v.v3baseScore <= $cvssV3Max)
  AND ($exploitability IS NULL OR v.exploitability = $exploitability)
  AND ($kev IS NULL OR coalesce(v.kev, false) = $kev)
  AND ($epssMin IS NULL OR v.epssScore >= $epssMin)
  AND ($epssMax IS NULL OR v.epssScore <= $epssMax)
  AND ($ecosystem IS NULL OR EXISTS {
    (v)-[ar:AFFECTS_PACKAGE]->(ap:Package)
    WHERE ap.ecosystem = $ecosystem AND coalesce(ar.removed, false) = false })
  AND ($cwe IS NULL OR EXISTS { (v)-[:EXAMPLE_OF]->(:Weakness {cweID: $cwe}) })
  AND ($afterID IS NULL OR score < $afterKey OR (score = $afterKey AND v.cveID < $afterID))
RETURN v.cveID AS cveID, v.publishedDate AS publishedDate, v.description AS description,
  v.v3baseScore AS v3baseScore, v.v3baseSeverity AS v3baseSeverity,
  v.exploitability AS exploitability, v.kev AS kev, v.epssScore AS epssScore, v.sources AS sources, score AS sortKey
ORDER BY score DESC, v.cveID DESC LIMIT $limit`

	// Co-exploitation and co-affected, computed at query time; nothing is
	// persisted (Requirement 19). Relationships with removed = true are
	// ignored. Parameters: id (canonical cveID), limit, and for co-affected
	// maxProductDegree. Rows come back ordered shared DESC, cveID ASC.
	cypherCoExploited = `
MATCH (a:Vulnerability {cveID: $id})<-[r1:EXPLOITS]-(e:Exploit)
WHERE coalesce(r1.removed, false) = false
WITH DISTINCT a, e
MATCH (e)-[r2:EXPLOITS]->(b:Vulnerability)
WHERE b <> a AND coalesce(r2.removed, false) = false
WITH b, count(DISTINCT e) AS shared
RETURN b.cveID AS cveID, shared, b.v3baseScore AS v3baseScore
ORDER BY shared DESC, cveID ASC LIMIT $limit`
	// Products linked to more than $maxProductDegree vulnerabilities are not
	// expanded. COUNT { } over the bare pattern is answered from the node's
	// relationship degree, without visiting the neighbours.
	cypherCoAffected = `
MATCH (a:Vulnerability {cveID: $id})-[r1:AFFECTS]->(p:Product)
WHERE coalesce(r1.removed, false) = false
  AND COUNT { (p)<-[:AFFECTS]-() } <= $maxProductDegree
WITH DISTINCT a, p
MATCH (p)<-[r2:AFFECTS]-(b:Vulnerability)
WHERE b <> a AND coalesce(r2.removed, false) = false
WITH b, count(DISTINCT p) AS shared
RETURN b.cveID AS cveID, shared, b.v3baseScore AS v3baseScore
ORDER BY shared DESC, cveID ASC LIMIT $limit`
	cypherCoAffectedSkipped = `
MATCH (a:Vulnerability {cveID: $id})-[r1:AFFECTS]->(p:Product)
WHERE coalesce(r1.removed, false) = false
  AND COUNT { (p)<-[:AFFECTS]-() } > $maxProductDegree
RETURN count(DISTINCT p) AS skipped LIMIT 1`

	// Change history (keyset on id, newest first) and as-of inputs.
	cypherHistory = `
MATCH (c:Change {entityKey: $entityKey})
WHERE $before IS NULL OR c.id < $before
RETURN c.id AS id, c.type AS type, c.field AS field, c.oldValue AS oldValue,
  c.newValue AS newValue, c.source AS source, c.runId AS runId, c.at AS at
ORDER BY c.id DESC LIMIT $limit`
	cypherAsOfChanges = `
MATCH (c:Change {entityKey: $entityKey})
WHERE c.at > $time AND c.type IN ['propertyChanged', 'entityCreated']
RETURN c.id AS id, c.type AS type, c.field AS field, c.oldValue AS oldValue, c.at AS at
ORDER BY c.id DESC`
	cypherHistoryFloor = `
OPTIONAL MATCH (c:Change {entityKey: $entityKey})
WITH min(c.at) AS earliest
OPTIONAL MATCH (b:BuildMeta {id: 'build'})
RETURN earliest, b.changesPurgedBefore AS purgedBefore`

	// Status. Per-source checkpoint and run data come from checkpoint.ReadStatus.
	cypherStatusBuild = `
OPTIONAL MATCH (b:BuildMeta {id: 'build'})
RETURN b IS NOT NULL AS found, b.buildState AS buildState, b.buildMode AS buildMode,
  b.sampleLimit AS sampleLimit, b.queueComplete AS queueComplete,
  b.lastValidationStatus AS validationStatus, b.lastValidationMode AS validationMode,
  b.lastValidationEndedAt AS validationEndedAt`
	cypherStatusJobs = `
MATCH (j:Job) WHERE j.queueState IS NOT NULL
RETURN j.name AS name, j.queueState AS state, j.queueAttempts AS attempts, j.queueError AS error,
  j.queueMode AS mode, j.queueLimit AS limit, j.queueStartedAt AS startedAt, j.queueEndedAt AS endedAt`

	// Highest applied schema migration (the migrating gate).
	cypherMigrationVersion = `OPTIONAL MATCH (m:Migration) RETURN max(m.version) AS version`

	// Statistics (Requirement 20.8). The per-label and per-type count
	// queries are generated from the schema registry in stats.go.
	cypherStatsScan = `
MATCH (v:Vulnerability) WHERE coalesce(v.rejected, false) = false
RETURN v.publishedDate.year AS year,
  CASE WHEN v.v3baseScore IS NULL THEN 'UNSCORED'
       WHEN v.v3baseScore = 0 THEN 'NONE'
       WHEN v.v3baseScore < 4.0 THEN 'LOW'
       WHEN v.v3baseScore < 7.0 THEN 'MEDIUM'
       WHEN v.v3baseScore < 9.0 THEN 'HIGH'
       ELSE 'CRITICAL' END AS severity,
  v.exploitability AS exploitability, count(*) AS n`
	cypherStatsTopWeaknesses = `
MATCH (v:Vulnerability)-[:EXAMPLE_OF]->(w:Weakness) WHERE coalesce(v.rejected, false) = false
RETURN w.cweID AS key, count(v) AS n ORDER BY n DESC, key ASC LIMIT 10`
	cypherStatsTopVendors = `
MATCH (v:Vulnerability)-[:AFFECTS]->(:Product)-[:BELONGS_TO]->(vd:Vendor) WHERE coalesce(v.rejected, false) = false
RETURN vd.vendorName AS key, count(DISTINCT v) AS n ORDER BY n DESC, key ASC LIMIT 10`
	cypherStatsTopProducts = `
MATCH (v:Vulnerability)-[:AFFECTS]->(p:Product) WHERE coalesce(v.rejected, false) = false
RETURN p.productName AS key, count(v) AS n ORDER BY n DESC, key ASC LIMIT 10`

	// Source coverage: what the graph holds, to compare with the upstream
	// totals stored on the Checkpoint nodes.
	cypherCoverageVulns = `
MATCH (v:Vulnerability)
RETURN count(v) AS cves, count(CASE WHEN coalesce(v.rejected, false) = false THEN 1 END) AS cvesNotRejected`
	cypherCoverageWeaknesses = `MATCH (w:Weakness) RETURN count(w) AS weaknesses`
	cypherCoverageExploits   = `MATCH (e:Exploit) RETURN count(e) AS exploits`

	// Phase 2: packages. The vulnerability detail reads AFFECTS_PACKAGE
	// (relationships marked removed are left out); the package page lists the
	// vulnerabilities and the repositories that host it.
	cypherVulnerabilityPackages = `
MATCH (v:Vulnerability {cveID: $id})-[r:AFFECTS_PACKAGE]->(p:Package)
WHERE coalesce(r.removed, false) = false
RETURN p.purl AS purl, p.ecosystem AS ecosystem, p.name AS name,
  r.introduced AS introduced, r.fixed AS fixed, r.lastAffected AS lastAffected,
  r.affectedRanges AS affectedRanges
ORDER BY purl ASC LIMIT $limit`
	cypherPackageByPurl = `
MATCH (p:Package {purl: $id})
RETURN properties(p) AS props,
  [(p)-[:HOSTED_IN]->(rp:Repository) | {url: rp.url, host: rp.host}][0..$limit] AS repositories`
	cypherPackageVulns = `
MATCH (v:Vulnerability)-[r:AFFECTS_PACKAGE]->(:Package {purl: $id})
WHERE coalesce(r.removed, false) = false
RETURN v.cveID AS cveID, v.publishedDate AS publishedDate, v.v3baseScore AS v3baseScore
ORDER BY v.cveID ASC LIMIT $limit`

	// Phase 3: attack knowledge. Attack patterns reach a vulnerability through
	// its weaknesses; techniques through those attack patterns.
	cypherVulnerabilityAttackPatterns = `
MATCH (:Vulnerability {cveID: $id})-[:EXAMPLE_OF]->(w:Weakness)-[:RELATED_ATTACK_PATTERN]->(ap:AttackPattern)
WITH ap, min(w.cweID) AS viaWeakness
RETURN ap.capecID AS capecID, ap.name AS name, viaWeakness
ORDER BY capecID ASC LIMIT $limit`
	cypherVulnerabilityTechniques = `
MATCH (:Vulnerability {cveID: $id})-[:EXAMPLE_OF]->(:Weakness)-[:RELATED_ATTACK_PATTERN]->(ap:AttackPattern)-[:MAPS_TO_TECHNIQUE]->(t:Technique)
WITH t, min(ap.capecID) AS viaAttackPattern
RETURN t.attackID AS attackID, t.name AS name, viaAttackPattern
ORDER BY attackID ASC LIMIT $limit`
	cypherAttackPatternByID = `
MATCH (ap:AttackPattern {capecID: $id})
RETURN properties(ap) AS props,
  [(w:Weakness)-[:RELATED_ATTACK_PATTERN]->(ap) | {cweID: w.cweID, cweName: w.cweName}][0..$limit] AS weaknesses,
  [(ap)-[:MAPS_TO_TECHNIQUE]->(t:Technique) | {attackID: t.attackID, name: t.name}][0..$limit] AS techniques`
	cypherTechniqueByID = `
MATCH (t:Technique {attackID: $id})
RETURN properties(t) AS props,
  [(ap:AttackPattern)-[:MAPS_TO_TECHNIQUE]->(t) | {capecID: ap.capecID, name: ap.name}][0..$limit] AS attackPatterns,
  [(a:AtlasTechnique)-[:ADAPTED_FROM]->(t) | {atlasID: a.atlasID, name: a.name}][0..$limit] AS atlasTechniques`
	cypherAtlasTechniqueByID = `
MATCH (a:AtlasTechnique {atlasID: $id})
RETURN properties(a) AS props,
  [(a)-[:ADAPTED_FROM]->(t:Technique) | {attackID: t.attackID, name: t.name}][0..$limit] AS techniques`

	// Vulnerability-level counts for /v1/stats (one bounded query each).
	cypherStatsKevCount  = `MATCH (v:Vulnerability) WHERE v.kev = true RETURN count(v) AS n`
	cypherStatsEpssHigh  = `MATCH (v:Vulnerability) WHERE v.epssScore >= 0.1 RETURN count(v) AS n`
	cypherCoverageKEV    = `MATCH (v:Vulnerability) WHERE v.kev = true RETURN count(v) AS entries`
	cypherCoverageEPSS   = `MATCH (v:Vulnerability) WHERE v.epssScore IS NOT NULL RETURN count(v) AS rows`
	cypherCoverageOSV    = `MATCH (v:Vulnerability) WHERE 'osv' IN v.sources RETURN count(v) AS advisories`
	cypherCoverageGHSA   = `MATCH (v:Vulnerability) WHERE 'ghsa' IN v.sources RETURN count(v) AS advisories`
	cypherCoverageAttack = `MATCH (t:Technique) RETURN count(t) AS techniques`
	cypherCoverageAtlas  = `MATCH (t:AtlasTechnique) RETURN count(t) AS techniques`
	cypherCoverageCAPEC  = `MATCH (p:AttackPattern) RETURN count(p) AS attackPatterns`

	// Sources list (no graph access beyond the envelope; kept for completeness
	// of last-success reads).
	cypherSourceLastSuccess = cypherLastRuns
)

// allQueries lists every Cypher constant for the read-only lint.
var allQueries = []string{
	cypherBuildMeta, cypherLastRuns,
	cypherVulnerabilityByID, cypherVulnerabilityByAlias, cypherVulnerabilityExists,
	cypherWeaknessByID, cypherWeaknessVulns,
	cypherProductExact, cypherProductFold, cypherProductByKey, cypherProductVulns,
	cypherVendorExact, cypherVendorFold, cypherVendorByKey, cypherVendorVulns,
	cypherExploitByID,
	cypherSearch, cypherSearchText,
	cypherCoExploited, cypherCoAffected, cypherCoAffectedSkipped,
	cypherHistory, cypherAsOfChanges, cypherHistoryFloor,
	cypherSourceLastSuccess,
	cypherStatusBuild, cypherStatusJobs, cypherMigrationVersion,
	cypherStatsScan, cypherStatsTopWeaknesses, cypherStatsTopVendors, cypherStatsTopProducts,
	cypherCoverageVulns, cypherCoverageWeaknesses, cypherCoverageExploits,
	cypherVulnerabilityPackages, cypherPackageByPurl, cypherPackageVulns,
	cypherVulnerabilityAttackPatterns, cypherVulnerabilityTechniques,
	cypherAttackPatternByID, cypherTechniqueByID, cypherAtlasTechniqueByID,
	cypherStatsKevCount, cypherStatsEpssHigh,
	cypherCoverageKEV, cypherCoverageEPSS, cypherCoverageOSV, cypherCoverageGHSA,
	cypherCoverageAttack, cypherCoverageAtlas, cypherCoverageCAPEC,
}

// Row is one result record as a column map.
type Row = map[string]any

// runRead runs one constant query in a read transaction and returns all rows.
// It is the only way handlers execute Cypher. The query must be one of the
// constants above (the type is string, enforced by review and the lint test).
func runRead(ctx context.Context, g *graph.Client, query string, params map[string]any) ([]Row, error) {
	v, err := g.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}
		rows := []Row{}
		for res.Next(ctx) {
			rows = append(rows, res.Record().AsMap())
		}
		return rows, res.Err()
	})
	if err != nil {
		return nil, err
	}
	return v.([]Row), nil
}
