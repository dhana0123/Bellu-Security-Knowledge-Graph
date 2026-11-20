package baseline

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Step names (VulKG load order, steps 9 to 14).
const (
	StepDomainRefers   = "domain_refers"
	StepProductAffects = "product_affects"
	StepVendorBelongs  = "vendor_belongs"
	StepAffectedVer    = "affected_version"
	StepRejectDelete   = "reject_delete"
	StepExploitability = "exploitability"
)

// Job properties written by steps 13 and 14.
const (
	JobPropRejectDeleted     = "rejectDeleted"
	JobPropRejectRelsDeleted = "rejectRelsDeleted"
)

const rejectPrefix = "** REJECT **"

var (
	// Step 9. Domain nodes exist for every row; the relationship needs both ends.
	cypherDomainRefers = `UNWIND $rows AS row
MERGE (d:Domain {domainName: row.domainName})
ON CREATE SET ` + mustSet("d") + `
WITH row, d
OPTIONAL MATCH (v:Vulnerability {cveID: row.cveID})
FOREACH (_ IN CASE WHEN v IS NULL THEN [] ELSE [1] END |
  MERGE (v)-[r:REFERS_TO]->(d)
  ON CREATE SET ` + mustSet("r") + `)
RETURN count(v) AS matched`

	// Step 10. productType is set when the Product is created and numOfVersion
	// when the AFFECTS relationship is created: the first row wins.
	cypherProductAffects = `UNWIND $rows AS row
MERGE (p:Product {productName: row.productName})
ON CREATE SET p.productType = row.productType, ` + mustSet("p") + `
WITH row, p
OPTIONAL MATCH (v:Vulnerability {cveID: row.cveID})
FOREACH (_ IN CASE WHEN v IS NULL THEN [] ELSE [1] END |
  MERGE (v)-[r:AFFECTS]->(p)
  ON CREATE SET r.numOfVersion = row.numOfVersion, ` + mustSet("r") + `)
RETURN count(v) AS matched`

	// Step 11.
	cypherVendorBelongs = `UNWIND $rows AS row
MERGE (vd:Vendor {vendorName: row.vendorName})
ON CREATE SET ` + mustSet("vd") + `
WITH row, vd
OPTIONAL MATCH (p:Product {productName: row.productName})
FOREACH (_ IN CASE WHEN p IS NULL THEN [] ELSE [1] END |
  MERGE (p)-[r:BELONGS_TO]->(vd)
  ON CREATE SET ` + mustSet("r") + `)
RETURN count(p) AS matched`

	// Step 12. Rows are grouped per (cveID, product) in file order. The first
	// group seen in this run (r.avRun <> $run) replaces the list; later groups,
	// including those from later batches, append.
	cypherAffectedVersion = `UNWIND $rows AS row
WITH row ORDER BY row.i
WITH row.cveID AS cveID, row.productName AS productName, collect(row.version) AS vs
OPTIONAL MATCH (:Vulnerability {cveID: cveID})-[r:AFFECTS]->(:Product {productName: productName})
SET r.affectedVersion = CASE WHEN r.avRun = $run THEN r.affectedVersion + vs ELSE vs END,
    r.avRun = $run
RETURN sum(CASE WHEN r IS NULL THEN 0 ELSE size(vs) END) AS matched`

	// Pairs the file does not list (or that carry a token from an earlier,
	// interrupted run) get an empty list.
	cypherAffectedVersionEmpty = `MATCH ()-[r:AFFECTS]->()
WHERE r.avRun IS NULL OR r.avRun <> $run
CALL { WITH r SET r.affectedVersion = [] } IN TRANSACTIONS OF 10000 ROWS`

	cypherAffectedVersionClean = `MATCH ()-[r:AFFECTS]->()
WHERE r.avRun IS NOT NULL
CALL { WITH r REMOVE r.avRun } IN TRANSACTIONS OF 10000 ROWS`

	// Step 13.
	cypherRejectCount = `MATCH (v:Vulnerability) WHERE v.description STARTS WITH $prefix
OPTIONAL MATCH (v)-[r]-()
RETURN count(DISTINCT v) AS nodes, count(DISTINCT r) AS rels`

	// The first count wins, so a restart after a partial delete keeps the
	// original number.
	cypherRejectRecord = `MERGE (j:Job {name: $name})
SET j.` + JobPropRejectDeleted + ` = coalesce(j.` + JobPropRejectDeleted + `, $nodes),
    j.` + JobPropRejectRelsDeleted + ` = coalesce(j.` + JobPropRejectRelsDeleted + `, $rels)`

	cypherRejectDelete = `MATCH (v:Vulnerability) WHERE v.description STARTS WITH $prefix
CALL { WITH v DETACH DELETE v } IN TRANSACTIONS OF 5000 ROWS`

	// Step 14.
	cypherExploitabilityReset = `MATCH (v:Vulnerability)
CALL { WITH v SET v.exploitability = 0, v.exploitDate = [] } IN TRANSACTIONS OF 10000 ROWS`

	cypherExploitabilitySet = `MATCH (e:Exploit)-[:EXPLOITS]->(v:Vulnerability)
WITH v, e ORDER BY e.exploitPublishDate
WITH v, collect(e.exploitPublishDate) AS ds
CALL { WITH v, ds SET v.exploitability = 1, v.exploitDate = ds } IN TRANSACTIONS OF 10000 ROWS`
)

func mapDomainRefers(r Row) (map[string]any, error) {
	return pairMapper("cveID", "cveID", "domainName", "domainName")(r)
}

func mapProductAffects(r Row) (map[string]any, error) {
	c, okC := r.Get("cveID")
	p, okP := r.Get("Product")
	if !okC || !okP {
		return nil, nil
	}
	m := map[string]any{"cveID": c, "productName": p, "productType": nil, "numOfVersion": nil}
	if t, ok := r.Get("ProductType"); ok {
		m["productType"] = t
	}
	if s, ok := r.Get("Nversions"); ok {
		n, err := ParseInt(s)
		if err != nil {
			return nil, fmt.Errorf("Nversions: %w", err)
		}
		m["numOfVersion"] = n
	}
	return m, nil
}

func mapVendorBelongs(r Row) (map[string]any, error) {
	return pairMapper("Product", "productName", "Vendor", "vendorName")(r)
}

// mapAffectedVersion numbers rows so the Cypher can keep file order.
func mapAffectedVersion() RowMapper {
	var i int64
	return func(r Row) (map[string]any, error) {
		c, okC := r.Get("cveID")
		p, okP := r.Get("Product")
		v, okV := r.Get("Version")
		if !okC || !okP || !okV {
			return nil, nil
		}
		i++
		return map[string]any{"cveID": c, "productName": p, "version": v, "i": i}, nil
	}
}

// DomainRefers is step 9.
func (l Loader) DomainRefers(ctx context.Context) (StepResult, error) {
	return l.relStep(ctx, LogicalDomainRelationship,
		StepSpec{Name: StepDomainRefers, Cypher: cypherDomainRefers, Map: mapDomainRefers}, "cveID", "domainName")
}

// ProductAffects is step 10.
func (l Loader) ProductAffects(ctx context.Context) (StepResult, error) {
	return l.relStep(ctx, LogicalProductVendorAffects,
		StepSpec{Name: StepProductAffects, Cypher: cypherProductAffects, Map: mapProductAffects}, "cveID", "Product")
}

// VendorBelongs is step 11.
func (l Loader) VendorBelongs(ctx context.Context) (StepResult, error) {
	return l.relStep(ctx, LogicalProductVendorAffects,
		StepSpec{Name: StepVendorBelongs, Cypher: cypherVendorBelongs, Map: mapVendorBelongs}, "Product", "Vendor")
}

// AffectedVersion is step 12. Each execution uses a fresh token, so a rerun or
// a restart rebuilds every list from the file (Requirement 4.6).
func (l Loader) AffectedVersion(ctx context.Context) (StepResult, error) {
	run := l.RunID + ":" + strconv.FormatInt(time.Now().UnixNano(), 36)
	res, err := l.relStep(ctx, LogicalAffectsAddProperty, StepSpec{
		Name: StepAffectedVer, Cypher: cypherAffectedVersion, Map: mapAffectedVersion(),
		Params: map[string]any{"run": run},
	}, "cveID", "Product", "Version")
	if err != nil {
		return res, err
	}
	for _, q := range []string{cypherAffectedVersionEmpty, cypherAffectedVersionClean} {
		if _, err := l.W.C.Auto(ctx, q, map[string]any{"run": run}); err != nil {
			return res, fmt.Errorf("step %s: %w", StepAffectedVer, err)
		}
	}
	return res, nil
}

// RejectDelete is step 13: it counts the REJECT Vulnerabilities and their
// relationships, stores the counts on the Job node, and deletes them in
// transactions of 5000.
func (l Loader) RejectDelete(ctx context.Context) (StepResult, error) {
	var res StepResult
	if err := (Jobs{C: l.W.C}).Begin(ctx, StepRejectDelete, 1); err != nil {
		return res, err
	}
	params := map[string]any{"prefix": rejectPrefix}
	v, err := l.W.C.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		r, err := tx.Run(ctx, cypherRejectCount, params)
		if err != nil {
			return nil, err
		}
		rec, err := r.Single(ctx)
		if err != nil {
			return nil, err
		}
		n, _ := rec.Values[0].(int64)
		rels, _ := rec.Values[1].(int64)
		return [2]int64{n, rels}, nil
	})
	if err != nil {
		return res, fmt.Errorf("step %s: count: %w", StepRejectDelete, err)
	}
	counts := v.([2]int64)
	_, err = l.W.C.WriteRetry(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		return nil, runJob(ctx, tx, cypherRejectRecord, map[string]any{"name": JobName, "nodes": counts[0], "rels": counts[1]})
	})
	if err != nil {
		return res, fmt.Errorf("step %s: record counts: %w", StepRejectDelete, err)
	}
	if _, err := l.W.C.Auto(ctx, cypherRejectDelete, params); err != nil {
		return res, fmt.Errorf("step %s: delete: %w", StepRejectDelete, err)
	}
	res.Rows, res.Sent = counts[0], counts[0]
	return res, nil
}

// Exploitability is step 14: reset every Vulnerability, then set the derived
// fields from the EXPLOITS relationships. It recomputes from scratch, so it is
// idempotent.
func (l Loader) Exploitability(ctx context.Context) (StepResult, error) {
	var res StepResult
	if err := (Jobs{C: l.W.C}).Begin(ctx, StepExploitability, 1); err != nil {
		return res, err
	}
	for _, q := range []string{cypherExploitabilityReset, cypherExploitabilitySet} {
		if _, err := l.W.C.Auto(ctx, q, nil); err != nil {
			return res, fmt.Errorf("step %s: %w", StepExploitability, err)
		}
	}
	return res, nil
}

// Steps9to14 runs steps 9 to 14 in VulKG order, marking each complete. Like
// Steps1to8 it does not skip completed steps.
func (l Loader) Steps9to14(ctx context.Context) error { return l.runAll(ctx, l.StepList()[8:14]) }
