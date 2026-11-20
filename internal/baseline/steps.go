package baseline

import (
	"context"
	"fmt"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/provenance"
)

// Step names (VulKG load order, steps 1 to 8).
const (
	StepVulnNodes     = "vuln_nodes"
	StepExploitNodes  = "exploit_nodes"
	StepAuthorNodes   = "author_nodes"
	StepWrites        = "writes"
	StepExploitsRel   = "exploits_rel"
	StepWeaknessNodes = "weakness_nodes"
	StepExampleOf     = "example_of"
	StepVulnAddProps  = "vuln_addprops"
)

// Job properties written by the loader steps. Other components (validation)
// read them from the (:Job {name:"baseline-load"}) node.
const (
	JobPropBareNodes   = "bareNodes"
	JobMissingPrefix   = "missing_" // + step name, for example missing_exploits_rel
	bareMarkerProperty = "bskgBare"
)

// Loader runs the baseline load steps against Neo4j.
type Loader struct {
	W     Writer
	Files map[string]string // logical file name -> local path (from Fetcher.Fetch)
	RunID string            // Sync_Run id written to p_vulkg_run
	Ref   string            // upstream commit SHA written to p_vulkg_ref
	At    time.Time         // load time written to p_vulkg_at
}

func (l Loader) params() map[string]any {
	return map[string]any{"runID": l.RunID, "at": l.At.UTC().Truncate(time.Millisecond), "ref": l.Ref}
}

func (l Loader) file(logical string) (string, error) {
	p, ok := l.Files[logical]
	if !ok {
		return "", fmt.Errorf("baseline file %q not provided", logical)
	}
	return p, nil
}

func mustSet(v string) string {
	s, err := provenance.SetClause(v, provenance.SourceVulKG)
	if err != nil {
		panic(err) // constant source name
	}
	return s
}

// Vulnerability column mapping (VulKG script; CVSS scores are decimals,
// the recorded deviation from the script's toInteger casts, Requirement 4.9).
var vulnFields = []Field{
	{"publishedDate", "publishedDate", TDate},
	{"description_value", "description", TString},
	{"num_reference", "numOfReference", TInt},
	{"v2version", "v2version", TInt},
	{"v2baseScore", "v2baseScore", TFloat},
	{"v2accessVector", "v2accessVector", TString},
	{"v2accessComplexity", "v2accessComplexity", TString},
	{"v2authentication", "v2authentication", TString},
	{"v2confidentialityImpact", "v2confidentialityImpact", TString},
	{"v2integrityImpact", "v2integrityImpact", TString},
	{"v2availabilityImpact", "v2availabilityImpact", TString},
	{"v2vectorString", "v2vectorString", TString},
	{"v2impactScore", "v2impactScore", TFloat},
	{"v2exploitabilityScore", "v2exploitabilityScore", TFloat},
	{"v2userInteractionRequired", "v2userInteractionRequired", TBool},
	{"v2severity", "v2severity", TString},
	{"v2obtainUserPrivilege", "v2obtainUserPrivilege", TBool},
	{"v2obtainAllPrivilege", "v2obtainAllPrivilege", TBool},
	{"v2acInsufInfo", "v2acInsufInfo", TBool},
	{"v2obtainOtherPrivilege", "v2obtainOtherPrivilege", TBool},
	{"v3version", "v3version", TFloat},
	{"v3baseScore", "v3baseScore", TFloat},
	{"v3attackVector", "v3attackVector", TString},
	{"v3attackComplexity", "v3attackComplexity", TString},
	{"v3privilegesRequired", "v3privilegesRequired", TString},
	{"v3userInteraction", "v3userInteraction", TString},
	{"v3scope", "v3scope", TString},
	{"v3confidentialityImpact", "v3confidentialityImpact", TString},
	{"v3integrityImpact", "v3integrityImpact", TString},
	{"v3availabilityImpact", "v3availabilityImpact", TString},
	{"v3vectorString", "v3vectorString", TString},
	{"v3impactScore", "v3impactScore", TFloat},
	{"v3exploitabilityScore", "v3exploitabilityScore", TFloat},
	{"v3baseSeverity", "v3baseSeverity", TString},
}

var (
	exploitFields = []Field{
		{"Exploit_Date", "exploitPublishDate", TDate},
		{"Exploit_Type", "exploitType", TString},
		{"Platform", "platform", TString},
	}
	weaknessFields = []Field{
		{"cweView", "cweView", TStringList},
		{"cweName", "cweName", TString},
		{"weaknessAbstraction", "weaknessAbstraction", TString},
		{"status", "status", TString},
		{"description", "description", TString},
		{"extendedDescription", "extendedDescription", TString},
	}
)

// keyedProps maps a row to {key: <value>, props: {...}}; rows without the key
// column are skipped.
func keyedProps(keyCol, keyName string, fields []Field) RowMapper {
	return func(r Row) (map[string]any, error) {
		k, ok := r.Get(keyCol)
		if !ok {
			return nil, nil
		}
		p, err := r.Props(fields)
		if err != nil {
			return nil, err
		}
		return map[string]any{keyName: k, "props": p}, nil
	}
}

// pairMapper maps two key columns to {a, b}; rows missing either are skipped.
func pairMapper(colA, nameA, colB, nameB string) RowMapper {
	return func(r Row) (map[string]any, error) {
		a, okA := r.Get(colA)
		b, okB := r.Get(colB)
		if !okA || !okB {
			return nil, nil
		}
		return map[string]any{nameA: a, nameB: b}, nil
	}
}

func mapVulnNode(r Row) (map[string]any, error) {
	return keyedProps("cveID", "cveID", vulnFields)(r)
}

func mapExploitNode(r Row) (map[string]any, error) {
	return keyedProps("ExploitID", "eid", exploitFields)(r)
}

func mapAuthorNode(r Row) (map[string]any, error) {
	a, ok := r.Get("Author")
	if !ok {
		return nil, nil
	}
	return map[string]any{"authorName": a}, nil
}

func mapWrites(r Row) (map[string]any, error) {
	return pairMapper("Author", "authorName", "ExploitID", "eid")(r)
}

func mapExploitsRel(r Row) (map[string]any, error) {
	return pairMapper("eid", "eid", "cveID", "cveID")(r)
}

func mapWeakness(r Row) (map[string]any, error) {
	return keyedProps("cweID", "cweID", weaknessFields)(r)
}

func mapExampleOf(r Row) (map[string]any, error) {
	return pairMapper("cveID", "cveID", "CWEID", "cweID")(r)
}

func mapAddProps(r Row) (map[string]any, error) {
	c, ok := r.Get("cveID")
	if !ok {
		return nil, nil
	}
	m := map[string]any{"cveID": c, "gainedAccess": nil, "vulnerabilityType": nil}
	if g, ok := r.Get("GainedAccess"); ok {
		m["gainedAccess"] = g
	}
	if t, ok := r.Get("VulnerabilityType"); ok {
		m["vulnerabilityType"] = ParseList(t)
	}
	return m, nil
}

// Step Cypher. All constant text; provenance is written on creation only.
var (
	cypherVulnNodes = `UNWIND $rows AS row
MERGE (v:Vulnerability {cveID: row.cveID})
ON CREATE SET v += row.props, ` + mustSet("v") + `
RETURN count(v) AS matched`

	cypherExploitNodes = `UNWIND $rows AS row
MERGE (e:Exploit {eid: row.eid})
ON CREATE SET e += row.props, ` + mustSet("e") + `
RETURN count(e) AS matched`

	cypherAuthorNodes = `UNWIND $rows AS row
MERGE (a:Author {authorName: row.authorName})
ON CREATE SET ` + mustSet("a") + `
RETURN count(a) AS matched`

	cypherWrites = `UNWIND $rows AS row
MATCH (e:Exploit {eid: row.eid})
MATCH (a:Author {authorName: row.authorName})
MERGE (a)-[r:WRITES]->(e)
ON CREATE SET ` + mustSet("r") + `
RETURN count(r) AS matched`

	cypherExploitsRel = `UNWIND $rows AS row
MATCH (e:Exploit {eid: row.eid})
MATCH (v:Vulnerability {cveID: row.cveID})
MERGE (e)-[r:EXPLOITS]->(v)
ON CREATE SET ` + mustSet("r") + `
RETURN count(r) AS matched`

	cypherWeaknessNodes = `UNWIND $rows AS row
MERGE (w:Weakness {cweID: row.cweID})
ON CREATE SET w += row.props, ` + mustSet("w") + `
RETURN count(w) AS matched`

	cypherExampleOf = `UNWIND $rows AS row
MATCH (v:Vulnerability {cveID: row.cveID})
MATCH (w:Weakness {cweID: row.cweID})
MERGE (v)-[r:EXAMPLE_OF]->(w)
ON CREATE SET ` + mustSet("r") + `
RETURN count(r) AS matched`

	// Step 8 follows the VulKG script literally: ON MATCH SET only. A node the
	// MERGE creates gets cveID and provenance (plus a temporary marker used to
	// count bare nodes) and nothing else.
	cypherVulnAddProps = `UNWIND $rows AS row
MERGE (v:Vulnerability {cveID: row.cveID})
ON CREATE SET v.` + bareMarkerProperty + ` = true, ` + mustSet("v") + `
ON MATCH SET v.gainedAccess = row.gainedAccess, v.vulnerabilityType = row.vulnerabilityType
RETURN count(v) AS matched`

	cypherRecordMissing = `MERGE (j:Job {name: $name})
SET j[$prop] = $n`

	cypherCountBare = `MATCH (v:Vulnerability) WHERE v.` + bareMarkerProperty + ` = true
WITH collect(v) AS vs
FOREACH (v IN vs | REMOVE v.` + bareMarkerProperty + `)
WITH size(vs) AS n
MERGE (j:Job {name: $name})
SET j.` + JobPropBareNodes + ` = coalesce(j.` + JobPropBareNodes + `, 0) + n
RETURN j.` + JobPropBareNodes + ` AS total`
)

func (l Loader) run(ctx context.Context, logical string, spec StepSpec, required ...string) (StepResult, error) {
	path, err := l.file(logical)
	if err != nil {
		return StepResult{}, err
	}
	total, err := CountRows(path)
	if err != nil {
		return StepResult{}, err
	}
	p := l.params()
	for k, v := range spec.Params {
		p[k] = v
	}
	spec.Params = p
	res, err := l.W.RunStep(ctx, path, total, spec, required...)
	if err != nil {
		return res, err
	}
	return res, nil
}

func (l Loader) recordMissing(ctx context.Context, step string, n int64) error {
	_, err := l.W.C.WriteRetry(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		return nil, runJob(ctx, tx, cypherRecordMissing, map[string]any{"name": JobName, "prop": JobMissingPrefix + step, "n": n})
	})
	if err != nil {
		return fmt.Errorf("record missing count for %s: %w", step, err)
	}
	return nil
}

// relStep runs a relationship step and stores its missing-endpoint count.
func (l Loader) relStep(ctx context.Context, logical string, spec StepSpec, required ...string) (StepResult, error) {
	res, err := l.run(ctx, logical, spec, required...)
	if err != nil {
		return res, err
	}
	return res, l.recordMissing(ctx, spec.Name, res.Missing)
}

// VulnNodes is step 1.
func (l Loader) VulnNodes(ctx context.Context) (StepResult, error) {
	return l.run(ctx, LogicalVulnerabilityNodes,
		StepSpec{Name: StepVulnNodes, Cypher: cypherVulnNodes, Map: mapVulnNode}, "cveID")
}

// ExploitNodes is step 2.
func (l Loader) ExploitNodes(ctx context.Context) (StepResult, error) {
	return l.run(ctx, LogicalExploitNodes,
		StepSpec{Name: StepExploitNodes, Cypher: cypherExploitNodes, Map: mapExploitNode}, "ExploitID")
}

// AuthorNodes is step 3.
func (l Loader) AuthorNodes(ctx context.Context) (StepResult, error) {
	return l.run(ctx, LogicalExploitNodes,
		StepSpec{Name: StepAuthorNodes, Cypher: cypherAuthorNodes, Map: mapAuthorNode}, "Author")
}

// Writes is step 4.
func (l Loader) Writes(ctx context.Context) (StepResult, error) {
	return l.relStep(ctx, LogicalExploitNodes,
		StepSpec{Name: StepWrites, Cypher: cypherWrites, Map: mapWrites}, "Author", "ExploitID")
}

// ExploitsRel is step 5.
func (l Loader) ExploitsRel(ctx context.Context) (StepResult, error) {
	return l.relStep(ctx, LogicalHasExploit,
		StepSpec{Name: StepExploitsRel, Cypher: cypherExploitsRel, Map: mapExploitsRel}, "eid", "cveID")
}

// WeaknessNodes is step 6.
func (l Loader) WeaknessNodes(ctx context.Context) (StepResult, error) {
	return l.run(ctx, LogicalWeaknessNodes,
		StepSpec{Name: StepWeaknessNodes, Cypher: cypherWeaknessNodes, Map: mapWeakness}, "cweID")
}

// ExampleOf is step 7.
func (l Loader) ExampleOf(ctx context.Context) (StepResult, error) {
	return l.relStep(ctx, LogicalVulnerabilityAddProperties,
		StepSpec{Name: StepExampleOf, Cypher: cypherExampleOf, Map: mapExampleOf}, "cveID", "CWEID")
}

// VulnAddProps is step 8. After the batches it counts the bare nodes the step
// created (cveID only) and adds that number to the Job's bareNodes property.
// The marker is removed in the same transaction, so a restart never counts a
// node twice.
func (l Loader) VulnAddProps(ctx context.Context) (StepResult, error) {
	res, err := l.run(ctx, LogicalVulnerabilityAddProperties,
		StepSpec{Name: StepVulnAddProps, Cypher: cypherVulnAddProps, Map: mapAddProps}, "cveID")
	if err != nil {
		return res, err
	}
	_, err = l.W.C.WriteRetry(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		return nil, runJob(ctx, tx, cypherCountBare, map[string]any{"name": JobName})
	})
	if err != nil {
		return res, fmt.Errorf("count bare nodes: %w", err)
	}
	return res, nil
}

// Steps1to8 runs steps 1 to 8 in VulKG order, marking each complete. It does
// not skip completed steps; Runner decides which to run.
func (l Loader) Steps1to8(ctx context.Context) error { return l.runAll(ctx, l.StepList()[:8]) }

// runAll runs steps in order and marks each complete, without skipping or retry.
func (l Loader) runAll(ctx context.Context, steps []Step) error {
	for _, s := range steps {
		if err := s.Run(ctx); err != nil {
			return err
		}
		if err := (Jobs{C: l.W.C}).Complete(ctx, s.Name); err != nil {
			return err
		}
	}
	return nil
}
