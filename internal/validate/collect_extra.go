package validate

import (
	"context"
	"fmt"
	"regexp"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/checkpoint"
	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/model"
)

// All Cypher in this file is read-only, constant, and bounded: values come
// from parameters, and every result that lists examples has LIMIT 100.

// provenanceKeyRe matches p_<src>_run, _at, _ref, and _removed
// (internal/provenance, source names are [a-z][a-z0-9]{0,15}).
const provenanceKeyRe = `p_[a-z][a-z0-9]{0,15}_(run|at|ref|removed)`

// maxExploitValueLen is the longest allowed Exploit property value
// (Requirement 13.5).
const maxExploitValueLen = 256

// exploitBadProps selects Exploit nodes with a property outside the allowed
// set (eid, model.ExploitProps, sources, provenance) or a value over 256
// characters. toStringOrNull is null for lists, so `sources` is never measured.
const exploitBadProps = `MATCH (e:Exploit)
WITH e, [k IN keys(e) WHERE NOT (k IN $allowed OR k =~ $provRe)] +
        [k IN keys(e) WHERE (k IN $allowed OR k =~ $provRe) AND size(toStringOrNull(e[k])) > $maxLen | k + ' (>256 chars)'] AS bad
WHERE size(bad) > 0
`

const (
	exploitDataCountQuery  = exploitBadProps + `RETURN count(e) AS n`
	exploitDataSampleQuery = exploitBadProps + `RETURN coalesce(toString(e.eid), '') AS eid, bad ORDER BY eid LIMIT 100`

	// Vulnerabilities with an active EXPLOITS relationship whose derived
	// fields differ. The aggregation starts from the (few) EXPLOITS
	// relationships, not from every Vulnerability. The ordering and the
	// null handling match upsert.RecomputeExploitability.
	exploitabilityWithBase = `MATCH (e:Exploit)-[r:EXPLOITS]->(v:Vulnerability)
WHERE r.removed IS NULL OR r.removed = false
WITH v, e ORDER BY e.exploitPublishDate
WITH v, collect(e.exploitPublishDate) AS ds
WHERE v.exploitability IS NULL OR v.exploitability <> 1 OR v.exploitDate IS NULL OR v.exploitDate <> ds
`
	exploitabilityWithCount  = exploitabilityWithBase + `RETURN count(v) AS n`
	exploitabilityWithSample = exploitabilityWithBase + `RETURN toString(v.cveID) AS id ORDER BY id LIMIT 100`

	// Vulnerabilities without an active EXPLOITS relationship that do not
	// have exploitability 0 and exploitDate []. One property scan; the
	// anti-join runs only for the few candidates.
	exploitabilityWithoutBase = `MATCH (v:Vulnerability)
WHERE (v.exploitability IS NULL OR v.exploitability <> 0 OR v.exploitDate IS NULL OR size(v.exploitDate) > 0)
  AND NOT EXISTS { MATCH (e:Exploit)-[r:EXPLOITS]->(v) WHERE r.removed IS NULL OR r.removed = false }
`
	exploitabilityWithoutCount  = exploitabilityWithoutBase + `RETURN count(v) AS n`
	exploitabilityWithoutSample = exploitabilityWithoutBase + `RETURN toString(v.cveID) AS id ORDER BY id LIMIT 100`

	unsetCountQuery = `MATCH (v:Vulnerability)
WHERE v.gainedAccess IS NOT NULL OR v.vulnerabilityType IS NOT NULL
RETURN count(v) AS n,
       sum(CASE WHEN v.gainedAccess IS NOT NULL THEN 1 ELSE 0 END) AS gained,
       sum(CASE WHEN v.vulnerabilityType IS NOT NULL THEN 1 ELSE 0 END) AS vtype`
	unsetSampleQuery = `MATCH (v:Vulnerability)
WHERE v.gainedAccess IS NOT NULL OR v.vulnerabilityType IS NOT NULL
RETURN toString(v.cveID) AS id ORDER BY id LIMIT 100`
)

var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// smokeCountQueries returns name -> Cypher for every domain label and
// relationship type of the phase. Names come from internal/model; the check
// guards against a malformed registry entry.
func smokeCountQueries(phase int) (map[string]string, error) {
	out := map[string]string{}
	for _, n := range model.DomainLabels(phase) {
		if !identRe.MatchString(n) {
			return nil, fmt.Errorf("invalid label name %q", n)
		}
		out[n] = fmt.Sprintf("MATCH (n:%s) RETURN count(n)", n)
	}
	for _, r := range model.Rels {
		if r.Phase > phase {
			continue
		}
		if !identRe.MatchString(r.Name) {
			return nil, fmt.Errorf("invalid relationship type %q", r.Name)
		}
		out[r.Name] = fmt.Sprintf("MATCH ()-[r:%s]->() RETURN count(r)", r.Name)
	}
	return out, nil
}

func readAllP(ctx context.Context, c *graph.Client, q string, params map[string]any) ([]neo4j.Record, error) {
	v, err := c.Read(ctx, func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, q, params)
		if err != nil {
			return nil, err
		}
		var out []neo4j.Record
		for res.Next(ctx) {
			out = append(out, *res.Record())
		}
		return out, res.Err()
	})
	if err != nil {
		return nil, err
	}
	return v.([]neo4j.Record), nil
}

func readIntP(ctx context.Context, c *graph.Client, q string, params map[string]any) (int64, error) {
	rows, err := readAllP(ctx, c, q, params)
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	n, _ := rows[0].Values[0].(int64)
	return n, nil
}

func readStrings(ctx context.Context, c *graph.Client, q string) ([]string, error) {
	rows, err := readAll(ctx, c, q)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		s, _ := r.Values[0].(string)
		out = append(out, s)
	}
	return out, nil
}

// CollectSmokeCounts returns the count of every domain label and relationship
// type of the phase. The counts come from the store's count statistics.
func CollectSmokeCounts(ctx context.Context, c *graph.Client, phase int) (map[string]int64, error) {
	qs, err := smokeCountQueries(phase)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(qs))
	for name, q := range qs {
		n, err := readInt(ctx, c, q)
		if err != nil {
			return nil, fmt.Errorf("count %s: %w", name, err)
		}
		out[name] = n
	}
	return out, nil
}

// CollectExploitData runs check (a).
func CollectExploitData(ctx context.Context, c *graph.Client) (ExploitDataCheck, error) {
	allowed := append([]string{"eid", "sources"}, model.ExploitProps...)
	p := map[string]any{"allowed": allowed, "provRe": provenanceKeyRe, "maxLen": int64(maxExploitValueLen)}
	n, err := readIntP(ctx, c, exploitDataCountQuery, p)
	if err != nil {
		return ExploitDataCheck{}, err
	}
	var ex []ExploitDataExample
	if n > 0 {
		rows, err := readAllP(ctx, c, exploitDataSampleQuery, p)
		if err != nil {
			return ExploitDataCheck{}, err
		}
		for _, r := range rows {
			id, _ := r.Values[0].(string)
			ex = append(ex, ExploitDataExample{EID: id, Props: strList(r.Values[1])})
		}
	}
	return NewExploitDataCheck(n, ex), nil
}

func countAndSample(ctx context.Context, c *graph.Client, countQ, sampleQ string) (int64, []string, error) {
	n, err := readInt(ctx, c, countQ)
	if err != nil || n == 0 {
		return 0, nil, err
	}
	ex, err := readStrings(ctx, c, sampleQ)
	return n, ex, err
}

// CollectExploitability runs check (b).
func CollectExploitability(ctx context.Context, c *graph.Client) (ExploitabilityCheck, error) {
	nA, exA, err := countAndSample(ctx, c, exploitabilityWithCount, exploitabilityWithSample)
	if err != nil {
		return ExploitabilityCheck{}, err
	}
	nB, exB, err := countAndSample(ctx, c, exploitabilityWithoutCount, exploitabilityWithoutSample)
	if err != nil {
		return ExploitabilityCheck{}, err
	}
	return NewExploitabilityCheck(nA, nB, exA, exB), nil
}

// CollectUnsetProps runs check (c).
func CollectUnsetProps(ctx context.Context, c *graph.Client) (UnsetPropsCheck, error) {
	rec, ok, err := readOne(ctx, c, unsetCountQuery)
	if err != nil {
		return UnsetPropsCheck{}, err
	}
	var n, g, t int64
	if ok {
		n, _ = rec.Values[0].(int64)
		g, _ = rec.Values[1].(int64)
		t, _ = rec.Values[2].(int64)
	}
	var ex []string
	if n > 0 {
		if ex, err = readStrings(ctx, c, unsetSampleQuery); err != nil {
			return UnsetPropsCheck{}, err
		}
	}
	return NewUnsetPropsCheck(n, g, t, ex), nil
}

// collectExtra fills the checks of this file into in. in.Phase must be set.
func collectExtra(ctx context.Context, c *graph.Client, in *Inputs) error {
	ed, err := CollectExploitData(ctx, c)
	if err != nil {
		return fmt.Errorf("exploit data check: %w", err)
	}
	in.ExploitData = &ed
	ex, err := CollectExploitability(ctx, c)
	if err != nil {
		return fmt.Errorf("exploitability check: %w", err)
	}
	in.Exploitability = &ex
	us, err := CollectUnsetProps(ctx, c)
	if err != nil {
		return fmt.Errorf("unset properties check: %w", err)
	}
	in.Unset = &us
	bm, err := checkpoint.ReadBuildMeta(ctx, c)
	if err != nil {
		return fmt.Errorf("read build meta: %w", err)
	}
	in.BuildMode, in.SampleLimit = bm.Mode, bm.Limit
	counts, err := CollectSmokeCounts(ctx, c, max(in.Phase, 1))
	if err != nil {
		return err
	}
	in.Counts = counts
	sm := DecideSmoke(bm.Mode, bm.Limit, counts)
	in.Smoke = &sm
	return nil
}
