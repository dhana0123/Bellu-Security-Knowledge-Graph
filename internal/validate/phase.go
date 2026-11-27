package validate

import (
	"fmt"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/model"
)

// Checks for the schema of phases 2 and 3 run only when the applied
// migrations include them (V1xx is phase 2, V2xx phase 3). The Package,
// AttackPattern, Technique, and AtlasTechnique labels and their relationship
// types come from internal/model, so a later phase needs no new list here.

// phaseConstraints are the uniqueness constraints of migrations V101 and V201.
var phaseConstraints = []struct {
	Phase int
	RequiredConstraint
}{
	{2, RequiredConstraint{"UniquePackagePurl", "Package", "purl"}},
	{3, RequiredConstraint{"UniqueAttackPatternID", "AttackPattern", "capecID"}},
	{3, RequiredConstraint{"UniqueTechniqueID", "Technique", "attackID"}},
	{3, RequiredConstraint{"UniqueAtlasTechniqueID", "AtlasTechnique", "atlasID"}},
}

// RequiredConstraintsFor returns the constraints required at the given schema
// phase: the Phase 1 list plus those of the later phases up to phase.
func RequiredConstraintsFor(phase int) []RequiredConstraint {
	out := append([]RequiredConstraint(nil), RequiredConstraints...)
	for _, p := range phaseConstraints {
		if p.Phase <= phase {
			out = append(out, p.RequiredConstraint)
		}
	}
	return out
}

// phaseDupQueries returns the duplicate-key queries of the domain labels of
// phases 2 up to phase. Names come from the registry, never from input.
func phaseDupQueries(phase int) []dupQuery {
	var out []dupQuery
	for _, l := range model.Labels {
		if l.Kind != model.Domain || l.Phase < 2 || l.Phase > phase {
			continue
		}
		out = append(out, dupQuery{l.Name, l.Key, fmt.Sprintf(
			"MATCH (n:%[1]s) WITH n.%[2]s AS k, count(*) AS c WHERE c > 1 RETURN toString(k), c ORDER BY c DESC, toString(k) LIMIT 100", l.Name, l.Key)})
	}
	return out
}

// phaseEndpointQueries returns the endpoint-label queries of the relationship
// types of phases 2 up to phase.
func phaseEndpointQueries(phase int) []endpointQuery {
	var out []endpointQuery
	for _, r := range model.Rels {
		if r.Phase < 2 || r.Phase > phase {
			continue
		}
		cond := fmt.Sprintf("MATCH (a)-[r:%s]->(b) WHERE NOT (a:%s AND b:%s)", r.Name, r.From, r.To)
		out = append(out, endpointQuery{
			rule:   EndpointRule{Type: r.Name, From: r.From, To: r.To},
			count:  cond + " RETURN count(r)",
			sample: cond + " RETURN elementId(r), labels(a), labels(b) ORDER BY elementId(r) LIMIT 100",
		})
	}
	return out
}

const maxMigrationQuery = `OPTIONAL MATCH (m:Migration) RETURN max(m.version)`
