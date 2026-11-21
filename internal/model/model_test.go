package model

import "testing"

func TestRegistryIsConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, l := range Labels {
		if seen[l.Name] || l.Key == "" || l.Phase < 1 || l.Phase > 3 {
			t.Errorf("bad label %+v", l)
		}
		seen[l.Name] = true
	}
	rels := map[string]bool{}
	for _, r := range Rels {
		if rels[r.Name] {
			t.Errorf("duplicate relationship %s", r.Name)
		}
		rels[r.Name] = true
		if _, ok := LabelByName(r.From); !ok {
			t.Errorf("%s: unknown start label %s", r.Name, r.From)
		}
		if _, ok := LabelByName(r.To); !ok {
			t.Errorf("%s: unknown end label %s", r.Name, r.To)
		}
	}
}

func TestPhaseOneSchema(t *testing.T) {
	if got := len(DomainLabels(1)); got != 9 {
		t.Errorf("phase 1 domain labels = %d, want 9 (Requirement 2.5 plus Repository and FixCommit moved to phase 1)", got)
	}
	if r, _ := RelByName("CHILD_OF"); len(r.Identity) != 1 || r.Identity[0] != "viewID" {
		t.Errorf("CHILD_OF identity = %v", r.Identity)
	}
	for _, n := range ResetLabels() {
		if n == "Migration" || n == "ApiKey" {
			t.Errorf("reset must keep %s", n)
		}
	}
}

func TestPhaseOfMigration(t *testing.T) {
	for v, want := range map[int]int{1: 1, 3: 1, 99: 1, 100: 2, 101: 2, 199: 2, 200: 3, 201: 3, 999: 3} {
		if got := PhaseOfMigration(v); got != want {
			t.Errorf("PhaseOfMigration(%d) = %d, want %d", v, got, want)
		}
	}
	if PhaseOfMigrations(nil) != 1 || PhaseOfMigrations([]int{1, 3, 101}) != 2 || PhaseOfMigrations([]int{201, 3, 101}) != 3 {
		t.Error("PhaseOfMigrations must use the highest version")
	}
}

func TestLaterPhaseSchema(t *testing.T) {
	if r, ok := RelByName("ADAPTED_FROM"); !ok || r.From != "AtlasTechnique" || r.To != "Technique" || r.Phase != 3 {
		t.Errorf("ADAPTED_FROM = %+v %v", r, ok)
	}
	for name, phase := range map[string]int{"Package": 2, "AttackPattern": 3, "Technique": 3, "AtlasTechnique": 3} {
		if l, ok := LabelByName(name); !ok || l.Phase != phase {
			t.Errorf("%s = %+v", name, l)
		}
	}
	for name, phase := range map[string]int{"AFFECTS_PACKAGE": 2, "HOSTED_IN": 2, "RELATED_ATTACK_PATTERN": 3, "MAPS_TO_TECHNIQUE": 3} {
		if r, ok := RelByName(name); !ok || r.Phase != phase {
			t.Errorf("%s = %+v", name, r)
		}
	}
}
