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
	if got := len(DomainLabels(1)); got != 7 {
		t.Errorf("phase 1 domain labels = %d, want 7 (Requirement 2.5)", got)
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
