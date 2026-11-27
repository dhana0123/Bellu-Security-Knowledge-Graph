package trust

import (
	"errors"
	"math"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func TestValidate(t *testing.T) {
	if err := Validate(Provenance{Direction: Direct}); !errors.Is(err, ErrMissingSource) {
		t.Fatal(err)
	}
	if err := Validate(Provenance{Source: "nvd"}); !errors.Is(err, ErrMissingDirection) {
		t.Fatal(err)
	}
	if err := Validate(Provenance{Source: "nvd", Direction: "x"}); !errors.Is(err, ErrMissingDirection) {
		t.Fatal(err)
	}
	if err := Validate(Provenance{Source: "nvd", Direction: Inferred}); err != nil {
		t.Fatal(err)
	}
}

func TestClassifyAndConfidence(t *testing.T) {
	if Classify(nil) != Predicted {
		t.Fatal("empty should be predicted")
	}
	c, rule, ok := Confidence([]Evidence{{Source: "a"}})
	if c != nil || rule != RuleInferredNoRule || ok {
		t.Fatal("non-direct evidence must give no confidence")
	}
	one := []Evidence{{Source: "nvd", Direct: true}, {Source: "nvd", Direct: true}}
	if Classify(one) != Verified {
		t.Fatal("same source twice is verified")
	}
	if c, r, ok := Confidence(one); !ok || *c != 0.80 || r != RuleSingleAuthoritative {
		t.Fatal(r)
	}
	derived := []Evidence{{Source: "github-advisories", DerivedFrom: "osv", Direct: true}, {Source: "osv", Direct: true}}
	if Classify(derived) != Verified {
		t.Fatal("derived source counts once")
	}
	two := []Evidence{{Source: "nvd", Direct: true}, {Source: "osv", Direct: true}}
	if Classify(two) != Corroborated {
		t.Fatal("two independent sources")
	}
	if c, r, _ := Confidence(two); math.Abs(*c-0.85) > 1e-9 || r != RuleMultiSource {
		t.Fatal(*c, r)
	}
}

func TestCanPromote(t *testing.T) {
	at := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	f := Fact{State: Predicted, PredictedAt: at}
	if CanPromote(f, []Evidence{{Direct: true, IngestedAt: at}}) {
		t.Fatal("same instant is not after")
	}
	if CanPromote(f, []Evidence{{Direct: false, IngestedAt: at.Add(time.Hour)}}) {
		t.Fatal("inferred evidence cannot promote")
	}
	if !CanPromote(f, []Evidence{{Direct: true, IngestedAt: at.Add(time.Second)}}) {
		t.Fatal("new direct evidence promotes")
	}
}

// Feature: bellu-security-knowledge-graph, Property 20: Trust-state classification and confidence
// **Validates: Requirements 7.3, 7.4, 7.5, 7.6, 7.7, 7.8**
func TestPropertyClassifyConfidence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ev := rapid.SliceOf(rapid.Custom(func(t *rapid.T) Evidence {
			return Evidence{
				Source:      rapid.SampledFrom([]string{"nvd", "osv", "ghsa", "kev"}).Draw(t, "s"),
				DerivedFrom: rapid.SampledFrom([]string{"", "", "osv", "nvd"}).Draw(t, "d"),
				Direct:      rapid.Bool().Draw(t, "direct"),
			}
		})).Draw(t, "ev")
		st := Classify(ev)
		c, rule, ok := Confidence(ev)
		if rule == "" {
			t.Fatal("rule id always present")
		}
		if st == Predicted {
			if c != nil || ok {
				t.Fatal("predicted must have unset confidence")
			}
			return
		}
		if c == nil || !ok || *c < 0 || *c > 0.95+1e-9 {
			t.Fatalf("bad confidence %v", c)
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 20: Trust-state classification and confidence (oracle form)
// **Validates: Requirements 7.3, 7.4, 7.5, 7.6, 7.7, 7.8**
func TestPropertyClassifyOracle(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ev := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) Evidence {
			return Evidence{
				Source:      rapid.SampledFrom([]string{"nvd", "osv", "ghsa", "kev"}).Draw(t, "s"),
				DerivedFrom: rapid.SampledFrom([]string{"", "", "osv", "nvd", "kev"}).Draw(t, "d"),
				Direct:      rapid.Bool().Draw(t, "direct"),
			}
		}), 0, 6).Draw(t, "ev")

		var direct []Evidence
		for _, e := range ev {
			if e.Direct {
				direct = append(direct, e)
			}
		}
		pair := false
		for i := range direct {
			for j := i + 1; j < len(direct); j++ {
				if Independent(direct[i], direct[j]) {
					pair = true
				}
			}
		}
		want := Predicted
		switch {
		case pair:
			want = Corroborated
		case len(direct) > 0:
			want = Verified
		}
		if got := Classify(ev); got != want {
			t.Fatalf("Classify=%s want %s for %+v", got, want, ev)
		}
		// order independence
		rev := make([]Evidence, len(ev))
		for i := range ev {
			rev[len(ev)-1-i] = ev[i]
		}
		if Classify(rev) != want {
			t.Fatal("classification depends on order")
		}

		c, rule, ok := Confidence(ev)
		if rule == "" {
			t.Fatal("rule id missing")
		}
		if want == Predicted {
			if c != nil || ok || rule != RuleInferredNoRule {
				t.Fatalf("predicted must have unset confidence: %v %s", c, rule)
			}
			return
		}
		if c == nil || !ok || *c < 0 || *c > 1 {
			t.Fatalf("bad confidence %v", c)
		}
		if (want == Verified) != (rule == RuleSingleAuthoritative) {
			t.Fatalf("rule %s for state %s", rule, want)
		}
	})
}
