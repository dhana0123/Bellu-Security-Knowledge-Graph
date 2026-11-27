package cvss

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func genV3Vector(t *rapid.T) string {
	ver := rapid.SampledFrom([]string{"3.0", "3.1"}).Draw(t, "ver")
	pick := func(name string, vals ...string) string {
		return name + ":" + rapid.SampledFrom(vals).Draw(t, name)
	}
	return fmt.Sprintf("CVSS:%s/%s/%s/%s/%s/%s/%s/%s/%s", ver,
		pick("AV", "N", "A", "L", "P"), pick("AC", "L", "H"), pick("PR", "N", "L", "H"),
		pick("UI", "N", "R"), pick("S", "U", "C"), pick("C", "H", "L", "N"),
		pick("I", "H", "L", "N"), pick("A", "H", "L", "N"))
}

// Feature: bellu-security-knowledge-graph, Property 10: CVSS validation status
// **Validates: Requirements 4.5, 4.6**
func TestProperty10CVSSValidationStatus(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		vec := genV3Vector(t)
		computed, ok := Score3(vec)
		if !ok {
			t.Fatalf("valid vector not parsed: %s", vec)
		}
		switch rapid.SampledFrom([]string{"equal", "differ", "absent"}).Draw(t, "mode") {
		case "equal":
			r := computed
			score, status, reason := Assess(vec, &r)
			if status != "valid" || score == nil || *score != computed || reason != "" {
				t.Fatalf("%s: got %v %q %q", vec, score, status, reason)
			}
		case "differ":
			// reported differs from computed by at least 0.1 (one decimal), within 0..10
			tenths := int(math.Round(computed * 10))
			other := rapid.IntRange(0, 100).Filter(func(x int) bool { return x != tenths }).Draw(t, "other")
			r := float64(other) / 10
			score, status, _ := Assess(vec, &r)
			if status != "mismatch" || score == nil || *score != r {
				t.Fatalf("%s reported %v: got %v %q", vec, r, score, status)
			}
		case "absent":
			score, status, _ := Assess(vec, nil)
			if status != "computed" || score == nil || *score != computed {
				t.Fatalf("%s: got %v %q", vec, score, status)
			}
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 10: CVSS validation status
// **Validates: Requirements 4.5, 4.6**
func TestProperty10CVSSUnverified(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var vec string
		switch rapid.IntRange(0, 4).Draw(t, "kind") {
		case 0:
			vec = "CVSS:4.0/" + rapid.StringMatching(`[A-Z]{1,3}:[A-Z]/[A-Z]{1,3}:[A-Z]`).Draw(t, "v4")
		case 1:
			vec = fmt.Sprintf("AV:%s/AC:%s/Au:%s/C:%s/I:%s/A:%s",
				rapid.SampledFrom([]string{"N", "A", "L"}).Draw(t, "av"),
				rapid.SampledFrom([]string{"L", "M", "H"}).Draw(t, "ac"),
				rapid.SampledFrom([]string{"N", "S", "M"}).Draw(t, "au"),
				rapid.SampledFrom([]string{"N", "P", "C"}).Draw(t, "c"),
				rapid.SampledFrom([]string{"N", "P", "C"}).Draw(t, "i"),
				rapid.SampledFrom([]string{"N", "P", "C"}).Draw(t, "a"))
		case 2:
			// v3 vector missing a metric
			parts := strings.Split(genV3Vector(t), "/")
			drop := rapid.IntRange(1, len(parts)-1).Draw(t, "drop")
			vec = strings.Join(append(append([]string{}, parts[:drop]...), parts[drop+1:]...), "/")
		case 3:
			// v3 vector with an invalid metric value
			parts := strings.Split(genV3Vector(t), "/")
			i := rapid.IntRange(1, len(parts)-1).Draw(t, "idx")
			parts[i] = strings.SplitN(parts[i], ":", 2)[0] + ":Z"
			vec = strings.Join(parts, "/")
		default:
			vec = rapid.StringMatching(`[a-z0-9 /:]{0,30}`).Draw(t, "junk")
		}
		var reported *float64
		if rapid.Bool().Draw(t, "hasScore") {
			r := float64(rapid.IntRange(0, 100).Draw(t, "r")) / 10
			reported = &r
		}
		score, status, reason := Assess(vec, reported)
		if status != "unverified" || reason == "" {
			t.Fatalf("%q: status=%q reason=%q", vec, status, reason)
		}
		if (score == nil) != (reported == nil) || (score != nil && *score != *reported) {
			t.Fatalf("%q: score changed: %v vs %v", vec, score, reported)
		}
	})
}
