// Package cvss computes CVSS v3.x base scores so source-reported scores can be validated.
package cvss

import (
	"math"
	"strings"
)

// Version returns "3.1", "3.0", "4.0", "2.0" or "" from a vector string.
func Version(vector string) string {
	switch {
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		return "3.1"
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		return "3.0"
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		return "4.0"
	case strings.Contains(vector, "Au:") && strings.Contains(vector, "AV:"):
		return "2.0"
	}
	return ""
}

func roundUp(x float64) float64 {
	i := math.Round(x * 100000)
	if int64(i)%10000 == 0 {
		return i / 100000
	}
	return (math.Floor(i/10000) + 1) / 10
}

// Score3 computes the v3.x base score. ok=false when the vector cannot be parsed.
func Score3(vector string) (float64, bool) {
	if v := Version(vector); v != "3.1" && v != "3.0" {
		return 0, false
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			return 0, false
		}
		m[kv[0]] = kv[1]
	}
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	changed := m["S"] == "C"
	if m["S"] != "C" && m["S"] != "U" {
		return 0, false
	}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[m["PR"]]
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, ok1 := cia[m["C"]]
	i, ok2 := cia[m["I"]]
	a, ok3 := cia[m["A"]]
	if av == 0 || ac == 0 || ui == 0 || pr == 0 || !ok1 || !ok2 || !ok3 {
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	expl := 8.22 * av * ac * pr * ui
	if changed {
		return roundUp(math.Min(1.08*(impact+expl), 10)), true
	}
	return roundUp(math.Min(impact+expl, 10)), true
}

// Assess returns the score to record, a validation status and a reason:
//
//	valid      – reported score equals the computed score
//	mismatch   – reported score differs from the computed score (reported is kept)
//	computed   – no reported score; score was computed from the vector
//	unverified – cannot be computed; reported score kept if any. The reason is
//	             unsupported-version:4.0, unsupported-version:2.0 or malformed-vector.
func Assess(vector string, reported *float64) (*float64, string, string) {
	if s, ok := Score3(vector); ok {
		if reported == nil {
			return &s, "computed", ""
		}
		if math.Abs(*reported-s) < 0.05 {
			return reported, "valid", ""
		}
		return reported, "mismatch", ""
	}
	switch Version(vector) {
	case "4.0":
		return reported, "unverified", "unsupported-version:4.0"
	case "2.0":
		return reported, "unverified", "unsupported-version:2.0"
	}
	return reported, "unverified", "malformed-vector"
}
