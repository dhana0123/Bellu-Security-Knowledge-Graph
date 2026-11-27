// Package ecosystem holds the pure string rules for ecosystem and package names.
// It is a leaf package so that both model and normalize can import it.
package ecosystem

import (
	"regexp"
	"strings"
)

// Vocabulary is the fixed set of canonical ecosystem names.
var Vocabulary = []string{"npm", "PyPI", "Maven", "Go", "crates.io", "NuGet"}

// Canonical maps a name to its vocabulary value, case-insensitively. When the name is
// outside the vocabulary it is returned trimmed and unchanged with mapped=false.
func Canonical(s string) (name string, mapped bool) {
	t := strings.TrimSpace(s)
	for _, v := range Vocabulary {
		if strings.EqualFold(t, v) {
			return v, true
		}
	}
	return t, false
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

// Package returns the canonical form of a package name for an ecosystem. The ecosystem
// may be given in any case; unknown ecosystems only get whitespace trimmed.
func Package(eco, name string) string {
	name = strings.TrimSpace(name)
	e, _ := Canonical(eco)
	switch e {
	case "PyPI":
		return pypiSep.ReplaceAllString(strings.ToLower(name), "-")
	case "npm", "crates.io", "NuGet":
		return strings.ToLower(name)
	case "Maven":
		g, a, ok := strings.Cut(name, ":")
		if !ok {
			return name
		}
		return strings.TrimSpace(g) + ":" + strings.TrimSpace(a)
	}
	return name
}
