// Package provenance builds per-source provenance properties and the Cypher
// that writes them. Storage is compact: properties on the node or
// relationship, no extra nodes.
package provenance

import (
	"fmt"
	"regexp"
	"time"
)

var sourceRe = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)

// ValidSource reports whether name may be used as a property prefix.
func ValidSource(name string) bool { return sourceRe.MatchString(name) }

// Key returns the property name p_<src>_<suffix> (suffix: run, at, ref, removed).
func Key(src, suffix string) (string, error) {
	if !ValidSource(src) {
		return "", fmt.Errorf("invalid source name %q", src)
	}
	return "p_" + src + "_" + suffix, nil
}

// Props returns the provenance properties a source writes when it creates or
// changes an item. "sources" holds only src; use SetClause to merge it into an
// existing list inside Cypher.
func Props(src, runID, ref string, at time.Time) (map[string]any, error) {
	if !ValidSource(src) {
		return nil, fmt.Errorf("invalid source name %q", src)
	}
	return map[string]any{
		"sources":           []string{src},
		"p_" + src + "_run": runID,
		"p_" + src + "_at":  at.UTC().Truncate(time.Millisecond),
		"p_" + src + "_ref": ref,
	}, nil
}

// SetClause returns a Cypher SET fragment (without the SET keyword) for the
// variable v. It appends src to v.sources once and writes p_<src>_run, _at,
// and _ref from the parameters $runID, $at (datetime string or value), and
// $ref. The source name is validated, so the text is safe to concatenate.
func SetClause(v, src string) (string, error) {
	if !ValidSource(src) {
		return "", fmt.Errorf("invalid source name %q", src)
	}
	return fmt.Sprintf(
		"%[1]s.sources = CASE WHEN %[1]s.sources IS NULL THEN ['%[2]s'] "+
			"WHEN '%[2]s' IN %[1]s.sources THEN %[1]s.sources ELSE %[1]s.sources + '%[2]s' END, "+
			"%[1]s.p_%[2]s_run = $runID, %[1]s.p_%[2]s_at = $at, %[1]s.p_%[2]s_ref = $ref",
		v, src), nil
}

// RemovedKeyOf returns p_<src>_removed without validating src. Callers pass
// source names that were already validated.
func RemovedKeyOf(src string) string { return "p_" + src + "_removed" }

// RemovedKey returns p_<src>_removed for a validated source name.
func RemovedKey(src string) (string, error) { return Key(src, "removed") }

// MergeSources returns list with src appended once, preserving order. The
// input slice is not modified.
func MergeSources(list []string, src string) []string {
	for _, s := range list {
		if s == src {
			return append([]string(nil), list...)
		}
	}
	return append(append([]string(nil), list...), src)
}

// RemovedSet returns the properties that mark src as having dropped an item.
func RemovedSet(src string, removed bool) (map[string]any, error) {
	k, err := RemovedKey(src)
	if err != nil {
		return nil, err
	}
	return map[string]any{k: removed}, nil
}
