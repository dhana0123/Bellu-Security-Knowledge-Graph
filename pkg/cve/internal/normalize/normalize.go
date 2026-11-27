// Package normalize canonicalizes and validates parsed records. A bad record yields
// Rejections and is dropped alone; a malformed payload yields ErrFormat and no records.
package normalize

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/ecosystem"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// ErrFormat marks a payload that cannot be parsed at all.
var ErrFormat = errors.New("normalize: malformed payload")

// Format wraps err (may be nil) as an ErrFormat.
func Format(source string, err error) error {
	if err == nil {
		return fmt.Errorf("%s: %w", source, ErrFormat)
	}
	return fmt.Errorf("%s: %w: %v", source, ErrFormat, err)
}

// Rejection describes why one record (or one field of it) was rejected.
type Rejection struct{ RecordID, Field, Rule string }

func (r Rejection) Error() string {
	return fmt.Sprintf("record %q rejected: field %s: %s", r.RecordID, r.Field, r.Rule)
}

var cveRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// CanonicalCVE trims and upper-cases s and checks it is a CVE id.
func CanonicalCVE(s string) (string, error) {
	c := strings.ToUpper(strings.TrimSpace(s))
	if !cveRe.MatchString(c) {
		return "", Rejection{RecordID: s, Field: "cve", Rule: "must match CVE-YYYY-NNNN+"}
	}
	return c, nil
}

// CanonicalEcosystem maps to the fixed vocabulary; unmapped names are kept and flagged.
func CanonicalEcosystem(s string) (name string, mapped bool) { return ecosystem.Canonical(s) }

// CanonicalPackage applies the per-ecosystem package name rules.
func CanonicalPackage(eco, name string) string { return ecosystem.Package(eco, name) }

// Apply canonicalizes rec in place (ids, ecosystems, package names, timestamps) and
// returns the validation rejections; rec must be dropped when any are returned.
func Apply(rec *model.Record) []Rejection {
	rec.ID = model.NormID(rec.ID)
	for i, a := range rec.Aliases {
		rec.Aliases[i] = model.NormID(a)
	}
	for i := range rec.Affected {
		a := &rec.Affected[i]
		if a.Kind != "package" {
			continue
		}
		eco, mapped := CanonicalEcosystem(a.Ecosystem)
		a.Ecosystem, a.Unmapped = eco, !mapped
		a.Name = CanonicalPackage(eco, a.Name)
	}
	rec.Normalize()
	return Validate(rec)
}

// Validate checks required identifiers and fields.
func Validate(rec *model.Record) []Rejection {
	var out []Rejection
	rej := func(field, rule string) { out = append(out, Rejection{rec.ID, field, rule}) }
	if strings.TrimSpace(rec.ID) == "" {
		rej("id", "required")
	} else if strings.EqualFold(rec.Source, "nvd") && !cveRe.MatchString(rec.ID) {
		rej("id", "must match CVE-YYYY-NNNN+")
	}
	if strings.TrimSpace(rec.Source) == "" {
		rej("source", "required")
	}
	for i, a := range rec.Aliases {
		if strings.TrimSpace(a) == "" {
			rej(fmt.Sprintf("aliases[%d]", i), "must not be empty")
		}
	}
	for i, a := range rec.Affected {
		if strings.TrimSpace(a.Name) == "" {
			rej(fmt.Sprintf("affected[%d].name", i), "required")
		}
		if a.Kind == "package" && strings.TrimSpace(a.Ecosystem) == "" {
			rej(fmt.Sprintf("affected[%d].ecosystem", i), "required")
		}
	}
	for i, r := range rec.References {
		if strings.TrimSpace(r.URL) == "" {
			rej(fmt.Sprintf("references[%d].url", i), "required")
		}
	}
	return out
}

// ValidateCVE returns a rejection when id is not a canonical CVE id.
func ValidateCVE(field, id string) *Rejection {
	if !cveRe.MatchString(id) {
		return &Rejection{RecordID: id, Field: field, Rule: "must match CVE-YYYY-NNNN+"}
	}
	return nil
}

// WithdrawnAt returns the source withdrawal time, or retrieved when the source marks the
// record withdrawn without a usable time.
func WithdrawnAt(sourceTime, retrieved time.Time) time.Time {
	if !sourceTime.IsZero() {
		return sourceTime
	}
	return retrieved
}
