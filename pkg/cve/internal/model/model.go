// Package model defines Bellu's normalized, source-agnostic record types.
package model

import (
	"regexp"
	"strings"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/ecosystem"
)

type Severity struct {
	Source     string   `json:"source"`
	Type       string   `json:"type"` // CVSS_V2, CVSS_V3, CVSS_V4
	Version    string   `json:"version,omitempty"`
	Vector     string   `json:"vector,omitempty"`
	Score      *float64 `json:"score,omitempty"`
	Validation string   `json:"validation,omitempty"`
	Reason     string   `json:"reason,omitempty"`
}

type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type Range struct {
	Type   string  `json:"type"` // SEMVER, ECOSYSTEM, GIT
	Repo   string  `json:"repo,omitempty"`
	Events []Event `json:"events"`
}

// Bound is an NVD-style version interval. An all-empty Bound matches every version.
type Bound struct {
	StartIncl string `json:"start_incl,omitempty"`
	StartExcl string `json:"start_excl,omitempty"`
	EndIncl   string `json:"end_incl,omitempty"`
	EndExcl   string `json:"end_excl,omitempty"`
}

type Affected struct {
	Kind      string   `json:"kind"` // package | product
	Ecosystem string   `json:"ecosystem,omitempty"`
	Name      string   `json:"name"`
	Vendor    string   `json:"vendor,omitempty"`
	Purl      string   `json:"purl,omitempty"`
	Ranges    []Range  `json:"ranges,omitempty"`
	Bounds    []Bound  `json:"bounds,omitempty"`
	Versions  []string `json:"versions,omitempty"`
	Unmapped  bool     `json:"unmapped,omitempty"` // ecosystem outside the fixed vocabulary
}

type Reference struct {
	Type string `json:"type"` // FIX, EXPLOIT, ADVISORY, WEB, ...
	URL  string `json:"url"`
}

type Fix struct {
	Repo   string `json:"repo"`
	Commit string `json:"commit"`
}

type Record struct {
	Source     string      `json:"source"`
	ID         string      `json:"id"`
	Aliases    []string    `json:"aliases,omitempty"`
	Summary    string      `json:"summary,omitempty"`
	Details    string      `json:"details,omitempty"`
	Published  time.Time   `json:"published"`
	Modified   time.Time   `json:"modified"`
	Withdrawn  time.Time   `json:"withdrawn"`
	Weaknesses []string    `json:"weaknesses,omitempty"`
	Severities []Severity  `json:"severities,omitempty"`
	Affected   []Affected  `json:"affected,omitempty"`
	References []Reference `json:"references,omitempty"`
	Fixes      []Fix       `json:"fixes,omitempty"`
}

type KEV struct {
	CVE        string `json:"cve"`
	Vendor     string `json:"vendor_project,omitempty"`
	Product    string `json:"product,omitempty"`
	Name       string `json:"name,omitempty"`
	DateAdded  string `json:"date_added,omitempty"`
	DueDate    string `json:"due_date,omitempty"`
	Action     string `json:"required_action,omitempty"`
	Ransomware string `json:"ransomware,omitempty"`
}

type EPSS struct {
	CVE        string  `json:"cve"`
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

var timeLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05", "2006-01-02"}

// ParseTime parses the timestamp formats used by the supported sources; zero on failure.
func ParseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, l := range timeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

var cveRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func IsCVE(id string) bool { return cveRe.MatchString(id) }

// NormID upper-cases and trims an advisory identifier.
func NormID(id string) string { return strings.ToUpper(strings.TrimSpace(id)) }

// PackageID is the canonical graph ID for a package.
func PackageID(eco, name string) string {
	return "pkg:" + strings.ToLower(strings.TrimSpace(eco)) + "/" + ecosystem.Package(eco, name)
}

// ProductID is the canonical graph ID for a CPE vendor/product pair.
func ProductID(vendor, product string) string {
	return "cpe:" + strings.ToLower(vendor) + ":" + strings.ToLower(product)
}
