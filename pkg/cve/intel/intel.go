// Package intel is the read-only Go SDK over a Bellu graph.db snapshot.
//
// This file holds the engine-independent interface, result types and errors.
// The SQLite implementation lives in sqlite.go. The package must not import
// net/http.
package intel

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// MaxSchemaVersion is the highest meta.schema_version this SDK can read.
const MaxSchemaVersion = 1

// Sentinel errors.
var (
	ErrNotFound           = errors.New("not found")
	ErrNotImplemented     = errors.New("not implemented")
	ErrHistoryUnavailable = errors.New("history unavailable")
	ErrInvalidAsOf        = errors.New("invalid as-of")
	ErrInvalidRequest     = errors.New("invalid request")
	ErrSourceUnavailable  = errors.New("data source unavailable")
	ErrNotInstalled       = errors.New("no installed graph snapshot")
)

// SchemaVersionError reports a graph.db whose schema is newer than supported.
type SchemaVersionError struct {
	File      int // schema version found in the file
	Supported int // highest version this SDK supports
}

func (e *SchemaVersionError) Error() string {
	return fmt.Sprintf("intel: graph.db schema version %d is newer than supported version %d", e.File, e.Supported)
}

// Option configures a query.
type Option func(*queryOptions)

type queryOptions struct {
	asOf    time.Time
	hasAsOf bool
}

// WithAsOf asks for the state of the graph at time t (requires history).
func WithAsOf(t time.Time) Option {
	return func(o *queryOptions) { o.asOf, o.hasAsOf = t, true }
}

func applyOptions(opts []Option) queryOptions {
	var o queryOptions
	for _, f := range opts {
		if f != nil {
			f(&o)
		}
	}
	return o
}

// Client queries a graph snapshot. Implementations are safe for concurrent use.
type Client interface {
	GetVulnerability(ctx context.Context, id string, opts ...Option) (*Vulnerability, error)
	GetPackageVulnerabilities(ctx context.Context, ecosystem, name, version string, opts ...Option) ([]PackageMatch, error)
	GetAffectedProducts(ctx context.Context, cveID string, opts ...Option) ([]AffectedProduct, error)
	GetPatches(ctx context.Context, cveID string, opts ...Option) ([]Patch, error)
	GetExploits(ctx context.Context, cveID string, opts ...Option) ([]Exploit, error)
	// SearchPackage and SearchProduct list vulnerabilities affecting a package or
	// product (no version filter), ordered by vulnerability id, keyset-paged.
	SearchPackage(ctx context.Context, ecosystem, name string, p PageReq) ([]VulnRef, error)
	SearchProduct(ctx context.Context, vendor, product string, p PageReq) ([]VulnRef, error)
	// GetAttackPaths always returns (nil, ErrNotImplemented) in D1.
	GetAttackPaths(ctx context.Context, cveID string) ([]AttackPath, error)
	AnalyzeDependencies(ctx context.Context, deps []Dependency) ([]DependencyResult, error)
	Close() error
}

// MatchState is the outcome of matching a version against an affected entry.
type MatchState string

const (
	MatchAffected MatchState = "affected"
	MatchUnknown  MatchState = "unknown"
)

// MatchLevel is the confidence level of a match; "affected-package" is the only D1 value.
type MatchLevel string

const LevelAffectedPackage MatchLevel = "affected-package"

// SeverityAssessment is one severity score from one source.
type SeverityAssessment struct {
	ID         string
	Source     string
	RecordID   string
	Type       string
	Version    string
	Score      float64
	Vector     string
	Rating     string
	Validation string
	Reason     string
}

// KEVEntry is a CISA Known Exploited Vulnerabilities listing.
type KEVEntry struct {
	CVE        string
	DateAdded  string
	DueDate    string
	Ransomware string
}

// EPSSAssessment is the current EPSS score.
type EPSSAssessment struct {
	CVE        string
	Score      float64
	Percentile float64
	Date       string
}

// SourceRecordRef points at a source record backing a vulnerability.
type SourceRecordRef struct {
	ID         string // graph node id, "src:<source>:<id>"
	Source     string
	ExternalID string
	Modified   string // RFC 3339, empty when unknown
	Withdrawn  string // RFC 3339, empty when not withdrawn
}

// Discrepancy is set when active sources disagree on severity.
type Discrepancy struct {
	Present bool
}

// Vulnerability is the merged view of one vulnerability.
type Vulnerability struct {
	ID          string
	Summary     string
	Published   string // RFC 3339, empty when unknown
	Modified    string
	Withdrawn   string
	Aliases     []string             // never nil
	Severities  []SeverityAssessment // never nil, may be empty
	Weaknesses  []string             // never nil
	KEV         *KEVEntry            // nil when none
	EPSS        *EPSSAssessment      // nil when none
	Sources     []SourceRecordRef    // never nil
	TrustState  string
	Discrepancy *Discrepancy // nil when sources agree
}

// VulnerabilitySummary is the short form used in match results.
type VulnerabilitySummary struct {
	ID         string
	Summary    string
	TrustState string
}

// AffectedRange is the matching entry of an AFFECTS edge.
type AffectedRange struct {
	Source     string
	Scheme     string
	Introduced string
	Fixed      string
	Versions   []string // never nil
}

// PackageMatch is one vulnerability affecting a package version.
type PackageMatch struct {
	Vulnerability VulnerabilitySummary
	State         MatchState
	Level         MatchLevel
	Range         *AffectedRange // nil for unknown
	FixedVersion  string
	TrustState    string
}

// AffectedProduct is a package or product affected by a vulnerability.
type AffectedProduct struct {
	ID         string // graph node id
	Kind       string // "package" or "product"
	Ecosystem  string
	Vendor     string
	Name       string
	Introduced string
	Fixed      string
	Status     string
}

// Patch is a fix reference for a vulnerability.
type Patch struct {
	ID           string
	URL          string
	Source       string
	FixedVersion string
}

// AttackPath is reserved; D1 never returns values.
type AttackPath struct {
	Steps []string
}

// Dependency is one input of AnalyzeDependencies.
type Dependency struct {
	Ecosystem string
	Name      string
	Version   string
}

// DependencyResult is the outcome for one dependency, in input order.
type DependencyResult struct {
	Dependency      Dependency
	Vulnerabilities []PackageMatch // never nil
}
