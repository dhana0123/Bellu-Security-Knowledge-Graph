// Package pack builds and verifies Bellu snapshot packages.
package pack

import (
	"fmt"
	"regexp"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/graph"
)

// Product is the manifest product name.
const Product = "Bellu Global Intelligence"

// MaxEcosystems is the upper bound of the manifest ecosystems list.
const MaxEcosystems = 100

// Package entry names.
const (
	FileManifest   = "manifest.json"
	FileGraphDB    = "graph.db"
	FileChecksums  = "checksums.sha256"
	FileSources    = "metadata/sources.json"
	FileSchemaVer  = "metadata/schema-version.json"
	FileStatistics = "metadata/statistics.json"
)

// SnapshotFiles lists the exact entries of a snapshot package, sorted.
var SnapshotFiles = []string{FileChecksums, FileGraphDB, FileManifest, FileSchemaVer, FileSources, FileStatistics}

// RecordCounts holds per node type and per edge type counts.
type RecordCounts struct {
	Nodes map[string]int64 `json:"nodes"`
	Edges map[string]int64 `json:"edges"`
}

// Manifest is the content of manifest.json.
type Manifest struct {
	Product           string       `json:"product"`
	SnapshotID        string       `json:"snapshot_id"`
	SchemaVersion     string       `json:"schema_version"`
	DatabaseEngine    string       `json:"database_engine"`
	EngineVersion     string       `json:"engine_version"`
	CreatedAt         time.Time    `json:"created_at"`
	DistributionLevel graph.Level  `json:"distribution_level"`
	Ecosystems        []string     `json:"ecosystems"`
	RecordCounts      RecordCounts `json:"record_counts"`
	LogicalDigest     string       `json:"logical_digest"`
}

var (
	snapshotIDRe = regexp.MustCompile(`^\d{8}T\d{6}Z-[0-9a-f]{8}$`)
	digestRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// SnapshotIDFor builds the snapshot id from the creation time and logical digest.
func SnapshotIDFor(created time.Time, digest string) string {
	return created.UTC().Format("20060102T150405Z") + "-" + digest[:8]
}

// Validate checks the manifest fields.
func (m Manifest) Validate() error {
	switch m.DistributionLevel {
	case graph.LevelCore, graph.LevelEcosystem, graph.LevelComplete:
	default:
		return fmt.Errorf("manifest: unsupported distribution_level %q", string(m.DistributionLevel))
	}
	if m.Product != Product {
		return fmt.Errorf("manifest: product %q, want %q", m.Product, Product)
	}
	if !snapshotIDRe.MatchString(m.SnapshotID) {
		return fmt.Errorf("manifest: malformed snapshot_id %q", m.SnapshotID)
	}
	if !digestRe.MatchString(m.LogicalDigest) {
		return fmt.Errorf("manifest: malformed logical_digest %q", m.LogicalDigest)
	}
	if m.SchemaVersion == "" || m.DatabaseEngine == "" || m.EngineVersion == "" {
		return fmt.Errorf("manifest: schema_version, database_engine and engine_version are required")
	}
	if m.CreatedAt.IsZero() || m.CreatedAt.Location() != time.UTC {
		return fmt.Errorf("manifest: created_at must be a UTC time")
	}
	if want := SnapshotIDFor(m.CreatedAt, m.LogicalDigest); want != m.SnapshotID {
		return fmt.Errorf("manifest: snapshot_id %q does not match created_at and logical_digest (%q)", m.SnapshotID, want)
	}
	if len(m.Ecosystems) > MaxEcosystems {
		return fmt.Errorf("manifest: %d ecosystems exceeds %d", len(m.Ecosystems), MaxEcosystems)
	}
	if m.RecordCounts.Nodes == nil || m.RecordCounts.Edges == nil {
		return fmt.Errorf("manifest: record_counts.nodes and record_counts.edges are required")
	}
	for _, c := range []map[string]int64{m.RecordCounts.Nodes, m.RecordCounts.Edges} {
		for k, v := range c {
			if v < 0 {
				return fmt.Errorf("manifest: negative record count for %q", k)
			}
		}
	}
	return nil
}
