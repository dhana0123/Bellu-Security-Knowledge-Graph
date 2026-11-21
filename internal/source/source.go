// Package source defines the Source_Adapter interface and the record types
// that adapters and the pipeline exchange (Requirement 3). Adapters live in
// one sub-package each.
package source

import (
	"context"
	"regexp"
	"time"
)

// Adapter is one data source. Registering an adapter is one line in
// cmd/bskg and one row in docs/sources.md.
type Adapter interface {
	// Name is unique and matches ^[a-z][a-z0-9]{0,15}$.
	Name() string
	// Fetch returns the records changed since cp; all records if cp is empty.
	Fetch(ctx context.Context, cp Checkpoint, opts RunOptions) (Iterator, error)
	// Normalize maps one record to entities and relationships. It is pure.
	Normalize(rec Record) (Normalized, error)
}

// Totaler is optionally implemented by an adapter that can report the
// upstream database's own counts, so the graph can be compared with it. The
// pipeline calls Totals once after a run ended succeeded or
// succeeded_with_errors. Keys match ^[a-zA-Z][a-zA-Z0-9]*$ and are stored as
// Checkpoint properties upstream_<key>.
type Totaler interface {
	Totals(ctx context.Context) (map[string]int64, error)
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)

// ValidName reports whether name may be used as an adapter name.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// RunOptions carries per-run settings. SampleLimit is used only by the NVD
// adapter; CWE and Exploit-DB ignore it (Requirements 12.5, 12.6).
type RunOptions struct {
	// SampleLimit is 0 for a full build and N >= 1 for a Sample_Build.
	SampleLimit int
	// SampleOrder is "first" (default) or "latest". With "latest" the NVD
	// adapter reads the most recent SampleLimit records. Used only when
	// SampleLimit > 0.
	SampleOrder string
}

// Sample orders of RunOptions.SampleOrder.
const (
	SampleFirst  = "first"
	SampleLatest = "latest"
)

// Checkpoint is the stored position of a source. The zero value means never
// synced.
type Checkpoint struct {
	Watermark time.Time
	Resume    string
	Version   string
}

// IsZero reports whether the source was never synced.
func (c Checkpoint) IsZero() bool {
	return c.Watermark.IsZero() && c.Resume == "" && c.Version == ""
}

// Cursor is the state after a record is committed. Version is a source
// snapshot version: the CWE catalog version or the Exploit-DB CSV SHA-256.
type Cursor struct {
	Resume    string
	Watermark time.Time
	Version   string
}

// Iterator yields records. Next returns io.EOF at the end.
type Iterator interface {
	Next(ctx context.Context) (Record, error)
}

// Record is one raw source record.
type Record struct {
	ID string // source record id, for example the CVE id or the Exploit-DB id
	// Payload is the raw record. An empty Payload marks a cursor update only.
	Payload []byte
	// Cursor is the state AFTER this record is committed.
	Cursor Cursor
}

// RefKind names how a Ref is resolved to a node key.
type RefKind string

// Reference kinds of Phase 1.
const (
	RefCVE     RefKind = "cve"
	RefCWE     RefKind = "cwe"
	RefCPE     RefKind = "cpe"       // a CPE 2.3 name; resolves to the Product
	RefCPEVend RefKind = "cpevendor" // a CPE 2.3 name; resolves to the Vendor
	RefVendor  RefKind = "vendor"
	RefDomain  RefKind = "domain"
	RefExploit RefKind = "exploit"
	RefAuthor  RefKind = "author"
	// RefRepository is a git repository URL; resolves to the Repository.
	RefRepository RefKind = "repository"
	// RefFixCommit is "<repo URL>@<40 hex sha>"; resolves to the FixCommit.
	RefFixCommit RefKind = "fixcommit"
)

// Ref points at a node by its raw source form. The resolver turns it into a
// canonical key. MustExist means the node is never created: when it is
// absent, the relationship is dropped and counted as unresolved.
type Ref struct {
	Kind      RefKind
	Raw       string
	MustExist bool
}

// Entity is a node to create or update. Properties absent from Props stay
// unchanged; Clear removes properties.
type Entity struct {
	Ref   Ref
	Props map[string]any
	Clear []string
}

// Rel is a relationship to create or update. Key holds the identity
// properties (for example viewID) that distinguish relationships between the
// same pair of nodes.
type Rel struct {
	From, To Ref
	Type     string
	Key      map[string]any
	Props    map[string]any
}

// OwnedRel names a relationship type an anchor owns for removal handling.
type OwnedRel struct {
	Type string
}

// Note is a warning or unresolved reference for the Sync_Run report.
type Note struct {
	Kind string // "warning" or "unresolved"
	ID   string
	Text string
}

// Normalized is the result of normalizing one record.
type Normalized struct {
	Entities []Entity
	Rels     []Rel
	// Gate: the record is processed only if at least one Ref exists in the
	// graph; otherwise it is skipped and counted.
	Gate []Ref
	// Anchor is the entity whose owned relationships are compared for removal.
	Anchor *Ref
	Owned  []OwnedRel
	// Missing is set when the record lacked a mappable field.
	Missing bool
	Notes   []Note
}
