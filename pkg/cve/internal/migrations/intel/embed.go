// Package intelmigrations embeds the versioned SQL migrations of intel.db, the
// separate database of the CVE graph intelligence worker. They are applied by
// internal/intel/store with the same runner as the canonical migrations.
package intelmigrations

import "embed"

// FS holds the *.sql migration files at its root.
//
//go:embed *.sql
var FS embed.FS
