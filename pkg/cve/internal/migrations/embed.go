// Package migrations embeds the versioned SQL migrations applied by canonical.Store.Migrate.
package migrations

import "embed"

// FS holds the *.sql migration files at its root.
//
//go:embed *.sql
var FS embed.FS
