// Package install is the public face of the snapshot installer. It re-exports
// internal/install so that other Go modules (for example bellucode) install
// signed packs with the same verification, delta apply and atomic `current`
// symlink swap as the Global CVE CLI.
//
// Data directory layout: snapshots/<id>/{graph.db,manifest.json}, a relative
// `current` symlink, and state.json.
package install

import internal "github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/install"

type (
	// Installer installs snapshots into DataDir. Set PreSwap to run extra
	// checks on a built snapshot before it can become current.
	Installer = internal.Installer
	// State is the content of state.json.
	State = internal.State
	// AppliedDelta records one applied delta package.
	AppliedDelta = internal.AppliedDelta
	// ApplyOptions configures Apply.
	ApplyOptions = internal.ApplyOptions
	// BaseMismatchError reports a delta whose base is not the installed snapshot.
	BaseMismatchError = internal.BaseMismatchError
	// ChecksumError reports a delta file whose checksum does not match.
	ChecksumError = internal.ChecksumError
)

var (
	ErrNotInstalled      = internal.ErrNotInstalled
	ErrUnsupportedSchema = internal.ErrUnsupportedSchema
	ErrBaseMismatch      = internal.ErrBaseMismatch
)
