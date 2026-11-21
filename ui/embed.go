// Package ui embeds the built Client_UI (ui/dist) into the bskg binary.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Files is the embedded Client_UI rooted at dist/ (index.html at its top).
var Files fs.FS = mustSub()

func mustSub() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
