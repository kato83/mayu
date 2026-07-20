//go:build uiembed

// Package uiassets provides access to the embedded Web UI static files.
// When built with the "uiembed" tag, the dist/ directory is embedded into the binary.
// The dist/ directory must be populated before building (see Makefile: build-embed).
package uiassets

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var assets embed.FS

// FS returns the embedded UI filesystem rooted at the dist/ directory.
func FS() fs.FS {
	sub, err := fs.Sub(assets, "dist")
	if err != nil {
		panic("uiassets: " + err.Error())
	}
	return sub
}
