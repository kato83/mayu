//go:build !uiembed

// Package uiassets provides access to the embedded Web UI static files.
// When built without the "uiembed" tag, no UI assets are embedded.
package uiassets

import "io/fs"

// FS returns nil when built without the uiembed tag.
// The caller should fall back to --ui-dir or skip UI serving.
func FS() fs.FS {
	return nil
}
