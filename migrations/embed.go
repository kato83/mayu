// Package migrations embeds the SQL migration files for use at runtime.
package migrations

import "embed"

// FS contains all SQL migration files embedded at build time.
//
//go:embed *.sql
var FS embed.FS
