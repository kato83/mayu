// Package reachability provides vulnerability reachability analysis for Go projects.
// It determines whether vulnerable symbols (functions/methods) are actually referenced
// from the project's source code, enabling more precise vulnerability prioritization.
package reachability

import "context"

// Result represents the reachability analysis result for a vulnerability finding.
type Result struct {
	// VulnID is the vulnerability identifier (e.g., "GO-2024-2687").
	VulnID string

	// Package is the Go import path of the vulnerable package.
	Package string

	// Reachable is true if any vulnerable symbol is referenced from the project.
	Reachable bool

	// Evidence lists the specific vulnerable symbols found in the project source.
	Evidence []Evidence
}

// Evidence records where a vulnerable symbol is referenced in the project source.
type Evidence struct {
	// Symbol is the qualified symbol name (e.g., "net/http.Get", "net/http.Client.Do").
	Symbol string

	// File is the file path (relative to project root) where the reference was found.
	File string

	// Line is the 1-based line number of the reference.
	Line int
}

// VulnSymbol represents a vulnerable symbol to check for reachability.
type VulnSymbol struct {
	// VulnID is the vulnerability identifier.
	VulnID string

	// Package is the Go import path (e.g., "net/http", "golang.org/x/crypto/ssh").
	Package string

	// Symbol is the unqualified symbol name (e.g., "Get", "Client.Do").
	Symbol string
}

// Analyzer performs reachability analysis on a Go project.
type Analyzer interface {
	// Analyze checks whether the given vulnerable symbols are referenced
	// from Go source files in projectDir.
	Analyze(ctx context.Context, projectDir string, symbols []VulnSymbol) ([]Result, error)
}
