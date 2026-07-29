package lockfile

import (
	"bufio"
	"io"
	"strings"

	"github.com/kato83/mayu/internal/sbom"
)

// GoSumParser parses Go go.sum files.
type GoSumParser struct{}

// Parse reads a go.sum file and returns the extracted components.
// go.sum format: <module> <version>[/go.mod] <hash>
// Each module may appear twice (once for go.mod, once for the module zip).
// We deduplicate by module+version.
func (p *GoSumParser) Parse(filename string, reader io.Reader) ([]sbom.Component, error) {
	seen := make(map[string]bool)
	var components []sbom.Component

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		module := parts[0]
		ver := parts[1]

		// Strip /go.mod suffix from version if present
		ver = strings.TrimSuffix(ver, "/go.mod")

		// Strip "v" prefix from version (Go modules use v-prefixed semver)
		cleanVer := strings.TrimPrefix(ver, "v")

		// Deduplicate
		key := module + "@" + cleanVer
		if seen[key] {
			continue
		}
		seen[key] = true

		// Split module path into namespace and name for purl
		// For Go, the full module path is the package name
		// purl format: pkg:golang/<module>@<version>
		namespace, name := splitGoModule(module)

		components = append(components, resolveComponent("golang", namespace, name, cleanVer, "Go"))
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return components, nil
}

// splitGoModule splits a Go module path into namespace and name for purl construction.
// For example: "golang.org/x/crypto" → namespace="golang.org/x", name="crypto"
// For "github.com/foo/bar/baz" → namespace="github.com/foo/bar", name="baz"
func splitGoModule(module string) (namespace, name string) {
	idx := strings.LastIndex(module, "/")
	if idx < 0 {
		return "", module
	}
	return module[:idx], module[idx+1:]
}
