package lockfile

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/kato83/mayu/internal/sbom"
)

// NPMLockParser parses npm package-lock.json files (v2/v3 format).
type NPMLockParser struct{}

// npmLockfile represents the structure of a package-lock.json file.
type npmLockfile struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]npmPackage  `json:"packages"`
	Dependencies    map[string]npmDepEntry `json:"dependencies"`
}

type npmPackage struct {
	Version  string `json:"version"`
	Resolved string `json:"resolved"`
	Dev      bool   `json:"dev"`
}

type npmDepEntry struct {
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
}

// Parse reads a package-lock.json file and returns the extracted components.
func (p *NPMLockParser) Parse(filename string, reader io.Reader) ([]sbom.Component, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read package-lock.json: %w", err)
	}

	var lockfile npmLockfile
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}

	// v2/v3 format uses "packages" field
	if len(lockfile.Packages) > 0 {
		return parseNPMPackages(lockfile.Packages), nil
	}

	// v1 format uses "dependencies" field
	if len(lockfile.Dependencies) > 0 {
		return parseNPMDependencies(lockfile.Dependencies), nil
	}

	return nil, nil
}

func parseNPMPackages(packages map[string]npmPackage) []sbom.Component {
	var components []sbom.Component

	for path, pkg := range packages {
		// Skip the root package (empty key)
		if path == "" {
			continue
		}

		// Extract package name from the path (e.g., "node_modules/@scope/name")
		name := extractNPMPackageName(path)
		if name == "" || pkg.Version == "" {
			continue
		}

		namespace, pkgName := splitNPMName(name)
		comp := resolveComponent("npm", namespace, url.PathEscape(pkgName), pkg.Version, "npm")
		// Override Name with the unescaped full name
		comp.Name = name
		comp.IsDev = pkg.Dev
		components = append(components, comp)
	}

	return components
}

func parseNPMDependencies(deps map[string]npmDepEntry) []sbom.Component {
	var components []sbom.Component

	for name, dep := range deps {
		if dep.Version == "" {
			continue
		}

		namespace, pkgName := splitNPMName(name)
		comp := resolveComponent("npm", namespace, url.PathEscape(pkgName), dep.Version, "npm")
		comp.Name = name
		comp.IsDev = dep.Dev
		components = append(components, comp)
	}

	return components
}

// extractNPMPackageName extracts the npm package name from a node_modules path.
// Examples:
//
//	"node_modules/lodash" → "lodash"
//	"node_modules/@angular/core" → "@angular/core"
//	"node_modules/a/node_modules/b" → "b"
func extractNPMPackageName(path string) string {
	// Find the last "node_modules/" prefix
	const prefix = "node_modules/"
	idx := strings.LastIndex(path, prefix)
	if idx < 0 {
		return path
	}
	return path[idx+len(prefix):]
}

// splitNPMName splits an npm package name into namespace and name.
// Scoped packages like "@angular/core" → namespace="@angular", name="core"
// Unscoped packages like "lodash" → namespace="", name="lodash"
func splitNPMName(name string) (namespace, pkg string) {
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			return url.PathEscape(parts[0]), parts[1]
		}
	}
	return "", name
}
