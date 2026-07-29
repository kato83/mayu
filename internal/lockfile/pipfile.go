package lockfile

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kato83/mayu/internal/sbom"
)

// PipfileLockParser parses Python Pipfile.lock files.
type PipfileLockParser struct{}

// pipfileLock represents the structure of a Pipfile.lock file.
type pipfileLock struct {
	Default map[string]pipfilePackage `json:"default"`
	Develop map[string]pipfilePackage `json:"develop"`
}

type pipfilePackage struct {
	Version string `json:"version"`
}

// Parse reads a Pipfile.lock file and returns the extracted components.
func (p *PipfileLockParser) Parse(filename string, reader io.Reader) ([]sbom.Component, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read Pipfile.lock: %w", err)
	}

	var lockfile pipfileLock
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parse Pipfile.lock: %w", err)
	}

	var components []sbom.Component

	for name, pkg := range lockfile.Default {
		ver := normalizePipVersion(pkg.Version)
		if ver == "" {
			continue
		}
		comp := resolveComponent("pypi", "", normalizePyPIName(name), ver, "PyPI")
		comp.Name = name
		components = append(components, comp)
	}

	for name, pkg := range lockfile.Develop {
		ver := normalizePipVersion(pkg.Version)
		if ver == "" {
			continue
		}
		comp := resolveComponent("pypi", "", normalizePyPIName(name), ver, "PyPI")
		comp.Name = name
		comp.IsDev = true
		components = append(components, comp)
	}

	return components, nil
}

// normalizePipVersion strips the "==" prefix from pip version specifiers.
func normalizePipVersion(version string) string {
	return strings.TrimPrefix(version, "==")
}

// normalizePyPIName normalizes a Python package name for purl.
// PyPI names are case-insensitive and use underscores/hyphens interchangeably.
// Purl convention: lowercase with hyphens.
func normalizePyPIName(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}
