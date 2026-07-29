package lockfile

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kato83/mayu/internal/sbom"
)

// ComposerLockParser parses PHP composer.lock files.
type ComposerLockParser struct{}

// composerLock represents the structure of a composer.lock file.
type composerLock struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Parse reads a composer.lock file and returns the extracted components.
func (p *ComposerLockParser) Parse(filename string, reader io.Reader) ([]sbom.Component, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read composer.lock: %w", err)
	}

	var lockfile composerLock
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %w", err)
	}

	var components []sbom.Component

	for _, pkg := range lockfile.Packages {
		comp := buildComposerComponent(pkg, false)
		if comp != nil {
			components = append(components, *comp)
		}
	}

	for _, pkg := range lockfile.PackagesDev {
		comp := buildComposerComponent(pkg, true)
		if comp != nil {
			components = append(components, *comp)
		}
	}

	return components, nil
}

func buildComposerComponent(pkg composerPackage, isDev bool) *sbom.Component {
	if pkg.Name == "" || pkg.Version == "" {
		return nil
	}

	// Strip "v" prefix from version
	version := strings.TrimPrefix(pkg.Version, "v")

	// Composer packages use "vendor/package" format
	parts := strings.SplitN(pkg.Name, "/", 2)
	var namespace, name string
	if len(parts) == 2 {
		namespace = parts[0]
		name = parts[1]
	} else {
		name = pkg.Name
	}

	comp := resolveComponent("composer", namespace, name, version, "Packagist")
	comp.Name = pkg.Name
	comp.IsDev = isDev
	return &comp
}
