package lockfile

import (
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/kato83/mayu/internal/sbom"
	"gopkg.in/yaml.v3"
)

// PnpmLockParser parses pnpm pnpm-lock.yaml files.
type PnpmLockParser struct{}

// pnpmLockfile represents the structure of a pnpm-lock.yaml file.
type pnpmLockfile struct {
	LockfileVersion string                   `yaml:"lockfileVersion"`
	Packages        map[string]pnpmPackageV6 `yaml:"packages"`
	Snapshots       map[string]interface{}   `yaml:"snapshots"`
}

type pnpmPackageV6 struct {
	Resolution interface{} `yaml:"resolution"`
	Dev        bool        `yaml:"dev"`
}

// Parse reads a pnpm-lock.yaml file and returns the extracted components.
func (p *PnpmLockParser) Parse(filename string, reader io.Reader) ([]sbom.Component, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read pnpm-lock.yaml: %w", err)
	}

	var lockfile pnpmLockfile
	if err := yaml.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parse pnpm-lock.yaml: %w", err)
	}

	seen := make(map[string]bool)
	var components []sbom.Component

	for path := range lockfile.Packages {
		name, ver := parsePnpmPackagePath(path)
		if name == "" || ver == "" {
			continue
		}

		key := name + "@" + ver
		if seen[key] {
			continue
		}
		seen[key] = true

		namespace, pkgName := splitNPMName(name)
		comp := resolveComponent("npm", namespace, url.PathEscape(pkgName), ver, "npm")
		comp.Name = name
		comp.IsDev = lockfile.Packages[path].Dev
		components = append(components, comp)
	}

	return components, nil
}

// parsePnpmPackagePath extracts name and version from a pnpm package path.
// Format examples (v6+):
//
//	"/lodash@4.17.21"              → name="lodash", version="4.17.21"
//	"/@angular/core@17.0.0"       → name="@angular/core", version="17.0.0"
//	"lodash@4.17.21"              → name="lodash", version="4.17.21"
//	"@angular/core@17.0.0"        → name="@angular/core", version="17.0.0"
//
// v9 format:
//
//	"lodash@4.17.21"              → name="lodash", version="4.17.21"
//	"@angular/core@17.0.0"        → name="@angular/core", version="17.0.0"
func parsePnpmPackagePath(path string) (name, version string) {
	// Strip leading "/" if present (v6 format)
	path = strings.TrimPrefix(path, "/")

	if path == "" {
		return "", ""
	}

	// For scoped packages (@scope/name@version)
	if strings.HasPrefix(path, "@") {
		slashIdx := strings.Index(path, "/")
		if slashIdx < 0 {
			return "", ""
		}
		// Find the "@" after the package name (the version separator)
		rest := path[slashIdx+1:]
		atIdx := strings.LastIndex(rest, "@")
		if atIdx < 0 {
			return "", ""
		}
		name = path[:slashIdx+1+atIdx]
		version = rest[atIdx+1:]
		// Strip any parenthesized peer info from version
		if paren := strings.Index(version, "("); paren >= 0 {
			version = version[:paren]
		}
		return name, version
	}

	// Unscoped packages (name@version)
	atIdx := strings.LastIndex(path, "@")
	if atIdx <= 0 {
		return "", ""
	}
	name = path[:atIdx]
	version = path[atIdx+1:]
	// Strip any parenthesized peer info from version
	if paren := strings.Index(version, "("); paren >= 0 {
		version = version[:paren]
	}
	return name, version
}
