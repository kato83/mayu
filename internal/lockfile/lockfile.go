// Package lockfile provides parsers for various lockfile formats used by
// package managers. Each parser extracts package information and converts
// it to sbom.Component structs with proper purl identifiers for vulnerability
// matching.
package lockfile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kato83/mayu/internal/sbom"
)

// Parser is the interface that lockfile parsers implement.
type Parser interface {
	// Parse reads a lockfile and returns the extracted components.
	// The filename parameter is used for disambiguation when the format
	// requires it (e.g., distinguishing Yarn classic vs Berry).
	Parse(filename string, reader io.Reader) ([]sbom.Component, error)
}

// knownFilenames maps lockfile basenames to their parsers.
var knownFilenames = map[string]Parser{
	"go.sum":            &GoSumParser{},
	"package-lock.json": &NPMLockParser{},
	"yarn.lock":         &YarnLockParser{},
	"pnpm-lock.yaml":    &PnpmLockParser{},
	"Pipfile.lock":      &PipfileLockParser{},
	"poetry.lock":       &PoetryLockParser{},
	"Gemfile.lock":      &GemfileLockParser{},
	"Cargo.lock":        &CargoLockParser{},
	"requirements.txt":  &RequirementsTxtParser{},
	"composer.lock":     &ComposerLockParser{},
}

// Detect returns the appropriate parser for the given file path based on its
// basename. Returns an error if the file is not a recognized lockfile format.
func Detect(path string) (Parser, error) {
	base := filepath.Base(path)
	parser, ok := knownFilenames[base]
	if !ok {
		return nil, fmt.Errorf("unrecognized lockfile: %q (supported: %s)", base, supportedNames())
	}
	return parser, nil
}

// SupportedFilenames returns the list of recognized lockfile basenames.
func SupportedFilenames() []string {
	names := make([]string, 0, len(knownFilenames))
	for name := range knownFilenames {
		names = append(names, name)
	}
	return names
}

func supportedNames() string {
	return strings.Join(SupportedFilenames(), ", ")
}

// buildPurl constructs a Package URL string from the given components.
// Returns an empty string if the type or name is empty.
func buildPurl(purlType, namespace, name, version string) string {
	if purlType == "" || name == "" {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("pkg:")
	sb.WriteString(purlType)
	sb.WriteString("/")
	if namespace != "" {
		sb.WriteString(namespace)
		sb.WriteString("/")
	}
	sb.WriteString(name)
	if version != "" {
		sb.WriteString("@")
		sb.WriteString(version)
	}
	return sb.String()
}

// resolveComponent creates an sbom.Component from purl parts.
func resolveComponent(purlType, namespace, name, version, ecosystem string) sbom.Component {
	purlStr := buildPurl(purlType, namespace, name, version)

	// Build full package name for display
	fullName := name
	if namespace != "" {
		switch purlType {
		case "golang":
			fullName = namespace + "/" + name
		case "composer", "npm":
			fullName = namespace + "/" + name
		case "maven":
			fullName = namespace + ":" + name
		default:
			fullName = namespace + "/" + name
		}
	}

	return sbom.Component{
		Purl:      purlStr,
		Name:      fullName,
		Version:   version,
		Ecosystem: ecosystem,
		IsDev:     false,
	}
}

// FindLockfiles scans the given directory for recognized lockfile names
// (non-recursive, top-level only) and returns their paths.
func FindLockfiles(dir string) ([]string, error) {
	var found []string
	for name := range knownFilenames {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			found = append(found, path)
		}
	}
	return found, nil
}
