package lockfile

import (
	"bufio"
	"io"
	"strings"

	"github.com/kato83/mayu/internal/sbom"
)

// RequirementsTxtParser parses Python requirements.txt files.
type RequirementsTxtParser struct{}

// Parse reads a requirements.txt file and returns the extracted components.
// Supported formats:
//
//	package==version
//	package==version ; markers
//	package==version # comment
//
// Lines with version ranges (>=, <=, !=, ~=) are skipped since we need exact versions.
// Lines starting with -r, -c, -e, --hash, etc. are skipped.
func (p *RequirementsTxtParser) Parse(filename string, reader io.Reader) ([]sbom.Component, error) {
	var components []sbom.Component
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()

		// Strip inline comments
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}

		line = strings.TrimSpace(line)

		// Skip empty lines and pip options
		if line == "" || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "--") {
			continue
		}

		// Strip environment markers (e.g., "; python_version >= '3.6'")
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Strip extras (e.g., "package[extra1,extra2]==1.0")
		name, version := parseRequirement(line)
		if name == "" || version == "" {
			continue
		}

		key := name + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		comp := resolveComponent("pypi", "", normalizePyPIName(name), version, "PyPI")
		comp.Name = name
		components = append(components, comp)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return components, nil
}

// parseRequirement parses a requirement line and returns name and version.
// Only exact version pins (==) are supported.
func parseRequirement(line string) (name, version string) {
	// Handle extras: strip [extra1,extra2] from the package name
	bracketIdx := strings.Index(line, "[")
	var extras string
	if bracketIdx >= 0 {
		closeBracket := strings.Index(line[bracketIdx:], "]")
		if closeBracket >= 0 {
			extras = line[bracketIdx : bracketIdx+closeBracket+1]
			line = line[:bracketIdx] + line[bracketIdx+closeBracket+1:]
		}
	}
	_ = extras

	// Only parse exact version pins (==)
	if idx := strings.Index(line, "=="); idx >= 0 {
		name = strings.TrimSpace(line[:idx])
		version = strings.TrimSpace(line[idx+2:])
		// Strip any trailing whitespace or version qualifiers
		if spaceIdx := strings.IndexAny(version, " \t"); spaceIdx >= 0 {
			version = version[:spaceIdx]
		}
		return name, version
	}

	return "", ""
}
