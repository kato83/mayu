package lockfile

import (
	"bufio"
	"io"
	"strings"

	"github.com/kato83/mayu/internal/sbom"
)

// PoetryLockParser parses Python poetry.lock files.
type PoetryLockParser struct{}

// Parse reads a poetry.lock file and returns the extracted components.
// poetry.lock is in TOML format with [[package]] sections.
// We parse it line-by-line to avoid a TOML dependency.
func (p *PoetryLockParser) Parse(filename string, reader io.Reader) ([]sbom.Component, error) {
	var components []sbom.Component

	scanner := bufio.NewScanner(reader)
	var currentName string
	var currentVersion string
	var inPackage bool

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Start of a new package section
		if trimmed == "[[package]]" {
			// Save the previous package if complete
			if inPackage && currentName != "" && currentVersion != "" {
				comp := resolveComponent("pypi", "", normalizePyPIName(currentName), currentVersion, "PyPI")
				comp.Name = currentName
				components = append(components, comp)
			}
			currentName = ""
			currentVersion = ""
			inPackage = true
			continue
		}

		if !inPackage {
			continue
		}

		// Parse name and version fields within the package section
		if strings.HasPrefix(trimmed, "name") {
			currentName = extractTOMLStringValue(trimmed)
		} else if strings.HasPrefix(trimmed, "version") {
			currentVersion = extractTOMLStringValue(trimmed)
		} else if strings.HasPrefix(trimmed, "[") && trimmed != "[[package]]" {
			// End of package fields — entering a sub-section
			// Save the current package
			if currentName != "" && currentVersion != "" {
				comp := resolveComponent("pypi", "", normalizePyPIName(currentName), currentVersion, "PyPI")
				comp.Name = currentName
				components = append(components, comp)
			}
			currentName = ""
			currentVersion = ""
			inPackage = false
		}
	}

	// Save the last package
	if inPackage && currentName != "" && currentVersion != "" {
		comp := resolveComponent("pypi", "", normalizePyPIName(currentName), currentVersion, "PyPI")
		comp.Name = currentName
		components = append(components, comp)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return components, nil
}

// extractTOMLStringValue extracts the string value from a simple TOML key-value pair.
// Input: `name = "requests"` → "requests"
func extractTOMLStringValue(line string) string {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return ""
	}
	val := strings.TrimSpace(parts[1])
	val = strings.Trim(val, "\"")
	return val
}
