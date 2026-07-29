package lockfile

import (
	"bufio"
	"io"
	"strings"

	"github.com/kato83/mayu/internal/sbom"
)

// CargoLockParser parses Rust Cargo.lock files.
type CargoLockParser struct{}

// Parse reads a Cargo.lock file and returns the extracted components.
// Cargo.lock is in TOML format with [[package]] sections containing
// name, version, and source fields.
func (p *CargoLockParser) Parse(filename string, reader io.Reader) ([]sbom.Component, error) {
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
				comp := resolveComponent("cargo", "", currentName, currentVersion, "crates.io")
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

		// Parse fields
		if strings.HasPrefix(trimmed, "name") {
			currentName = extractTOMLStringValue(trimmed)
		} else if strings.HasPrefix(trimmed, "version") {
			currentVersion = extractTOMLStringValue(trimmed)
		} else if trimmed == "" || (strings.HasPrefix(trimmed, "[") && trimmed != "[[package]]") {
			// End of package section
			if currentName != "" && currentVersion != "" {
				comp := resolveComponent("cargo", "", currentName, currentVersion, "crates.io")
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
		comp := resolveComponent("cargo", "", currentName, currentVersion, "crates.io")
		comp.Name = currentName
		components = append(components, comp)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return components, nil
}
