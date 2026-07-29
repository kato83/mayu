package lockfile

import (
	"bufio"
	"io"
	"strings"

	"github.com/kato83/mayu/internal/sbom"
)

// GemfileLockParser parses Ruby Gemfile.lock files.
type GemfileLockParser struct{}

// Parse reads a Gemfile.lock file and returns the extracted components.
// Gemfile.lock has sections like GEM, GIT, PATH, etc.
// We parse the specs under the GEM section.
func (p *GemfileLockParser) Parse(filename string, reader io.Reader) ([]sbom.Component, error) {
	var components []sbom.Component
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(reader)
	inSpecs := false

	for scanner.Scan() {
		line := scanner.Text()

		// Check for section headers
		trimmed := strings.TrimSpace(line)

		// "specs:" indicates the start of a gem listing
		if trimmed == "specs:" {
			inSpecs = true
			continue
		}

		// A non-indented line that isn't empty ends the specs section
		if inSpecs && len(line) > 0 && line[0] != ' ' {
			inSpecs = false
			// Check if this new section also has specs
			if trimmed == "specs:" {
				inSpecs = true
			}
			continue
		}

		if !inSpecs {
			continue
		}

		// Gem entries are indented with exactly 4 spaces (top-level gems)
		// Sub-dependencies are indented with 6+ spaces
		// We want top-level gems (4 spaces indent under specs)
		if !strings.HasPrefix(line, "    ") {
			continue
		}

		// Only parse lines with exactly 4 spaces of indent (top-level gem in specs)
		if strings.HasPrefix(line, "      ") {
			// This is a sub-dependency — skip
			continue
		}

		// Parse "    gem-name (version)"
		entry := strings.TrimSpace(line)
		name, version := parseGemEntry(entry)
		if name == "" || version == "" {
			continue
		}

		key := name + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		comp := resolveComponent("gem", "", name, version, "RubyGems")
		comp.Name = name
		components = append(components, comp)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return components, nil
}

// parseGemEntry parses a gem entry line like "rails (7.1.0)" into name and version.
func parseGemEntry(entry string) (name, version string) {
	parenIdx := strings.Index(entry, "(")
	if parenIdx < 0 {
		return "", ""
	}

	name = strings.TrimSpace(entry[:parenIdx])

	closeIdx := strings.Index(entry[parenIdx:], ")")
	if closeIdx < 0 {
		return name, ""
	}

	version = entry[parenIdx+1 : parenIdx+closeIdx]
	return name, version
}
