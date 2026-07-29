package lockfile

import (
	"bufio"
	"io"
	"net/url"
	"strings"

	"github.com/kato83/mayu/internal/sbom"
)

// YarnLockParser parses Yarn yarn.lock files (v1 classic format).
type YarnLockParser struct{}

// Parse reads a yarn.lock file and returns the extracted components.
// Yarn v1 classic format has entries like:
//
//	"package@version":
//	  version "1.0.0"
//	  resolved "..."
//	  integrity "..."
func (p *YarnLockParser) Parse(filename string, reader io.Reader) ([]sbom.Component, error) {
	seen := make(map[string]bool)
	var components []sbom.Component

	scanner := bufio.NewScanner(reader)
	var currentName string
	var inEntry bool

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// Entry header lines (not indented, end with ":")
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			// Parse the package name from the header
			// Format: "name@version", "name@^version", "@scope/name@version":
			header := strings.TrimSuffix(strings.TrimSpace(line), ":")
			currentName = extractYarnPackageName(header)
			inEntry = true
			continue
		}

		// Version line within an entry
		if inEntry && strings.Contains(line, "version") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "version ") {
				ver := strings.TrimPrefix(trimmed, "version ")
				ver = strings.Trim(ver, "\"")

				if currentName != "" && ver != "" {
					key := currentName + "@" + ver
					if !seen[key] {
						seen[key] = true
						namespace, pkgName := splitNPMName(currentName)
						comp := resolveComponent("npm", namespace, url.PathEscape(pkgName), ver, "npm")
						comp.Name = currentName
						components = append(components, comp)
					}
				}
				inEntry = false
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return components, nil
}

// extractYarnPackageName extracts the package name from a yarn.lock entry header.
// Input examples:
//
//	"lodash@^4.17.21"         → "lodash"
//	"@angular/core@^17.0.0"  → "@angular/core"
//	"lodash@^4.17.21, lodash@^4.17.0" → "lodash"
//	lodash@^4.17.21           → "lodash" (without quotes)
func extractYarnPackageName(header string) string {
	// Take the first entry if there are multiple (comma-separated)
	if idx := strings.Index(header, ","); idx >= 0 {
		header = header[:idx]
	}

	header = strings.TrimSpace(header)
	header = strings.Trim(header, "\"")

	// Find the last "@" that separates name from version spec
	// For scoped packages like @scope/name@version, we need the last "@"
	if strings.HasPrefix(header, "@") {
		// Scoped package: find "@" after the first "/"
		slashIdx := strings.Index(header, "/")
		if slashIdx < 0 {
			return header
		}
		atIdx := strings.Index(header[slashIdx:], "@")
		if atIdx < 0 {
			return header
		}
		return header[:slashIdx+atIdx]
	}

	// Unscoped package: find the first "@"
	atIdx := strings.Index(header, "@")
	if atIdx < 0 {
		return header
	}
	return header[:atIdx]
}
