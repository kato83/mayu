package audit

import (
	"bufio"
	"os"
	"strings"
)

// ParseIgnoreFile reads an ignore file and returns a set of vulnerability IDs
// to suppress. The file format uses one ID per line. Lines starting with # are
// comments, blank lines are skipped, and inline comments (text after #) are
// stripped. Leading and trailing whitespace is trimmed from each ID.
func ParseIgnoreFile(path string) (ignored map[string]bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	ignored = make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Strip inline comments
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		ignored[line] = true
	}

	if err = scanner.Err(); err != nil {
		return nil, err
	}

	return ignored, nil
}

// FilterFindings returns a new slice of findings that excludes any finding
// whose VulnID or any of its Aliases appear in the ignored set.
func FilterFindings(findings []Finding, ignored map[string]bool) []Finding {
	if len(ignored) == 0 {
		return findings
	}

	var filtered []Finding
	for _, f := range findings {
		if ignored[f.VulnID] {
			continue
		}
		// Also check aliases
		aliasIgnored := false
		for _, alias := range f.Aliases {
			if ignored[alias] {
				aliasIgnored = true
				break
			}
		}
		if aliasIgnored {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}
