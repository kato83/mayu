package fetcher

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"time"
)

// ModifiedEntry represents a single entry from modified_id.csv.
// Format: <iso modified date>,<ecosystem_dir>/<id> (top-level)
// Format: <iso modified date>,<id> (per-ecosystem)
type ModifiedEntry struct {
	ModifiedAt time.Time
	Ecosystem  string // Empty for per-ecosystem CSVs
	ID         string
}

// ParseModifiedCSV parses the modified_id.csv content.
// The CSV is sorted in reverse chronological order (newest first).
//
// For top-level CSV: format is "<timestamp>,<ecosystem>/<id>"
// For per-ecosystem CSV: format is "<timestamp>,<id>"
//
// If ecosystem is provided, it is used as the ecosystem for all entries
// (per-ecosystem CSV mode). If empty, the ecosystem is parsed from the path.
func ParseModifiedCSV(data []byte, ecosystem string) ([]ModifiedEntry, error) {
	var entries []ModifiedEntry

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		entry, err := parseCSVLine(line, ecosystem)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}

		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan CSV: %w", err)
	}

	return entries, nil
}

// FilterModifiedSince returns entries that were modified after the given timestamp.
// Since the CSV is sorted in reverse chronological order, we can stop early
// once we encounter an entry older than the cutoff.
func FilterModifiedSince(entries []ModifiedEntry, since time.Time) []ModifiedEntry {
	var filtered []ModifiedEntry
	for _, entry := range entries {
		if !entry.ModifiedAt.After(since) {
			// CSV is reverse-chronological; all subsequent entries are older
			break
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

// parseCSVLine parses a single line of the modified_id.csv.
func parseCSVLine(line string, ecosystem string) (ModifiedEntry, error) {
	// Find the first comma to split timestamp from the rest
	commaIdx := strings.Index(line, ",")
	if commaIdx < 0 {
		return ModifiedEntry{}, fmt.Errorf("invalid format (no comma): %q", line)
	}

	timestampStr := line[:commaIdx]
	idPart := line[commaIdx+1:]

	// Parse timestamp
	modifiedAt, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		// Try with fractional seconds
		modifiedAt, err = time.Parse("2006-01-02T15:04:05.999999999Z07:00", timestampStr)
		if err != nil {
			return ModifiedEntry{}, fmt.Errorf("invalid timestamp %q: %w", timestampStr, err)
		}
	}

	entry := ModifiedEntry{
		ModifiedAt: modifiedAt,
	}

	if ecosystem != "" {
		// Per-ecosystem CSV: idPart is just the ID
		entry.Ecosystem = ecosystem
		entry.ID = strings.TrimSpace(idPart)
	} else {
		// Top-level CSV: idPart is "ecosystem/id"
		slashIdx := strings.Index(idPart, "/")
		if slashIdx < 0 {
			return ModifiedEntry{}, fmt.Errorf("invalid format (no slash in id part): %q", idPart)
		}
		entry.Ecosystem = idPart[:slashIdx]
		entry.ID = idPart[slashIdx+1:]
	}

	return entry, nil
}
