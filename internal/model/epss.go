// Package model defines Go structs for the EPSS (Exploit Prediction Scoring System) API.
// See https://www.first.org/epss/ for the specification.
//
// Design principle: reversibility.
//   - The RawJSON field preserves the original API response entry for storage in
//     PostgreSQL (raw_json JSONB column), ensuring no data loss.
//   - This pattern is shared with NVD and MITRE models, and is designed to be
//     reusable for future scoring systems (e.g., LEV/NIST CSWP 41).
package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// EPSSAPIResponse represents the top-level EPSS API response from FIRST.
// Endpoint: https://api.first.org/data/v1/epss
type EPSSAPIResponse struct {
	Status     string      `json:"status"`
	StatusCode int         `json:"status-code"`
	Version    string      `json:"version"`
	Access     string      `json:"access"`
	Total      int         `json:"total"`
	Offset     int         `json:"offset"`
	Limit      int         `json:"limit"`
	Data       []EPSSEntry `json:"data"`
}

// EPSSEntry represents a single EPSS score entry from the API response.
type EPSSEntry struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`

	// RawJSON stores the original API response entry for reversibility.
	// It is excluded from JSON marshaling to avoid circular encoding.
	// Populated during ingestion; used when writing to the database.
	RawJSON json.RawMessage `json:"-"`
}

// EPSSScore represents a parsed and validated EPSS score ready for storage.
// This is the normalized form used by the store layer.
type EPSSScore struct {
	CVEID      string
	EPSS       float64
	Percentile float64
	ScoreDate  time.Time
	RawJSON    json.RawMessage
}

// ParseEPSSScore validates and converts an EPSSEntry into an EPSSScore.
// Returns an error if required fields are missing or malformed.
func (e *EPSSEntry) ParseEPSSScore() (*EPSSScore, error) {
	if e.CVE == "" {
		return nil, errors.New("EPSS entry missing required field: cve")
	}
	if !strings.HasPrefix(strings.ToUpper(e.CVE), "CVE-") {
		return nil, fmt.Errorf("EPSS entry has invalid CVE ID: %q", e.CVE)
	}

	epss, err := strconv.ParseFloat(e.EPSS, 64)
	if err != nil {
		return nil, fmt.Errorf("parse EPSS score for %s: %w", e.CVE, err)
	}
	if epss < 0 || epss > 1 {
		return nil, fmt.Errorf("EPSS score for %s out of range [0,1]: %f", e.CVE, epss)
	}

	percentile, err := strconv.ParseFloat(e.Percentile, 64)
	if err != nil {
		return nil, fmt.Errorf("parse EPSS percentile for %s: %w", e.CVE, err)
	}
	if percentile < 0 || percentile > 1 {
		return nil, fmt.Errorf("EPSS percentile for %s out of range [0,1]: %f", e.CVE, percentile)
	}

	scoreDate, err := time.Parse("2006-01-02", e.Date)
	if err != nil {
		return nil, fmt.Errorf("parse EPSS date for %s: %w", e.CVE, err)
	}

	return &EPSSScore{
		CVEID:      strings.ToUpper(e.CVE),
		EPSS:       epss,
		Percentile: percentile,
		ScoreDate:  scoreDate,
		RawJSON:    e.RawJSON,
	}, nil
}

// ParseEPSSAPIResponse parses a full EPSS API JSON response.
// Each entry in the response has its RawJSON populated from the original data item.
func ParseEPSSAPIResponse(data []byte) (*EPSSAPIResponse, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	var resp EPSSAPIResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal EPSS response: %w", err)
	}

	if resp.Status != "OK" {
		return nil, fmt.Errorf("EPSS API returned non-OK status: %q (code: %d)", resp.Status, resp.StatusCode)
	}

	// Extract raw JSON for each data entry to preserve original format.
	var raw struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("extract raw EPSS data entries: %w", err)
	}

	for i := range resp.Data {
		if i < len(raw.Data) {
			compact, err := compactJSON(raw.Data[i])
			if err != nil {
				resp.Data[i].RawJSON = raw.Data[i]
			} else {
				resp.Data[i].RawJSON = compact
			}
		}
	}

	return &resp, nil
}

// ParseEPSSCSVLine parses a single line from the EPSS CSV bulk download file.
// CSV format: cve,epss,percentile (after header/comment lines are skipped).
// The date is provided externally (from the CSV file header comment or filename).
func ParseEPSSCSVLine(line string, scoreDate time.Time) (*EPSSScore, error) {
	parts := strings.Split(line, ",")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid EPSS CSV line (expected 3 fields): %q", line)
	}

	cve := strings.TrimSpace(parts[0])
	if !strings.HasPrefix(strings.ToUpper(cve), "CVE-") {
		return nil, fmt.Errorf("invalid CVE ID in CSV: %q", cve)
	}

	epss, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	if err != nil {
		return nil, fmt.Errorf("parse EPSS score for %s: %w", cve, err)
	}

	percentile, err := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
	if err != nil {
		return nil, fmt.Errorf("parse EPSS percentile for %s: %w", cve, err)
	}

	// Build raw JSON for reversibility (reconstruct the entry as it would appear from API).
	rawEntry := map[string]string{
		"cve":        strings.ToUpper(cve),
		"epss":       strings.TrimSpace(parts[1]),
		"percentile": strings.TrimSpace(parts[2]),
		"date":       scoreDate.Format("2006-01-02"),
	}
	rawJSON, err := json.Marshal(rawEntry)
	if err != nil {
		return nil, fmt.Errorf("marshal raw JSON for %s: %w", cve, err)
	}

	return &EPSSScore{
		CVEID:      strings.ToUpper(cve),
		EPSS:       epss,
		Percentile: percentile,
		ScoreDate:  scoreDate,
		RawJSON:    rawJSON,
	}, nil
}
