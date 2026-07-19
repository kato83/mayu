package parser

import (
	"errors"
	"fmt"

	"github.com/kato83/mayu/internal/model"
)

// NVDParseResult contains the results of parsing an NVD feed.
type NVDParseResult struct {
	// Entries contains successfully parsed NVD CVE entries.
	Entries []*model.NVDCVE

	// Errors contains entries that failed to parse.
	Errors []ParseError
}

// ParseNVDFeed parses a complete NVD JSON Feed 2.0 response.
// It extracts individual CVE entries, validates required fields,
// and preserves the raw JSON of each entry for reversibility.
func (p *Parser) ParseNVDFeed(data []byte) (*NVDParseResult, error) {
	if len(data) == 0 {
		return nil, errors.New("empty feed data")
	}

	// Parse the feed structure using model.ParseNVDFeedResponse
	// which handles RawJSON extraction for each CVE entry.
	feed, err := model.ParseNVDFeedResponse(data)
	if err != nil {
		return nil, fmt.Errorf("parse NVD feed: %w", err)
	}

	result := &NVDParseResult{}

	for i, item := range feed.Vulnerabilities {
		cve := item.CVE

		// Validate required fields
		if err := validateNVDEntry(&cve); err != nil {
			parseErr := ParseError{
				ID:    cve.ID,
				Error: err,
			}
			if cve.ID == "" {
				parseErr.ID = fmt.Sprintf("entry[%d]", i)
			}
			if p.Strict {
				return nil, fmt.Errorf("parse entry %s: %w", parseErr.ID, err)
			}
			result.Errors = append(result.Errors, parseErr)
			p.logf("skipping NVD entry %s: %v", parseErr.ID, err)
			continue
		}

		// Copy the CVE to avoid referencing the loop variable
		entry := cve
		result.Entries = append(result.Entries, &entry)
	}

	return result, nil
}

// ParseNVDSingle parses a single NVD CVE JSON object.
// This is useful for parsing individual CVE files or API responses.
func (p *Parser) ParseNVDSingle(data []byte) (*model.NVDCVE, error) {
	cve, err := model.ParseNVDEntry(data)
	if err != nil {
		return nil, err
	}
	if err := validateNVDEntry(cve); err != nil {
		return nil, err
	}
	return cve, nil
}

// validateNVDEntry checks that required NVD CVE fields are present and valid.
func validateNVDEntry(cve *model.NVDCVE) error {
	if cve.ID == "" {
		return errors.New("missing required field: id")
	}
	if !isValidCVEID(cve.ID) {
		return fmt.Errorf("invalid CVE ID format: %s", cve.ID)
	}
	if cve.Published.Time.IsZero() {
		return fmt.Errorf("missing required field: published (CVE: %s)", cve.ID)
	}
	if cve.LastModified.Time.IsZero() {
		return fmt.Errorf("missing required field: lastModified (CVE: %s)", cve.ID)
	}
	if len(cve.Descriptions) == 0 {
		return fmt.Errorf("missing required field: descriptions (CVE: %s)", cve.ID)
	}
	return nil
}

// isValidCVEID checks if a string matches the CVE ID pattern: CVE-YYYY-NNNN+
func isValidCVEID(id string) bool {
	if len(id) < 13 { // CVE-YYYY-NNNN minimum
		return false
	}
	if id[:4] != "CVE-" {
		return false
	}
	// Check year part (4 digits)
	for i := 4; i < 8; i++ {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
	}
	if id[8] != '-' {
		return false
	}
	// Check number part (4+ digits)
	for i := 9; i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
	}
	return true
}
