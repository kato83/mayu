// Package parser handles parsing and validating OSV JSON data,
// converting raw bytes into model.Vulnerability structs ready for storage.
package parser

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/kato83/mayu/internal/model"
)

// ParseResult contains the results of parsing a batch of OSV JSON files.
type ParseResult struct {
	// Vulnerabilities contains successfully parsed entries.
	Vulnerabilities []*model.Vulnerability

	// Errors contains entries that failed to parse, with details.
	Errors []ParseError
}

// ParseError describes a single parse failure.
type ParseError struct {
	ID    string // Filename or ID if available
	Error error
}

// Parser parses OSV JSON data into model.Vulnerability structs.
type Parser struct {
	// Logger for reporting skipped entries. If nil, uses log.Default().
	Logger *log.Logger

	// Strict mode: if true, return error on first failure instead of skipping.
	Strict bool
}

// New creates a new Parser with default settings.
func New() *Parser {
	return &Parser{}
}

// Parse parses a single OSV JSON byte slice into a Vulnerability.
// Returns an error if the JSON is invalid or missing required fields.
func (p *Parser) Parse(data []byte) (*model.Vulnerability, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	// First validate it's valid JSON
	if !json.Valid(data) {
		return nil, errors.New("invalid JSON")
	}

	// Parse using model.ParseVulnerability (preserves RawJSON)
	vuln, err := model.ParseVulnerability(data)
	if err != nil {
		return nil, fmt.Errorf("parse vulnerability: %w", err)
	}

	// Validate required fields per OSV schema
	if err := validate(vuln); err != nil {
		return nil, fmt.Errorf("validation: %w", err)
	}

	return vuln, nil
}

// ParseBatch parses multiple OSV JSON entries.
// Files is a map of identifier (e.g., filename) → raw JSON bytes.
// Invalid entries are skipped (logged) unless Strict mode is enabled.
func (p *Parser) ParseBatch(files map[string][]byte) (*ParseResult, error) {
	result := &ParseResult{}

	for id, data := range files {
		vuln, err := p.Parse(data)
		if err != nil {
			parseErr := ParseError{ID: id, Error: err}
			if p.Strict {
				return nil, fmt.Errorf("parse %s: %w", id, err)
			}
			result.Errors = append(result.Errors, parseErr)
			p.logf("skipping %s: %v", id, err)
			continue
		}
		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
	}

	return result, nil
}

// validate checks that required fields are present and valid.
func validate(vuln *model.Vulnerability) error {
	if vuln.ID == "" {
		return errors.New("missing required field: id")
	}
	if vuln.Modified.IsZero() {
		return errors.New("missing required field: modified")
	}
	return nil
}

// logf logs a message using the parser's logger.
func (p *Parser) logf(format string, args ...interface{}) {
	if p.Logger != nil {
		p.Logger.Printf(format, args...)
	} else {
		log.Printf("[parser] "+format, args...)
	}
}
