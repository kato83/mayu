package parser

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kato83/mayu/internal/model"
)

// nvdSourceResponse represents the JSON structure from the NVD Source API.
type nvdSourceResponse struct {
	TotalResults int             `json:"totalResults"`
	Sources      []nvdSourceItem `json:"sources"`
}

// nvdSourceItem represents a single source organization from the NVD Source API.
type nvdSourceItem struct {
	Name              string   `json:"name"`
	ContactEmail      string   `json:"contactEmail"`
	SourceIdentifiers []string `json:"sourceIdentifiers"`
	LastModified      string   `json:"lastModified"`
	Created           string   `json:"created"`
	V3AcceptanceLevel *struct {
		Description  string `json:"description"`
		LastModified string `json:"lastModified"`
	} `json:"v3AcceptanceLevel"`
}

// nvdSourceTimeFormats lists the time formats used by the NVD Source API.
var nvdSourceTimeFormats = []string{
	"2006-01-02T15:04:05.000",
	"2006-01-02T15:04:05",
	time.RFC3339,
}

// ParseNVDSources parses a response from the NVD Source API into model.NVDSource entries.
// Each source identifier gets its own NVDSource entry (a source organization with
// multiple identifiers produces multiple entries sharing the same name).
func (p *Parser) ParseNVDSources(data []byte) ([]model.NVDSource, error) {
	if len(data) == 0 {
		return nil, errors.New("empty source data")
	}

	var resp nvdSourceResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse NVD source response: %w", err)
	}

	var sources []model.NVDSource
	for _, item := range resp.Sources {
		lastMod := parseNVDSourceTime(item.LastModified)
		created := parseNVDSourceTime(item.Created)

		var acceptanceLevel string
		if item.V3AcceptanceLevel != nil {
			acceptanceLevel = item.V3AcceptanceLevel.Description
		}

		for _, id := range item.SourceIdentifiers {
			sources = append(sources, model.NVDSource{
				Name:             item.Name,
				ContactEmail:     item.ContactEmail,
				SourceIdentifier: id,
				AcceptanceLevel:  acceptanceLevel,
				LastModified:     lastMod,
				CreatedAt:        created,
			})
		}
	}

	return sources, nil
}

// parseNVDSourceTime attempts to parse a timestamp string from the NVD Source API.
// Returns nil if the string is empty or cannot be parsed.
func parseNVDSourceTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, format := range nvdSourceTimeFormats {
		if t, err := time.Parse(format, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}
