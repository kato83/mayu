package translate

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// VulnerabilityTexts holds all translatable text fields for a vulnerability.
type VulnerabilityTexts struct {
	// VulnerabilityID is the canonical vulnerability ID (e.g., CVE-2024-1234).
	VulnerabilityID string

	// Summary is the vulnerability summary (from vulnerabilities table).
	Summary string

	// Details is the vulnerability details (from vulnerabilities table).
	Details string

	// NVDDescription is the English description from NVD.
	NVDDescription string

	// NVDDescriptionID is the database ID of the nvd_descriptions row (for storage).
	NVDDescriptionID int64

	// KEVEntryID is the database ID of the kev_entries row (for storage).
	KEVEntryID int64

	// KEVVulnerabilityName is the KEV vulnerability name.
	KEVVulnerabilityName string

	// KEVShortDescription is the KEV short description.
	KEVShortDescription string

	// KEVRequiredAction is the KEV required action.
	KEVRequiredAction string

	// KEVNotes is the KEV notes field.
	KEVNotes string

	// OSVEntries holds translatable texts for each OSV entry.
	OSVEntries []OSVEntryTexts
}

// OSVEntryTexts holds translatable text fields for a single OSV entry.
type OSVEntryTexts struct {
	OsvID   string
	Summary string
	Details string
}

// TranslationResult holds all translated texts for a vulnerability.
type TranslationResult struct {
	Locale         string
	TranslatedAt   time.Time
	Summary        string
	Details        string
	NVDDescription string
	KEVVulnName    string
	KEVShortDesc   string
	KEVReqAction   string
	KEVNotes       string
	OSVEntries     []OSVEntryTranslationResult
}

// OSVEntryTranslationResult holds translated texts for a single OSV entry.
type OSVEntryTranslationResult struct {
	OsvID   string
	Summary string
	Details string
}

// Service orchestrates translating vulnerability text fields using an LLM client.
type Service struct {
	client *Client
}

// NewService creates a new translation service.
func NewService(client *Client) *Service {
	return &Service{client: client}
}

// TranslateVulnerability translates all non-empty text fields of a vulnerability
// into the target locale. Returns the translation result.
func (s *Service) TranslateVulnerability(ctx context.Context, texts VulnerabilityTexts, targetLocale string) (*TranslationResult, error) {
	slog.Info("translating vulnerability",
		"id", texts.VulnerabilityID,
		"locale", targetLocale,
		"provider", s.client.Provider(),
	)

	result := &TranslationResult{
		Locale:       targetLocale,
		TranslatedAt: time.Now().UTC(),
	}

	// Translate vulnerability summary
	if texts.Summary != "" {
		translated, err := s.client.Translate(ctx, texts.Summary, targetLocale)
		if err != nil {
			return nil, fmt.Errorf("translate summary: %w", err)
		}
		result.Summary = translated
	}

	// Translate vulnerability details
	if texts.Details != "" {
		translated, err := s.client.Translate(ctx, texts.Details, targetLocale)
		if err != nil {
			return nil, fmt.Errorf("translate details: %w", err)
		}
		result.Details = translated
	}

	// Translate NVD description
	if texts.NVDDescription != "" {
		translated, err := s.client.Translate(ctx, texts.NVDDescription, targetLocale)
		if err != nil {
			return nil, fmt.Errorf("translate NVD description: %w", err)
		}
		result.NVDDescription = translated
	}

	// Translate KEV fields (batch them together if all present)
	if texts.KEVVulnerabilityName != "" || texts.KEVShortDescription != "" || texts.KEVRequiredAction != "" || texts.KEVNotes != "" {
		kevTexts := []string{texts.KEVVulnerabilityName, texts.KEVShortDescription, texts.KEVRequiredAction, texts.KEVNotes}
		translations, err := s.client.TranslateBatch(ctx, kevTexts, targetLocale)
		if err != nil {
			return nil, fmt.Errorf("translate KEV fields: %w", err)
		}
		result.KEVVulnName = translations[0]
		result.KEVShortDesc = translations[1]
		result.KEVReqAction = translations[2]
		result.KEVNotes = translations[3]
	}

	// Translate OSV entry texts
	for _, entry := range texts.OSVEntries {
		var entryResult OSVEntryTranslationResult
		entryResult.OsvID = entry.OsvID

		if entry.Summary != "" {
			translated, err := s.client.Translate(ctx, entry.Summary, targetLocale)
			if err != nil {
				return nil, fmt.Errorf("translate OSV entry %s summary: %w", entry.OsvID, err)
			}
			entryResult.Summary = translated
		}

		if entry.Details != "" {
			translated, err := s.client.Translate(ctx, entry.Details, targetLocale)
			if err != nil {
				return nil, fmt.Errorf("translate OSV entry %s details: %w", entry.OsvID, err)
			}
			entryResult.Details = translated
		}

		if entryResult.Summary != "" || entryResult.Details != "" {
			result.OSVEntries = append(result.OSVEntries, entryResult)
		}
	}

	slog.Info("translation complete",
		"id", texts.VulnerabilityID,
		"locale", targetLocale,
		"fields_translated", countNonEmpty(result),
	)

	return result, nil
}

func countNonEmpty(r *TranslationResult) int {
	count := 0
	if r.Summary != "" {
		count++
	}
	if r.Details != "" {
		count++
	}
	if r.NVDDescription != "" {
		count++
	}
	if r.KEVVulnName != "" {
		count++
	}
	if r.KEVShortDesc != "" {
		count++
	}
	if r.KEVReqAction != "" {
		count++
	}
	if r.KEVNotes != "" {
		count++
	}
	for _, entry := range r.OSVEntries {
		if entry.Summary != "" {
			count++
		}
		if entry.Details != "" {
			count++
		}
	}
	return count
}
