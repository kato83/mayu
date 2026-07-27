package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/kato83/mayu/internal/translate"
)

// translateRequest is the request body for POST /api/v1/vulnerabilities/{id}/translate.
type translateRequest struct {
	// Locale is the target locale for translation (BCP 47 tag, e.g., "ja", "ko", "zh-Hans").
	Locale string `json:"locale"`
}

// translateResponse is the response for a successful translation request.
type translateResponse struct {
	// Status indicates the operation result ("ok").
	Status string `json:"status"`
	// VulnerabilityID is the translated vulnerability ID.
	VulnerabilityID string `json:"vulnerability_id"`
	// Locale is the locale that was translated into.
	Locale string `json:"locale"`
	// FieldsTranslated is the number of text fields that were translated.
	FieldsTranslated int `json:"fields_translated"`
}

// handleTranslateVulnerability handles POST /api/v1/vulnerabilities/{id}/translate.
// It translates all text fields of a vulnerability into the requested locale using the configured LLM.
func (s *Server) handleTranslateVulnerability(w http.ResponseWriter, r *http.Request) {
	if s.translateService == nil {
		writeError(w, http.StatusServiceUnavailable, "translation is not configured; set translation.enabled=true in config.yaml")
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "vulnerability ID is required")
		return
	}
	if decoded, err := url.PathUnescape(id); err == nil {
		id = decoded
	}

	// Parse request body
	var req translateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Locale == "" {
		writeError(w, http.StatusBadRequest, "locale is required")
		return
	}

	ctx := r.Context()

	// Resolve vulnerability ID (handles aliases/OSV IDs)
	vulnID, err := s.store.ResolveVulnerabilityID(ctx, id)
	if err != nil {
		slog.Error("failed to resolve vulnerability ID for translation", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if vulnID == "" {
		writeError(w, http.StatusNotFound, fmt.Sprintf("vulnerability %q not found", id))
		return
	}

	// Get all translatable texts from the database
	texts, err := s.store.GetTranslatableTexts(ctx, vulnID)
	if err != nil {
		slog.Error("failed to get translatable texts", "id", vulnID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if texts == nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("vulnerability %q not found", id))
		return
	}

	// Perform translation via LLM
	translationTexts := translate.VulnerabilityTexts{
		VulnerabilityID:      vulnID,
		Summary:              texts.Summary,
		Details:              texts.Details,
		NVDDescription:       texts.NVDDescription,
		NVDDescriptionID:     texts.NVDDescriptionID,
		KEVEntryID:           texts.KEVEntryID,
		KEVVulnerabilityName: texts.KEVVulnerabilityName,
		KEVShortDescription:  texts.KEVShortDescription,
		KEVRequiredAction:    texts.KEVRequiredAction,
		KEVNotes:             texts.KEVNotes,
	}

	result, err := s.translateService.TranslateVulnerability(ctx, translationTexts, req.Locale)
	if err != nil {
		slog.Error("LLM translation failed", "id", vulnID, "locale", req.Locale, "error", err)
		writeError(w, http.StatusInternalServerError, "translation failed: "+err.Error())
		return
	}

	// Save translations to database
	fieldsTranslated := 0

	// Save vulnerability summary/details
	if result.Summary != "" || result.Details != "" {
		if err := s.store.SaveVulnerabilityTranslation(ctx, vulnID, req.Locale, result.Summary, result.Details, result.TranslatedAt); err != nil {
			slog.Error("failed to save vulnerability translation", "id", vulnID, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to save translation")
			return
		}
		if result.Summary != "" {
			fieldsTranslated++
		}
		if result.Details != "" {
			fieldsTranslated++
		}
	}

	// Save NVD description translation
	if result.NVDDescription != "" && texts.NVDDescriptionID > 0 {
		if err := s.store.SaveNVDDescriptionTranslation(ctx, texts.NVDDescriptionID, req.Locale, result.NVDDescription, result.TranslatedAt); err != nil {
			slog.Error("failed to save NVD description translation", "id", vulnID, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to save translation")
			return
		}
		fieldsTranslated++
	}

	// Save KEV translation
	if texts.KEVEntryID > 0 && (result.KEVVulnName != "" || result.KEVShortDesc != "" || result.KEVReqAction != "" || result.KEVNotes != "") {
		if err := s.store.SaveKEVTranslation(ctx, texts.KEVEntryID, req.Locale, result.KEVVulnName, result.KEVShortDesc, result.KEVReqAction, result.KEVNotes, result.TranslatedAt); err != nil {
			slog.Error("failed to save KEV translation", "id", vulnID, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to save translation")
			return
		}
		if result.KEVVulnName != "" {
			fieldsTranslated++
		}
		if result.KEVShortDesc != "" {
			fieldsTranslated++
		}
		if result.KEVReqAction != "" {
			fieldsTranslated++
		}
		if result.KEVNotes != "" {
			fieldsTranslated++
		}
	}

	writeJSON(w, http.StatusOK, translateResponse{
		Status:           "ok",
		VulnerabilityID:  vulnID,
		Locale:           req.Locale,
		FieldsTranslated: fieldsTranslated,
	})
}
