package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/kato83/mayu/internal/auth"
	"github.com/kato83/mayu/internal/store"
	"github.com/kato83/mayu/internal/triage"
)

// isBuiltinProfile checks if a profile name is a built-in (protected) profile.
func isBuiltinProfile(name string) bool {
	name = strings.TrimSpace(name)
	for _, t := range triage.BuiltinTemplates() {
		if t.Name == name {
			return true
		}
	}
	return false
}

// triageProfileResponse is the JSON response format for triage profiles.
type triageProfileResponse struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Base        string            `json:"base,omitempty"`
	Weights     interface{}       `json:"weights"`
	Thresholds  interface{}       `json:"thresholds"`
	SSVCMapping map[string]string `json:"ssvc_mapping,omitempty"`
	Builtin     bool              `json:"builtin"`
	ID          *int64            `json:"id,omitempty"`
	CreatedBy   *int64            `json:"created_by,omitempty"`
	CreatedAt   string            `json:"created_at,omitempty"`
	UpdatedAt   string            `json:"updated_at,omitempty"`
}

// handleListTriageProfilesAll handles GET /api/v1/triage/profiles
// Returns both built-in and custom profiles.
func (s *Server) handleListTriageProfilesAll(w http.ResponseWriter, r *http.Request) {
	// Built-in profiles
	builtins := triage.BuiltinTemplates()

	var profiles []triageProfileResponse

	for _, b := range builtins {
		profiles = append(profiles, triageProfileResponse{
			Name:        b.Name,
			Description: b.Description,
			Weights:     b.Weights,
			Thresholds:  b.Thresholds,
			SSVCMapping: b.SSVCMapping,
			Builtin:     true,
		})
	}

	// Custom profiles from DB
	customProfiles, err := s.store.ListTriageProfiles(r.Context())
	if err != nil {
		slog.Error("failed to list custom triage profiles", "error", err)
	} else {
		for _, cp := range customProfiles {
			pr := triageProfileResponse{
				Name:        cp.Name,
				Description: cp.Description,
				Base:        cp.Base,
				Builtin:     false,
				ID:          &cp.ID,
				CreatedBy:   cp.CreatedBy,
				CreatedAt:   cp.CreatedAt.Format("2006-01-02T15:04:05Z"),
				UpdatedAt:   cp.UpdatedAt.Format("2006-01-02T15:04:05Z"),
			}

			// Unmarshal JSONB fields into interface{} for response
			var weights interface{}
			if err := json.Unmarshal(cp.Weights, &weights); err == nil {
				pr.Weights = weights
			}
			var thresholds interface{}
			if err := json.Unmarshal(cp.Thresholds, &thresholds); err == nil {
				pr.Thresholds = thresholds
			}
			if cp.SSVCMapping != nil {
				var ssvc map[string]string
				if err := json.Unmarshal(*cp.SSVCMapping, &ssvc); err == nil {
					pr.SSVCMapping = ssvc
				}
			}

			profiles = append(profiles, pr)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"profiles": profiles,
	})
}

// handleCreateTriageProfile handles POST /api/v1/triage/profiles
func (s *Server) handleCreateTriageProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Base        string            `json:"base,omitempty"`
		Weights     json.RawMessage   `json:"weights"`
		Thresholds  json.RawMessage   `json:"thresholds"`
		SSVCMapping map[string]string `json:"ssvc_mapping,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	if isBuiltinProfile(req.Name) {
		writeError(w, http.StatusConflict, "cannot create profile with reserved name: "+req.Name)
		return
	}

	if len(req.Weights) == 0 {
		writeError(w, http.StatusBadRequest, "weights is required")
		return
	}
	if len(req.Thresholds) == 0 {
		writeError(w, http.StatusBadRequest, "thresholds is required")
		return
	}

	// Validate profile
	profile := buildProfileFromRequest(req.Name, req.Description, req.Base, req.Weights, req.Thresholds, req.SSVCMapping)
	if profile == nil {
		writeError(w, http.StatusBadRequest, "invalid profile data")
		return
	}
	errs := triage.ValidateProfile(profile)
	if len(errs) > 0 {
		errStrs := make([]string, len(errs))
		for i, e := range errs {
			errStrs[i] = e.Error()
		}
		writeJSON(w, http.StatusUnprocessableEntity, map[string]interface{}{
			"valid":  false,
			"errors": errStrs,
		})
		return
	}

	// Persist
	var ssvcMapping *json.RawMessage
	if len(req.SSVCMapping) > 0 {
		data, _ := json.Marshal(req.SSVCMapping)
		raw := json.RawMessage(data)
		ssvcMapping = &raw
	}

	var createdBy *int64
	if user := auth.UserFromContext(r.Context()); user != nil {
		createdBy = &user.ID
	}

	row := &store.TriageProfileRow{
		Name:        req.Name,
		Description: req.Description,
		Base:        req.Base,
		Weights:     req.Weights,
		Thresholds:  req.Thresholds,
		SSVCMapping: ssvcMapping,
		CreatedBy:   createdBy,
	}

	created, err := s.store.CreateTriageProfile(r.Context(), row)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique constraint") {
			writeError(w, http.StatusConflict, "profile with name '"+req.Name+"' already exists")
			return
		}
		slog.Error("failed to create triage profile", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create profile")
		return
	}

	writeJSON(w, http.StatusCreated, formatProfileRow(created))
}

// handleGetTriageProfile handles GET /api/v1/triage/profiles/{name}
func (s *Server) handleGetTriageProfile(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "profile name is required")
		return
	}

	// Check built-in first
	for _, b := range triage.BuiltinTemplates() {
		if b.Name == name {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"name":         b.Name,
				"description":  b.Description,
				"weights":      b.Weights,
				"thresholds":   b.Thresholds,
				"ssvc_mapping": b.SSVCMapping,
				"builtin":      true,
			})
			return
		}
	}

	// Check custom
	row, err := s.store.GetTriageProfile(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get profile")
		return
	}
	if row == nil {
		writeError(w, http.StatusNotFound, "profile not found: "+name)
		return
	}

	writeJSON(w, http.StatusOK, formatProfileRow(row))
}

// handleUpdateTriageProfile handles PUT /api/v1/triage/profiles/{name}
func (s *Server) handleUpdateTriageProfile(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "profile name is required")
		return
	}

	if isBuiltinProfile(name) {
		writeError(w, http.StatusForbidden, "cannot modify built-in profile: "+name)
		return
	}

	var req struct {
		Description string            `json:"description"`
		Base        string            `json:"base,omitempty"`
		Weights     json.RawMessage   `json:"weights"`
		Thresholds  json.RawMessage   `json:"thresholds"`
		SSVCMapping map[string]string `json:"ssvc_mapping,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Weights) == 0 {
		writeError(w, http.StatusBadRequest, "weights is required")
		return
	}
	if len(req.Thresholds) == 0 {
		writeError(w, http.StatusBadRequest, "thresholds is required")
		return
	}

	// Validate
	profile := buildProfileFromRequest(name, req.Description, req.Base, req.Weights, req.Thresholds, req.SSVCMapping)
	if profile == nil {
		writeError(w, http.StatusBadRequest, "invalid profile data")
		return
	}
	errs := triage.ValidateProfile(profile)
	if len(errs) > 0 {
		errStrs := make([]string, len(errs))
		for i, e := range errs {
			errStrs[i] = e.Error()
		}
		writeJSON(w, http.StatusUnprocessableEntity, map[string]interface{}{
			"valid":  false,
			"errors": errStrs,
		})
		return
	}

	var ssvcMapping *json.RawMessage
	if len(req.SSVCMapping) > 0 {
		data, _ := json.Marshal(req.SSVCMapping)
		raw := json.RawMessage(data)
		ssvcMapping = &raw
	}

	row := &store.TriageProfileRow{
		Description: req.Description,
		Base:        req.Base,
		Weights:     req.Weights,
		Thresholds:  req.Thresholds,
		SSVCMapping: ssvcMapping,
	}

	updated, err := s.store.UpdateTriageProfile(r.Context(), name, row)
	if err != nil {
		slog.Error("failed to update triage profile", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update profile")
		return
	}
	if updated == nil {
		writeError(w, http.StatusNotFound, "profile not found: "+name)
		return
	}

	writeJSON(w, http.StatusOK, formatProfileRow(updated))
}

// handleDeleteTriageProfile handles DELETE /api/v1/triage/profiles/{name}
func (s *Server) handleDeleteTriageProfile(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "profile name is required")
		return
	}

	if isBuiltinProfile(name) {
		writeError(w, http.StatusForbidden, "cannot delete built-in profile: "+name)
		return
	}

	err := s.store.DeleteTriageProfile(r.Context(), name)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "profile not found: "+name)
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete profile: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "profile deleted: " + name,
	})
}

// buildProfileFromRequest constructs a triage.Profile for validation from request data.
func buildProfileFromRequest(name, description, base string, weightsJSON, thresholdsJSON json.RawMessage, ssvcMapping map[string]string) *triage.Profile {
	var weights triage.ExtendedWeights
	if err := json.Unmarshal(weightsJSON, &weights); err != nil {
		return nil
	}

	var thresholds triage.Thresholds
	if err := json.Unmarshal(thresholdsJSON, &thresholds); err != nil {
		return nil
	}

	p := &triage.Profile{
		Name:        name,
		Description: description,
		Base:        base,
		Weights:     &weights,
		Thresholds:  &thresholds,
	}
	if len(ssvcMapping) > 0 {
		p.SSVCMapping = ssvcMapping
	}
	return p
}

// formatProfileRow converts a store.TriageProfileRow to a JSON-friendly response.
func formatProfileRow(row *store.TriageProfileRow) map[string]interface{} {
	resp := map[string]interface{}{
		"id":          row.ID,
		"name":        row.Name,
		"description": row.Description,
		"builtin":     false,
		"created_at":  row.CreatedAt.Format("2006-01-02T15:04:05Z"),
		"updated_at":  row.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}

	if row.Base != "" {
		resp["base"] = row.Base
	}
	if row.CreatedBy != nil {
		resp["created_by"] = *row.CreatedBy
	}

	var weights interface{}
	if err := json.Unmarshal(row.Weights, &weights); err == nil {
		resp["weights"] = weights
	}
	var thresholds interface{}
	if err := json.Unmarshal(row.Thresholds, &thresholds); err == nil {
		resp["thresholds"] = thresholds
	}
	if row.SSVCMapping != nil {
		var ssvc interface{}
		if err := json.Unmarshal(*row.SSVCMapping, &ssvc); err == nil {
			resp["ssvc_mapping"] = ssvc
		}
	}

	return resp
}
