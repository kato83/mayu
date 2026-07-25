package server

import "net/http"

// versionResponse is the JSON response for GET /api/v1/version.
type versionResponse struct {
	Version string `json:"version"`
}

// handleVersion handles GET /api/v1/version — returns the application version.
func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, versionResponse{
		Version: s.version,
	})
}
