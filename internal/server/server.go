// Package server provides an HTTP API server for the Mayu vulnerability
// intelligence tool. It exposes search and lookup endpoints that mirror
// the CLI search command functionality.
package server

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	purlpkg "github.com/kato83/mayu/internal/purl"
	"github.com/kato83/mayu/internal/store"
	"github.com/kato83/mayu/internal/validate"
)

//go:embed openapi.yaml
var openapiSpec embed.FS

// Config holds configuration for the API server.
type Config struct {
	// Addr is the address to listen on (e.g., ":8080").
	Addr string

	// Store is the vulnerability data store.
	Store store.Store

	// Version is the application version string.
	Version string
}

// Server is the HTTP API server.
type Server struct {
	httpServer *http.Server
	store      store.Store
	version    string
}

// New creates a new Server with the given configuration.
func New(cfg Config) *Server {
	s := &Server{
		store:   cfg.Store,
		version: cfg.Version,
	}

	router := s.routes()

	s.httpServer = &http.Server{
		Addr:         cfg.Addr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// routes sets up the chi router with all API endpoints.
func (s *Server) routes() http.Handler {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type"},
		ExposedHeaders:   []string{"X-Total-Count"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Health check
	r.Get("/healthz", s.handleHealthCheck)

	// OpenAPI spec
	r.Get("/openapi.yaml", s.handleOpenAPISpec)

	// API v1 routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/vulnerabilities", s.handleSearchVulnerabilities)
		r.Get("/vulnerabilities/{id}", s.handleGetVulnerability)
	})

	return r
}

// --- Handlers ---

// handleHealthCheck returns the server health status.
func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": s.version,
	})
}

// handleOpenAPISpec serves the embedded OpenAPI specification.
func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	data, err := openapiSpec.ReadFile("openapi.yaml")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read OpenAPI spec")
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleSearchVulnerabilities handles GET /api/v1/vulnerabilities
func (s *Server) handleSearchVulnerabilities(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Parse query parameters
	id := q.Get("id")
	pkg := q.Get("package")
	ecosystem := strings.TrimSpace(q.Get("ecosystem"))
	alias := q.Get("alias")
	purlStr := q.Get("purl")
	severity := q.Get("severity")
	since := q.Get("since")
	version := q.Get("version")

	// Parse limit
	limit := 20
	if l := q.Get("limit"); l != "" {
		parsed, err := strconv.Atoi(l)
		if err != nil || parsed < 1 {
			writeError(w, http.StatusBadRequest, "invalid limit parameter: must be a positive integer")
			return
		}
		if parsed > 1000 {
			parsed = 1000
		}
		limit = parsed
	}

	// Parse offset
	offset := 0
	if o := q.Get("offset"); o != "" {
		parsed, err := strconv.Atoi(o)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "invalid offset parameter: must be a non-negative integer")
			return
		}
		offset = parsed
	}

	// Validate severity
	if severity != "" {
		validSeverities := []string{"critical", "high", "medium", "low", "none"}
		valid := false
		for _, s := range validSeverities {
			if strings.ToLower(severity) == s {
				valid = true
				break
			}
		}
		if !valid {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("invalid severity %q (valid: critical, high, medium, low, none)", severity))
			return
		}
	}

	// Validate since
	if since != "" {
		if err := validate.DateInput(since); err != nil {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("invalid since parameter: %v", err))
			return
		}
	}

	// If purl is specified, parse it into package name + ecosystem
	if purlStr != "" {
		parsed, err := purlpkg.Parse(purlStr)
		if err != nil {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("invalid purl %q: %v", purlStr, err))
			return
		}
		pkg = parsed.Package
		ecosystem = parsed.Ecosystem
		if parsed.Version != "" && version == "" {
			version = parsed.Version
		}
	}

	// Validate at least one search parameter
	if id == "" && pkg == "" && ecosystem == "" && alias == "" && severity == "" && since == "" && version == "" {
		writeError(w, http.StatusBadRequest, "at least one search parameter is required")
		return
	}

	query := store.SearchQuery{
		ID:          id,
		Ecosystem:   ecosystem,
		PackageName: pkg,
		Alias:       alias,
		Severity:    severity,
		Since:       since,
		Version:     version,
		Limit:       limit,
		Offset:      offset,
	}

	ctx := r.Context()

	// Get total count
	total, err := s.store.Count(ctx, query)
	if err != nil {
		slog.Error("failed to count vulnerabilities", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Execute search
	results, err := s.store.Search(ctx, query)
	if err != nil {
		slog.Error("failed to search vulnerabilities", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Build response with raw JSON for maximum fidelity
	vulns := make([]json.RawMessage, 0, len(results))
	for _, vuln := range results {
		if vuln.RawJSON != nil {
			vulns = append(vulns, vuln.RawJSON)
		} else {
			data, err := json.Marshal(vuln)
			if err != nil {
				slog.Error("failed to marshal vulnerability", "id", vuln.ID, "error", err)
				continue
			}
			vulns = append(vulns, data)
		}
	}

	w.Header().Set("X-Total-Count", strconv.FormatInt(total, 10))
	writeJSON(w, http.StatusOK, SearchResponse{
		Vulnerabilities: vulns,
		Total:           total,
		Limit:           limit,
		Offset:          offset,
	})
}

// handleGetVulnerability handles GET /api/v1/vulnerabilities/{id}
func (s *Server) handleGetVulnerability(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "vulnerability ID is required")
		return
	}

	vuln, err := s.store.GetByID(r.Context(), id)
	if err != nil {
		slog.Error("failed to get vulnerability", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if vuln == nil {
		writeError(w, http.StatusNotFound,
			fmt.Sprintf("vulnerability %q not found", id))
		return
	}

	// Return raw JSON for maximum fidelity
	if vuln.RawJSON != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(vuln.RawJSON)
		return
	}

	writeJSON(w, http.StatusOK, vuln)
}

// --- Response types ---

// SearchResponse is the response body for vulnerability search.
type SearchResponse struct {
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	Total           int64             `json:"total"`
	Limit           int               `json:"limit"`
	Offset          int               `json:"offset"`
}

// --- Helpers ---

// writeJSON marshals v to JSON and writes it to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
