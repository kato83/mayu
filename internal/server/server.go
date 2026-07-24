// Package server provides an HTTP API server for the Mayu vulnerability
// intelligence tool. It exposes search and lookup endpoints that mirror
// the CLI search command functionality.
package server

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/model"
	purlpkg "github.com/kato83/mayu/internal/purl"
	"github.com/kato83/mayu/internal/store"
	"github.com/kato83/mayu/internal/validate"
	"golang.org/x/sync/errgroup"
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

	// UIDir is the path to the SPA static files directory.
	// If empty, no static file serving is configured (unless EmbedFS is set).
	UIDir string

	// EmbedFS is an embedded filesystem containing SPA static files.
	// Used when the binary is built with UI assets embedded.
	// UIDir takes precedence over EmbedFS when both are set.
	EmbedFS fs.FS

	// Fetcher is the data fetcher for ingest operations.
	// If nil, the ingest endpoint is not registered.
	Fetcher *fetcher.Fetcher
}

// Server is the HTTP API server.
type Server struct {
	httpServer    *http.Server
	store         store.Store
	version       string
	uiDir         string
	embedFS       fs.FS
	fetcher       *fetcher.Fetcher
	ingestRunning atomic.Bool
	runners       activeRunners
}

// New creates a new Server with the given configuration.
func New(cfg Config) *Server {
	s := &Server{
		store:   cfg.Store,
		version: cfg.Version,
		uiDir:   cfg.UIDir,
		embedFS: cfg.EmbedFS,
		fetcher: cfg.Fetcher,
	}

	router := s.routes()

	s.httpServer = &http.Server{
		Addr:         cfg.Addr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // Disabled for SSE streaming (ingest progress)
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
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type"},
		ExposedHeaders:   []string{"X-Total-Count"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Health check
	r.Get("/healthz", s.handleHealthCheck)

	// OpenAPI spec
	r.Get("/openapi.yaml", s.handleOpenAPISpec)

	// Swagger UI (Scalar)
	r.Get("/swagger", s.handleSwaggerUI)

	// API v1 routes (with 30s timeout)
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(middleware.Timeout(30 * time.Second))
		r.Get("/vulnerabilities", s.handleSearchVulnerabilities)
		r.Get("/vulnerabilities/{id}", s.handleGetVulnerability)
		r.Get("/ecosystems", s.handleListEcosystems)
		r.Get("/status", s.handleStatus)
	})

	// Ingest endpoints
	r.Route("/api/v1/ingest", func(r chi.Router) {
		// Job history endpoints (with standard timeout)
		r.With(middleware.Timeout(30*time.Second)).Get("/jobs", s.handleListIngestJobs)
		r.With(middleware.Timeout(30*time.Second)).Get("/jobs/{id}", s.handleGetIngestJob)

		// SSE stream for job progress — no timeout (long-lived connection)
		r.Get("/jobs/{id}/stream", s.handleIngestJobStream)

		// Ingest trigger — returns immediately with job ID
		if s.fetcher != nil {
			r.With(middleware.Timeout(30*time.Second)).Post("/", s.handleIngest)
		}
	})

	// SPA static file serving with fallback to index.html
	if s.uiDir != "" || s.embedFS != nil {
		r.Get("/*", s.handleSPA)
	}

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

// handleSwaggerUI serves an interactive API documentation page using Scalar.
func (s *Server) handleSwaggerUI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
  <title>Mayu API Reference</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
  <script id="api-reference" data-url="/openapi.yaml"></script>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>`))
}

// handleSearchVulnerabilities handles GET /api/v1/vulnerabilities
func (s *Server) handleSearchVulnerabilities(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Parse query parameters
	id := q.Get("id")
	pkg := q.Get("package")
	ecosystem := strings.TrimSpace(q.Get("ecosystem"))
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

	// Parse cursor (takes precedence over offset when set)
	cursor := q.Get("cursor")
	if cursor != "" {
		if _, err := store.DecodeCursor(cursor); err != nil {
			writeError(w, http.StatusBadRequest, "invalid cursor parameter")
			return
		}
	}

	// Validate severity
	if severity != "" {
		validSeverities := []string{"critical", "high", "medium", "low", "none", "unknown"}
		valid := false
		for _, s := range validSeverities {
			if strings.ToLower(severity) == s {
				valid = true
				break
			}
		}
		if !valid {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("invalid severity %q (valid: critical, high, medium, low, none, unknown)", severity))
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

	// Parse fields parameter (comma-separated list of field names)
	var fields []string
	if f := q.Get("fields"); f != "" {
		validFields := map[string]bool{
			"id": true, "summary": true, "modified": true,
			"severity": true, "ecosystem": true,
		}
		for _, field := range strings.Split(f, ",") {
			field = strings.TrimSpace(strings.ToLower(field))
			if field == "" {
				continue
			}
			if !validFields[field] {
				writeError(w, http.StatusBadRequest,
					fmt.Sprintf("invalid field %q (valid: id, summary, modified, severity, ecosystem)", field))
				return
			}
			fields = append(fields, field)
		}
	}

	query := store.SearchQuery{
		ID:          id,
		Ecosystem:   ecosystem,
		PackageName: pkg,
		Severity:    severity,
		Since:       since,
		Version:     version,
		Limit:       limit,
		Offset:      offset,
		Cursor:      cursor,
		Fields:      fields,
	}

	// Sort parameter
	if sortParam := q.Get("sort"); sortParam != "" {
		validSorts := map[string]bool{
			"modified_desc": true, "modified_asc": true,
			"published_desc": true, "published_asc": true,
		}
		if !validSorts[sortParam] {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("invalid sort %q (valid: modified_desc, modified_asc, published_desc, published_asc)", sortParam))
			return
		}
		query.Sort = sortParam
	}

	// KEV filter
	if kevStr := q.Get("kev"); kevStr == "true" {
		t := true
		query.InKEV = &t
	}

	ctx := r.Context()

	// Execute count and search in parallel
	var total int64
	var results []*model.Vulnerability

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		var err error
		total, err = s.store.Count(gCtx, query)
		return err
	})

	g.Go(func() error {
		var err error
		results, err = s.store.Search(gCtx, query)
		return err
	})

	if err := g.Wait(); err != nil {
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

	// Compute next_cursor from the last result item
	var nextCursor string
	if len(results) == limit {
		last := results[len(results)-1]
		nextCursor = store.EncodeCursor(last.Published, last.ID)
	}

	w.Header().Set("X-Total-Count", strconv.FormatInt(total, 10))
	writeJSON(w, http.StatusOK, SearchResponse{
		Vulnerabilities: vulns,
		Total:           total,
		Limit:           limit,
		Offset:          offset,
		NextCursor:      nextCursor,
	})
}

// handleGetVulnerability handles GET /api/v1/vulnerabilities/{id}
func (s *Server) handleGetVulnerability(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "vulnerability ID is required")
		return
	}

	// If ?detail=true, return enriched vulnerability data from all sources
	if r.URL.Query().Get("detail") == "true" {
		detail, err := s.store.GetVulnerabilityDetail(r.Context(), id)
		if err != nil {
			slog.Error("failed to get vulnerability detail", "id", id, "error", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if detail == nil {
			writeError(w, http.StatusNotFound,
				fmt.Sprintf("vulnerability %q not found", id))
			return
		}
		writeJSON(w, http.StatusOK, detail)
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
	NextCursor      string            `json:"next_cursor,omitempty"`
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

// handleSPA serves static files from the UI directory with SPA fallback.
// Structure: ui-dir/{locale}/index.html, ui-dir/{locale}/*.js, etc.
// - GET / → redirect to /{locale}/ based on Accept-Language
// - GET /{locale}/assets/foo.js → serve file directly
// - GET /{locale}/any/spa/route → serve /{locale}/index.html
func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	reqPath := strings.TrimPrefix(filepath.Clean(r.URL.Path), "/")

	// Root: redirect to locale
	if reqPath == "" || reqPath == "." {
		locale := s.detectLocale(r)
		http.Redirect(w, r, "/"+locale+"/", http.StatusFound)
		return
	}

	// Try serving the file directly
	if s.serveStaticFile(w, r, reqPath) {
		return
	}

	// SPA fallback: serve {first-segment}/index.html
	locale := reqPath
	if idx := strings.IndexByte(reqPath, '/'); idx >= 0 {
		locale = reqPath[:idx]
	}
	if s.serveStaticFile(w, r, locale+"/index.html") {
		return
	}

	http.NotFound(w, r)
}

// serveStaticFile tries to serve a file at the given path.
// It checks uiDir first (filesystem), then embedFS.
// Returns true if the file was served.
func (s *Server) serveStaticFile(w http.ResponseWriter, r *http.Request, filePath string) bool {
	// Priority 1: filesystem (--ui-dir)
	if s.uiDir != "" {
		fullPath := filepath.Join(s.uiDir, filePath)
		if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
			http.ServeFile(w, r, fullPath)
			return true
		}
	}

	// Priority 2: embedded FS
	if s.embedFS != nil {
		f, err := s.embedFS.Open(filePath)
		if err != nil {
			return false
		}
		defer func() { _ = f.Close() }()

		stat, err := f.Stat()
		if err != nil || stat.IsDir() {
			return false
		}

		// embed.FS files implement io.ReadSeeker
		seeker, ok := f.(readSeeker)
		if !ok {
			return false
		}
		http.ServeContent(w, r, stat.Name(), stat.ModTime(), seeker)
		return true
	}

	return false
}

// readSeeker combines io.Reader and io.Seeker for http.ServeContent.
type readSeeker interface {
	Read(p []byte) (n int, err error)
	Seek(offset int64, whence int) (int64, error)
}

// hasLocaleDir checks if a locale directory exists (filesystem or embedFS).
func (s *Server) hasLocaleDir(locale string) bool {
	if s.uiDir != "" {
		info, err := os.Stat(filepath.Join(s.uiDir, locale))
		return err == nil && info.IsDir()
	}
	if s.embedFS != nil {
		f, err := s.embedFS.Open(locale)
		if err != nil {
			return false
		}
		defer func() { _ = f.Close() }()
		stat, err := f.Stat()
		return err == nil && stat.IsDir()
	}
	return false
}

// detectLocale determines the preferred locale from the Accept-Language header.
// Returns the best matching locale directory that exists under uiDir/embedFS.
// Falls back to "en" if no match is found.
func (s *Server) detectLocale(r *http.Request) string {
	acceptLang := r.Header.Get("Accept-Language")
	if acceptLang == "" {
		return "en"
	}

	// Parse Accept-Language and find the best match among available locale dirs
	locales := parseAcceptLanguage(acceptLang)
	for _, lang := range locales {
		// Check exact match (e.g., "ja", "en")
		if s.hasLocaleDir(lang) {
			return lang
		}
		// Check base language (e.g., "ja-JP" → "ja")
		if idx := strings.IndexAny(lang, "-_"); idx > 0 {
			base := lang[:idx]
			if s.hasLocaleDir(base) {
				return base
			}
		}
	}

	return "en"
}

// parseAcceptLanguage parses the Accept-Language header and returns languages
// sorted by quality (highest first). Example: "ja,en-US;q=0.9,en;q=0.8"
func parseAcceptLanguage(header string) []string {
	type langQ struct {
		lang string
		q    float64
	}

	var langs []langQ
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		lang := part
		q := 1.0

		if idx := strings.Index(part, ";"); idx >= 0 {
			lang = strings.TrimSpace(part[:idx])
			qPart := strings.TrimSpace(part[idx+1:])
			if strings.HasPrefix(qPart, "q=") {
				if parsed, err := strconv.ParseFloat(qPart[2:], 64); err == nil {
					q = parsed
				}
			}
		}

		if lang != "" && lang != "*" {
			langs = append(langs, langQ{lang: strings.ToLower(lang), q: q})
		}
	}

	// Sort by quality descending
	for i := range langs {
		for j := i + 1; j < len(langs); j++ {
			if langs[j].q > langs[i].q {
				langs[i], langs[j] = langs[j], langs[i]
			}
		}
	}

	result := make([]string, len(langs))
	for i, l := range langs {
		result[i] = l.lang
	}
	return result
}

// handleListEcosystems returns all known OSV ecosystem names sorted alphabetically.
func (s *Server) handleListEcosystems(w http.ResponseWriter, r *http.Request) {
	ecosystems, err := s.store.ListOSVEcosystems(r.Context())
	if err != nil {
		slog.Error("failed to list ecosystems", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if ecosystems == nil {
		ecosystems = []string{}
	}
	writeJSON(w, http.StatusOK, map[string][]string{"ecosystems": ecosystems})
}
