package server

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kato83/mayu/internal/store"
)

// ogpVulnPathPattern matches /{locale}/vulnerabilities/{id} paths.
// Captures: locale (group 1), vulnerability ID (group 2).
var ogpVulnPathPattern = regexp.MustCompile(`^/([a-z]{2}(?:-[A-Za-z]+)?)/vulnerabilities/(.+)$`)

// ogpMeta holds metadata used to populate OGP meta tags.
type ogpMeta struct {
	Title       string
	Description string
	Type        string
	URL         string
}

// serveIndexWithOGP reads the index.html, replaces OGP meta tag content attributes
// with vulnerability-specific values, and writes the response.
// All values are sanitized using html/template.HTMLEscapeString to prevent XSS.
func (s *Server) serveIndexWithOGP(w http.ResponseWriter, r *http.Request, locale string, meta ogpMeta) bool {
	htmlBytes, ok := s.readIndexHTML(locale)
	if !ok {
		return false
	}

	html := string(htmlBytes)
	html = replaceMetaContent(html, `property="og:title"`, sanitizeForMeta(meta.Title))
	html = replaceMetaContent(html, `property="og:description"`, sanitizeForMeta(meta.Description))
	html = replaceMetaContent(html, `property="og:type"`, sanitizeForMeta(meta.Type))
	html = replaceMetaContent(html, `property="og:url"`, sanitizeForMeta(meta.URL))
	html = replaceMetaContent(html, `name="twitter:title"`, sanitizeForMeta(meta.Title))
	html = replaceMetaContent(html, `name="twitter:description"`, sanitizeForMeta(meta.Description))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, html)
	return true
}

// sanitizeForMeta sanitizes a string for safe inclusion in an HTML meta tag content attribute.
// It strips control characters, newlines, and then HTML-escapes the result.
func sanitizeForMeta(s string) string {
	// Strip any control characters (prevents injection via newlines, null bytes, etc.)
	s = stripControlChars(s)
	// Use Go's html/template package for safe HTML attribute escaping
	return template.HTMLEscapeString(s)
}

// stripControlChars removes ASCII control characters (0x00-0x1F, 0x7F)
// except space (0x20). This prevents meta tag injection via newlines, tabs, etc.
func stripControlChars(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= 0x20 && r != 0x7F {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// readIndexHTML reads the index.html for the given locale from uiDir or embedFS.
func (s *Server) readIndexHTML(locale string) ([]byte, bool) {
	filePath := locale + "/index.html"

	if s.uiDir != "" {
		fullPath := filepath.Join(s.uiDir, filePath)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, false
		}
		return data, true
	}

	if s.embedFS != nil {
		f, err := s.embedFS.Open(filePath)
		if err != nil {
			return nil, false
		}
		defer func() { _ = f.Close() }()

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, f); err != nil {
			return nil, false
		}
		return buf.Bytes(), true
	}

	return nil, false
}

// replaceMetaContent replaces the content attribute value in a meta tag
// identified by the given attribute selector (e.g., `property="og:title"`).
// The newContent parameter MUST already be sanitized via sanitizeForMeta.
func replaceMetaContent(html, attrSelector, newContent string) string {
	// Find the meta tag with the given attribute
	idx := strings.Index(html, attrSelector)
	if idx < 0 {
		return html
	}

	// Find the tag boundaries.
	tagStart := strings.LastIndex(html[:idx], "<meta")
	if tagStart < 0 {
		return html
	}
	tagEnd := strings.Index(html[tagStart:], ">")
	if tagEnd < 0 {
		return html
	}
	tagEnd += tagStart

	tag := html[tagStart : tagEnd+1]

	// Replace content="..." within the tag
	contentIdx := strings.Index(tag, `content="`)
	if contentIdx < 0 {
		return html
	}
	contentStart := contentIdx + len(`content="`)
	contentEnd := strings.Index(tag[contentStart:], `"`)
	if contentEnd < 0 {
		return html
	}
	contentEnd += contentStart

	newTag := tag[:contentStart] + newContent + tag[contentEnd:]
	return html[:tagStart] + newTag + html[tagEnd+1:]
}

// severityLabel converts a numeric severity level (1-5) to a human-readable label.
func severityLabel(level int) string {
	switch level {
	case 5:
		return "CRITICAL"
	case 4:
		return "HIGH"
	case 3:
		return "MEDIUM"
	case 2:
		return "LOW"
	case 1:
		return "NONE"
	default:
		return ""
	}
}

// tryServeOGP checks if the request path matches a vulnerability detail page
// and serves index.html with dynamically populated OGP meta tags.
// Returns true if the request was handled.
func (s *Server) tryServeOGP(w http.ResponseWriter, r *http.Request) bool {
	matches := ogpVulnPathPattern.FindStringSubmatch(r.URL.Path)
	if matches == nil {
		return false
	}

	locale := matches[1]
	vulnID := matches[2]

	// Decode percent-encoded vulnerability ID
	if decoded, err := url.PathUnescape(vulnID); err == nil {
		vulnID = decoded
	}

	// Check if this locale directory actually exists
	if !s.hasLocaleDir(locale) {
		return false
	}

	// Look up vulnerability info for OGP
	var vuln *store.VulnOGPMeta
	if meta, err := s.store.GetVulnOGPMeta(r.Context(), vulnID); err == nil {
		vuln = meta
	}

	// Build OGP meta
	meta := ogpMeta{
		Type: "article",
		URL:  requestURL(r),
	}

	if vuln != nil && vuln.Summary != "" {
		meta.Description = truncate(vuln.Summary, 200)
	} else {
		meta.Description = fmt.Sprintf("Vulnerability details for %s", vulnID)
	}

	// Build title with severity
	if vuln != nil && vuln.SeverityWorst > 0 {
		sev := severityLabel(vuln.SeverityWorst)
		if sev != "" {
			meta.Title = fmt.Sprintf("%s [%s] - Mayu", vulnID, sev)
		} else {
			meta.Title = fmt.Sprintf("%s - Mayu", vulnID)
		}
	} else {
		meta.Title = fmt.Sprintf("%s - Mayu", vulnID)
	}

	return s.serveIndexWithOGP(w, r, locale, meta)
}

// requestURL reconstructs the full request URL for og:url.
func requestURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
			scheme = fwd
		} else {
			scheme = "http"
		}
	}
	return scheme + "://" + r.Host + r.URL.Path
}

// truncate truncates a string to maxLen characters, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen-3]) + "..."
}
