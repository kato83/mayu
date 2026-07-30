package server

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReplaceMetaContent(t *testing.T) {
	html := `<meta property="og:title" content="Default Title">`

	result := replaceMetaContent(html, `property="og:title"`, template.HTMLEscapeString("CVE-2024-1234 [CRITICAL] - Mayu"))
	expected := `<meta property="og:title" content="CVE-2024-1234 [CRITICAL] - Mayu">`
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestReplaceMetaContent_EscapesHTML(t *testing.T) {
	html := `<meta property="og:description" content="Default">`

	result := replaceMetaContent(html, `property="og:description"`, sanitizeForMeta(`<script>alert("xss")</script>`))
	// Verify the escaped content is present and properly escaped
	expected := `<meta property="og:description" content="&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;">`
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
	// Verify the content attribute value does not contain raw dangerous chars
	contentValue := extractContentAttrValue(result)
	if strings.ContainsAny(contentValue, `<>"`) {
		t.Errorf("content attribute contains unsafe chars: %q", contentValue)
	}
}

func TestReplaceMetaContent_NoMatch(t *testing.T) {
	html := `<meta property="og:title" content="Default Title">`

	result := replaceMetaContent(html, `property="og:nonexistent"`, "New Value")
	if result != html {
		t.Errorf("expected no change, got %q", result)
	}
}

func TestSanitizeForMeta_XSSVectors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"script tag", `<script>alert(1)</script>`},
		{"event handler", `" onload="alert(1)`},
		{"newline injection", "line1\nline2\r\nline3"},
		{"null byte", "before\x00after"},
		{"tab injection", "before\tafter"},
		{"closing tag", `"></meta><script>alert(1)</script><meta content="`},
		{"javascript protocol", `javascript:alert(1)`},
		{"data URI", `data:text/html,<script>alert(1)</script>`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeForMeta(tt.input)
			// Must not contain raw < > " characters (these should be escaped)
			if strings.ContainsAny(result, `<>"`) {
				t.Errorf("sanitizeForMeta(%q) = %q, contains unsafe characters", tt.input, result)
			}
			// Must not contain control characters
			for _, r := range result {
				if r < 0x20 || r == 0x7F {
					t.Errorf("sanitizeForMeta(%q) = %q, contains control char %U", tt.input, result, r)
				}
			}
		})
	}
}

func TestStripControlChars(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal text", "normal text"},
		{"with\nnewline", "withnewline"},
		{"with\ttab", "withtab"},
		{"with\x00null", "withnull"},
		{"mixed\r\n\t control", "mixed control"},
		{"日本語テスト", "日本語テスト"},
	}

	for _, tt := range tests {
		got := stripControlChars(tt.input)
		if got != tt.want {
			t.Errorf("stripControlChars(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestOgpVulnPathPattern(t *testing.T) {
	tests := []struct {
		path      string
		wantMatch bool
		locale    string
		vulnID    string
	}{
		{"/en/vulnerabilities/CVE-2024-1234", true, "en", "CVE-2024-1234"},
		{"/ja/vulnerabilities/GO-2024-2687", true, "ja", "GO-2024-2687"},
		{"/zh-Hans/vulnerabilities/GHSA-xxxx-yyyy-zzzz", true, "zh-Hans", "GHSA-xxxx-yyyy-zzzz"},
		{"/en/vulnerabilities/CVE-2024-1234/extra", true, "en", "CVE-2024-1234/extra"},
		{"/en/dashboard", false, "", ""},
		{"/vulnerabilities/CVE-2024-1234", false, "", ""},
		{"/en/", false, "", ""},
	}

	for _, tt := range tests {
		matches := ogpVulnPathPattern.FindStringSubmatch(tt.path)
		if tt.wantMatch {
			if matches == nil {
				t.Errorf("path %q: expected match, got none", tt.path)
				continue
			}
			if matches[1] != tt.locale {
				t.Errorf("path %q: locale got %q, want %q", tt.path, matches[1], tt.locale)
			}
			if matches[2] != tt.vulnID {
				t.Errorf("path %q: vulnID got %q, want %q", tt.path, matches[2], tt.vulnID)
			}
		} else {
			if matches != nil {
				t.Errorf("path %q: expected no match, got %v", tt.path, matches)
			}
		}
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly ten", 11, "exactly ten"},
		{"this is a long string that should be truncated", 20, "this is a long st..."},
		{"日本語テスト文字列", 5, "日本..."},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestSeverityLabel(t *testing.T) {
	tests := []struct {
		level int
		want  string
	}{
		{5, "CRITICAL"},
		{4, "HIGH"},
		{3, "MEDIUM"},
		{2, "LOW"},
		{1, "NONE"},
		{0, ""},
		{6, ""},
	}

	for _, tt := range tests {
		got := severityLabel(tt.level)
		if got != tt.want {
			t.Errorf("severityLabel(%d) = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestRequestURL(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		path    string
		headers map[string]string
		want    string
	}{
		{
			name: "with X-Forwarded-Proto",
			host: "example.com",
			path: "/en/vulnerabilities/CVE-2024-1234",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
			},
			want: "https://example.com/en/vulnerabilities/CVE-2024-1234",
		},
		{
			name:    "without forwarded proto (plain HTTP)",
			host:    "localhost:8080",
			path:    "/ja/vulnerabilities/GO-2024-2687",
			headers: map[string]string{},
			want:    "http://localhost:8080/ja/vulnerabilities/GO-2024-2687",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tt.path, nil)
			r.Host = tt.host
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			got := requestURL(r)
			if got != tt.want {
				t.Errorf("requestURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// extractContentAttrValue extracts the value between content="..." from a meta tag string.
func extractContentAttrValue(tag string) string {
	const marker = `content="`
	idx := strings.Index(tag, marker)
	if idx < 0 {
		return ""
	}
	start := idx + len(marker)
	end := strings.Index(tag[start:], `"`)
	if end < 0 {
		return ""
	}
	return tag[start : start+end]
}
