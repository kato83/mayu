package fetcher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchGitHubAdvisories(t *testing.T) {
	// Create mock advisories
	advisories := []map[string]interface{}{
		{
			"ghsa_id":     "GHSA-1234-5678-9012",
			"cve_id":      "CVE-2024-12345",
			"summary":     "Test advisory 1",
			"description": "A test advisory",
			"severity":    "high",
			"state":       "published",
			"identifiers": []map[string]string{
				{"type": "GHSA", "value": "GHSA-1234-5678-9012"},
				{"type": "CVE", "value": "CVE-2024-12345"},
			},
			"vulnerabilities": []map[string]interface{}{
				{
					"package": map[string]string{
						"ecosystem": "composer",
						"name":      "test/package",
					},
					"vulnerable_version_range": ">= 1.0.0, < 1.0.5",
					"patched_versions":         "1.0.5",
				},
			},
		},
		{
			"ghsa_id":     "GHSA-abcd-efgh-ijkl",
			"cve_id":      "CVE-2024-67890",
			"summary":     "Test advisory 2",
			"description": "Another test advisory",
			"severity":    "critical",
			"state":       "published",
			"identifiers": []map[string]string{
				{"type": "GHSA", "value": "GHSA-abcd-efgh-ijkl"},
				{"type": "CVE", "value": "CVE-2024-67890"},
			},
			"vulnerabilities": []map[string]interface{}{},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request
		if r.URL.Path != "/repos/WordPress/wordpress-develop/security-advisories" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}

		// Verify query parameters
		q := r.URL.Query()
		if q.Get("state") != "published" {
			t.Errorf("expected state=published, got %s", q.Get("state"))
		}
		if q.Get("per_page") != "100" {
			t.Errorf("expected per_page=100, got %s", q.Get("per_page"))
		}

		// Verify headers
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("unexpected Accept header: %s", r.Header.Get("Accept"))
		}
		if r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Errorf("unexpected API version: %s", r.Header.Get("X-GitHub-Api-Version"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(advisories)
	}))
	defer server.Close()

	// Patch the base URL in FetchGitHubAdvisories by using a custom fetcher
	// that overrides the URL construction
	f := New(WithHTTPClient(server.Client()))

	// We need to override GitHubAPIBaseURL for testing.
	// Use fetchGHSAPage directly with the test server URL.
	url := server.URL + "/repos/WordPress/wordpress-develop/security-advisories?state=published&per_page=100&sort=updated&direction=desc"
	results, next, err := f.fetchGHSAPage(context.Background(), url, "")
	if err != nil {
		t.Fatalf("fetchGHSAPage: %v", err)
	}

	if next != "" {
		t.Errorf("expected no next page, got %q", next)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 advisories, got %d", len(results))
	}

	// Verify the first advisory can be parsed back
	var adv1 map[string]interface{}
	if err := json.Unmarshal(results[0], &adv1); err != nil {
		t.Fatalf("unmarshal advisory 1: %v", err)
	}
	if adv1["ghsa_id"] != "GHSA-1234-5678-9012" {
		t.Errorf("unexpected ghsa_id: %v", adv1["ghsa_id"])
	}
}

func TestFetchGitHubAdvisoriesPagination(t *testing.T) {
	page := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		w.Header().Set("Content-Type", "application/json")

		if page == 1 {
			// First page: include Link header pointing to next page
			nextURL := "http://" + r.Host + "/repos/owner/repo/security-advisories?state=published&per_page=100&after=cursor123"
			w.Header().Set("Link", `<`+nextURL+`>; rel="next"`)
			advisories := []map[string]interface{}{
				{"ghsa_id": "GHSA-page1-0001", "state": "published", "identifiers": []map[string]string{}},
			}
			_ = json.NewEncoder(w).Encode(advisories)
		} else {
			// Second page: no Link header (last page)
			advisories := []map[string]interface{}{
				{"ghsa_id": "GHSA-page2-0001", "state": "published", "identifiers": []map[string]string{}},
			}
			_ = json.NewEncoder(w).Encode(advisories)
		}
	}))
	defer server.Close()

	f := New(WithHTTPClient(server.Client()))

	// Start from page 1
	url := server.URL + "/repos/owner/repo/security-advisories?state=published&per_page=100&sort=updated&direction=desc"
	results1, next, err := f.fetchGHSAPage(context.Background(), url, "")
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(results1) != 1 {
		t.Fatalf("page 1: expected 1 advisory, got %d", len(results1))
	}
	if next == "" {
		t.Fatal("page 1: expected next page URL")
	}

	// Fetch page 2
	results2, next2, err := f.fetchGHSAPage(context.Background(), next, "")
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(results2) != 1 {
		t.Fatalf("page 2: expected 1 advisory, got %d", len(results2))
	}
	if next2 != "" {
		t.Errorf("page 2: expected no next page, got %q", next2)
	}
}

func TestFetchGitHubAdvisoriesWithToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token-123" {
			t.Errorf("expected Bearer token, got %q", auth)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer server.Close()

	f := New(WithHTTPClient(server.Client()))

	url := server.URL + "/repos/owner/repo/security-advisories?state=published&per_page=100"
	_, _, err := f.fetchGHSAPage(context.Background(), url, "test-token-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchGitHubAdvisoriesValidation(t *testing.T) {
	f := New()

	_, err := f.FetchGitHubAdvisories(context.Background(), "", "repo", "")
	if err == nil || err.Error() != "owner must not be empty" {
		t.Errorf("expected owner validation error, got: %v", err)
	}

	_, err = f.FetchGitHubAdvisories(context.Background(), "owner", "", "")
	if err == nil || err.Error() != "repo must not be empty" {
		t.Errorf("expected repo validation error, got: %v", err)
	}
}

func TestExtractNextLink(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "empty",
			header: "",
			want:   "",
		},
		{
			name:   "next only",
			header: `<https://api.github.com/repos/owner/repo/security-advisories?after=abc123>; rel="next"`,
			want:   "https://api.github.com/repos/owner/repo/security-advisories?after=abc123",
		},
		{
			name:   "prev and next",
			header: `<https://api.github.com/repos/owner/repo/security-advisories?before=xyz>; rel="prev", <https://api.github.com/repos/owner/repo/security-advisories?after=abc>; rel="next"`,
			want:   "https://api.github.com/repos/owner/repo/security-advisories?after=abc",
		},
		{
			name:   "last only (no next)",
			header: `<https://api.github.com/repos/owner/repo/security-advisories?before=xyz>; rel="prev"`,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNextLink(tt.header)
			if got != tt.want {
				t.Errorf("extractNextLink(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestFetchGitHubAdvisoriesHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message": "Not Found"}`))
	}))
	defer server.Close()

	f := New(WithHTTPClient(server.Client()))

	url := server.URL + "/repos/nonexistent/repo/security-advisories?state=published&per_page=100"
	_, _, err := f.fetchGHSAPage(context.Background(), url, "")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	if !contains(err.Error(), "status 404") {
		t.Errorf("expected 404 in error message, got: %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
