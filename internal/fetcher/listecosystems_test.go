package fetcher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListEcosystems(t *testing.T) {
	// Simulate ecosystems.txt with multiple ecosystems.
	ecosystemsTxt := "AlmaLinux\nAlpine\nGo\nnpm\nPyPI\nDebian\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(ecosystemsTxt))
	}))
	defer server.Close()

	f := New()

	ecosystems, err := f.listEcosystems(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("ListEcosystems failed: %v", err)
	}

	expected := []string{"AlmaLinux", "Alpine", "Go", "npm", "PyPI", "Debian"}
	if len(ecosystems) != len(expected) {
		t.Fatalf("expected %d ecosystems, got %d: %v", len(expected), len(ecosystems), ecosystems)
	}

	for i, eco := range ecosystems {
		if eco != expected[i] {
			t.Errorf("ecosystems[%d] = %q, want %q", i, eco, expected[i])
		}
	}
}

func TestListEcosystems_SkipsEmptyLines(t *testing.T) {
	// ecosystems.txt with empty lines and trailing newline.
	ecosystemsTxt := "\nGo\n\nnpm\n\nPyPI\n\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(ecosystemsTxt))
	}))
	defer server.Close()

	f := New()

	ecosystems, err := f.listEcosystems(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("ListEcosystems failed: %v", err)
	}

	expected := []string{"Go", "npm", "PyPI"}
	if len(ecosystems) != len(expected) {
		t.Fatalf("expected %d ecosystems, got %d: %v", len(expected), len(ecosystems), ecosystems)
	}

	for i, eco := range ecosystems {
		if eco != expected[i] {
			t.Errorf("ecosystems[%d] = %q, want %q", i, eco, expected[i])
		}
	}
}

func TestListEcosystems_TrimsWhitespace(t *testing.T) {
	// ecosystems.txt with leading/trailing whitespace on lines.
	ecosystemsTxt := "  Go  \n\tnpm\t\n PyPI \n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(ecosystemsTxt))
	}))
	defer server.Close()

	f := New()

	ecosystems, err := f.listEcosystems(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("ListEcosystems failed: %v", err)
	}

	expected := []string{"Go", "npm", "PyPI"}
	if len(ecosystems) != len(expected) {
		t.Fatalf("expected %d ecosystems, got %d: %v", len(expected), len(ecosystems), ecosystems)
	}

	for i, eco := range ecosystems {
		if eco != expected[i] {
			t.Errorf("ecosystems[%d] = %q, want %q", i, eco, expected[i])
		}
	}
}

func TestListEcosystems_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	f := New()

	_, err := f.listEcosystems(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for HTTP 403, got nil")
	}
}

func TestListEcosystems_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Will never respond (context should cancel)
		<-r.Context().Done()
	}))
	defer server.Close()

	f := New()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := f.listEcosystems(ctx, server.URL)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestParseEcosystemsTxt(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "normal content",
			input:    "Go\nnpm\nPyPI\n",
			expected: []string{"Go", "npm", "PyPI"},
		},
		{
			name:     "empty content",
			input:    "",
			expected: nil,
		},
		{
			name:     "only newlines",
			input:    "\n\n\n",
			expected: nil,
		},
		{
			name:     "no trailing newline",
			input:    "Go\nnpm",
			expected: []string{"Go", "npm"},
		},
		{
			name:     "with whitespace",
			input:    "  Go  \n  npm  \n",
			expected: []string{"Go", "npm"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseEcosystemsTxt([]byte(tt.input))
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d ecosystems, got %d: %v", len(tt.expected), len(result), result)
			}
			for i, eco := range result {
				if eco != tt.expected[i] {
					t.Errorf("result[%d] = %q, want %q", i, eco, tt.expected[i])
				}
			}
		})
	}
}
