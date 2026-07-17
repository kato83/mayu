package main

import (
	"testing"
	"unicode/utf8"
)

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxRunes int
		want     string
	}{
		{"short ascii", "hello", 40, "hello"},
		{"exact length", "12345", 5, "12345"},
		{"truncate ascii", "abcdefghij", 8, "abcde..."},
		{"multibyte japanese", "これは日本語の脆弱性の要約テキストです", 10, "これは日本語の..."},
		{"multibyte exact", "あいうえお", 5, "あいうえお"},
		{"very small max", "hello", 2, "..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateString(tt.input, tt.maxRunes)
			if got != tt.want {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxRunes, got, tt.want)
			}
			// The result must always be valid UTF-8 (the core of the L-4 fix).
			if !utf8.ValidString(got) {
				t.Errorf("truncateString(%q, %d) produced invalid UTF-8: %q", tt.input, tt.maxRunes, got)
			}
			// The result must not exceed maxRunes runes.
			if n := utf8.RuneCountInString(got); n > tt.maxRunes && tt.maxRunes > 3 {
				t.Errorf("truncateString(%q, %d) returned %d runes, exceeds max", tt.input, tt.maxRunes, n)
			}
		})
	}
}

func TestIsLocalHost(t *testing.T) {
	local := []string{"", "localhost", "127.0.0.1", "::1"}
	for _, h := range local {
		if !isLocalHost(h) {
			t.Errorf("isLocalHost(%q) = false, want true", h)
		}
	}
	remote := []string{"db.example.com", "10.0.0.5", "192.168.1.1", "example.org"}
	for _, h := range remote {
		if isLocalHost(h) {
			t.Errorf("isLocalHost(%q) = true, want false", h)
		}
	}
}

func TestIsInsecureRemoteURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"local disable is fine", "postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable", false},
		{"local no sslmode is fine", "postgres://mayu:mayu@127.0.0.1:5432/mayu", false},
		{"remote disable is insecure", "postgres://u:p@db.example.com:5432/mayu?sslmode=disable", true},
		{"remote no sslmode is insecure", "postgres://u:p@db.example.com:5432/mayu", true},
		{"remote prefer is insecure", "postgres://u:p@db.example.com:5432/mayu?sslmode=prefer", true},
		{"remote require is fine", "postgres://u:p@db.example.com:5432/mayu?sslmode=require", false},
		{"remote verify-full is fine", "postgres://u:p@db.example.com:5432/mayu?sslmode=verify-full", false},
		{"unparseable is ignored", "://not a url", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, _ := isInsecureRemoteURL(tt.url)
			if got != tt.want {
				t.Errorf("isInsecureRemoteURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}
