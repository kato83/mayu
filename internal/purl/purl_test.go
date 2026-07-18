package purl

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      *ParsedPURL
		wantError bool
	}{
		{
			name:  "npm scoped package",
			input: "pkg:npm/%40angular/core",
			want:  &ParsedPURL{Ecosystem: "npm", Package: "@angular/core", Version: ""},
		},
		{
			name:  "npm scoped package with encoded slash",
			input: "pkg:npm/%40angular%2Fcore",
			want:  &ParsedPURL{Ecosystem: "npm", Package: "@angular/core", Version: ""},
		},
		{
			name:  "npm scoped package with version",
			input: "pkg:npm/%40angular/core@16.0.0",
			want:  &ParsedPURL{Ecosystem: "npm", Package: "@angular/core", Version: "16.0.0"},
		},
		{
			name:  "npm unscoped package",
			input: "pkg:npm/express",
			want:  &ParsedPURL{Ecosystem: "npm", Package: "express", Version: ""},
		},
		{
			name:  "golang package",
			input: "pkg:golang/golang.org/x/crypto",
			want:  &ParsedPURL{Ecosystem: "Go", Package: "golang.org/x/crypto", Version: ""},
		},
		{
			name:  "golang stdlib",
			input: "pkg:golang/stdlib",
			want:  &ParsedPURL{Ecosystem: "Go", Package: "stdlib", Version: ""},
		},
		{
			name:  "golang package with version",
			input: "pkg:golang/golang.org/x/net@0.23.0",
			want:  &ParsedPURL{Ecosystem: "Go", Package: "golang.org/x/net", Version: "0.23.0"},
		},
		{
			name:  "golang package with subpath",
			input: "pkg:golang/github.com/example/repo#sub/path",
			want:  &ParsedPURL{Ecosystem: "Go", Package: "github.com/example/repo/sub/path", Version: ""},
		},
		{
			name:  "pypi package",
			input: "pkg:pypi/django",
			want:  &ParsedPURL{Ecosystem: "PyPI", Package: "django", Version: ""},
		},
		{
			name:  "maven package",
			input: "pkg:maven/org.apache.commons/commons-lang3",
			want:  &ParsedPURL{Ecosystem: "Maven", Package: "org.apache.commons:commons-lang3", Version: ""},
		},
		{
			name:  "gradle package maps to Maven",
			input: "pkg:gradle/org.apache.commons/commons-lang3",
			want:  &ParsedPURL{Ecosystem: "Maven", Package: "org.apache.commons:commons-lang3", Version: ""},
		},
		{
			name:  "cargo package",
			input: "pkg:cargo/serde",
			want:  &ParsedPURL{Ecosystem: "crates.io", Package: "serde", Version: ""},
		},
		{
			name:  "gem package",
			input: "pkg:gem/rails",
			want:  &ParsedPURL{Ecosystem: "RubyGems", Package: "rails", Version: ""},
		},
		{
			name:  "nuget package",
			input: "pkg:nuget/Newtonsoft.Json",
			want:  &ParsedPURL{Ecosystem: "NuGet", Package: "Newtonsoft.Json", Version: ""},
		},
		{
			name:  "composer package",
			input: "pkg:composer/laravel/framework",
			want:  &ParsedPURL{Ecosystem: "Packagist", Package: "laravel/framework", Version: ""},
		},
		{
			name:  "deb debian package",
			input: "pkg:deb/debian/curl",
			want:  &ParsedPURL{Ecosystem: "Debian", Package: "curl", Version: ""},
		},
		{
			name:  "deb ubuntu package",
			input: "pkg:deb/ubuntu/openssl",
			want:  &ParsedPURL{Ecosystem: "Ubuntu", Package: "openssl", Version: ""},
		},
		{
			name:  "apk alpine package",
			input: "pkg:apk/alpine/curl",
			want:  &ParsedPURL{Ecosystem: "Alpine", Package: "curl", Version: ""},
		},
		{
			name:  "rpm redhat package",
			input: "pkg:rpm/redhat/httpd",
			want:  &ParsedPURL{Ecosystem: "Red Hat", Package: "httpd", Version: ""},
		},
		{
			name:  "hex package",
			input: "pkg:hex/phoenix/phoenix",
			want:  &ParsedPURL{Ecosystem: "Hex", Package: "phoenix/phoenix", Version: ""},
		},
		{
			name:      "unsupported type",
			input:     "pkg:unsupported/foo",
			wantError: true,
		},
		{
			name:      "invalid purl",
			input:     "not-a-purl",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.input)
			if tt.wantError {
				if err == nil {
					t.Errorf("Parse(%q) expected error, got %+v", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.input, err)
			}
			if got.Ecosystem != tt.want.Ecosystem {
				t.Errorf("Parse(%q).Ecosystem = %q, want %q", tt.input, got.Ecosystem, tt.want.Ecosystem)
			}
			if got.Package != tt.want.Package {
				t.Errorf("Parse(%q).Package = %q, want %q", tt.input, got.Package, tt.want.Package)
			}
			if got.Version != tt.want.Version {
				t.Errorf("Parse(%q).Version = %q, want %q", tt.input, got.Version, tt.want.Version)
			}
		})
	}
}
