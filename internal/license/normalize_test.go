package license

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Exact SPDX IDs
		{"MIT", "MIT"},
		{"Apache-2.0", "Apache-2.0"},
		{"BSD-3-Clause", "BSD-3-Clause"},
		{"GPL-3.0-only", "GPL-3.0-only"},

		// Case-insensitive SPDX IDs
		{"mit", "MIT"},
		{"apache-2.0", "Apache-2.0"},
		{"bsd-3-clause", "BSD-3-Clause"},
		{"ISc", "ISC"},

		// Common aliases
		{"MIT License", "MIT"},
		{"The MIT License", "MIT"},
		{"Apache License 2.0", "Apache-2.0"},
		{"Apache License, Version 2.0", "Apache-2.0"},
		{"Apache 2.0", "Apache-2.0"},
		{"BSD License", "BSD-3-Clause"},
		{"New BSD License", "BSD-3-Clause"},
		{"ISC License", "ISC"},

		// GPL aliases
		{"GNU GPL v2", "GPL-2.0-only"},
		{"GPLv2", "GPL-2.0-only"},
		{"GNU GPL v3", "GPL-3.0-only"},
		{"GPLv3", "GPL-3.0-only"},

		// Whitespace handling
		{"  MIT  ", "MIT"},
		{" Apache-2.0 ", "Apache-2.0"},

		// Empty string
		{"", ""},

		// Unknown license (returned as-is after trimming)
		{"My Custom License", "My Custom License"},
		{"PROPRIETARY", "PROPRIETARY"},

		// CC0
		{"CC0 1.0 Universal", "CC0-1.0"},
		{"Public Domain", "CC0-1.0"},

		// Unlicense
		{"The Unlicense", "Unlicense"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := Normalize(tt.input)
			if got != tt.want {
				t.Errorf("Normalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLookupSPDX(t *testing.T) {
	// Known license
	info := LookupSPDX("MIT")
	if info.SPDXID != "MIT" {
		t.Errorf("LookupSPDX(MIT).SPDXID = %q, want %q", info.SPDXID, "MIT")
	}
	if info.Category != Permissive {
		t.Errorf("LookupSPDX(MIT).Category = %q, want %q", info.Category, Permissive)
	}

	// Unknown license
	info = LookupSPDX("CustomLicense-1.0")
	if info.Category != Unknown {
		t.Errorf("LookupSPDX(CustomLicense-1.0).Category = %q, want %q", info.Category, Unknown)
	}
	if info.SPDXID != "CustomLicense-1.0" {
		t.Errorf("LookupSPDX(CustomLicense-1.0).SPDXID = %q, want %q", info.SPDXID, "CustomLicense-1.0")
	}
}
