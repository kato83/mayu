package parser

import (
	"testing"
	"time"
)

func TestParseNVDSources(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantLen int
		wantErr bool
	}{
		{
			name:    "empty data",
			input:   nil,
			wantLen: 0,
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			input:   []byte(`{invalid`),
			wantLen: 0,
			wantErr: true,
		},
		{
			name: "single source with one identifier",
			input: []byte(`{
				"totalResults": 1,
				"sources": [
					{
						"name": "kernel.org",
						"contactEmail": "cve@kernel.org",
						"sourceIdentifiers": ["416baaa9-dc9f-4396-8d5f-8c081fb06d67"],
						"lastModified": "2024-02-20T13:15:08.140",
						"created": "2024-02-20T13:15:08.140",
						"v3AcceptanceLevel": {"description": "Contributor", "lastModified": "2024-02-20T13:15:08.140"}
					}
				]
			}`),
			wantLen: 1,
			wantErr: false,
		},
		{
			name: "source with multiple identifiers",
			input: []byte(`{
				"totalResults": 1,
				"sources": [
					{
						"name": "MITRE Corporation",
						"contactEmail": "cve@mitre.org",
						"sourceIdentifiers": ["cve@mitre.org", "8254265b-2729-46b6-b9e3-3dfca2d5bfca"],
						"lastModified": "2024-01-15T10:00:00.000",
						"created": "2020-01-01T00:00:00.000"
					}
				]
			}`),
			wantLen: 2,
			wantErr: false,
		},
		{
			name: "multiple sources",
			input: []byte(`{
				"totalResults": 2,
				"sources": [
					{
						"name": "kernel.org",
						"contactEmail": "cve@kernel.org",
						"sourceIdentifiers": ["416baaa9-dc9f-4396-8d5f-8c081fb06d67"],
						"lastModified": "2024-02-20T13:15:08.140",
						"created": "2024-02-20T13:15:08.140"
					},
					{
						"name": "CISA-ADP",
						"contactEmail": "",
						"sourceIdentifiers": ["134c704f-9b21-4f2e-91b3-4a467353bcc0"],
						"lastModified": "2024-03-01T00:00:00.000",
						"created": "2024-03-01T00:00:00.000",
						"v3AcceptanceLevel": {"description": "Provider", "lastModified": "2024-03-01T00:00:00.000"}
					}
				]
			}`),
			wantLen: 2,
			wantErr: false,
		},
		{
			name: "source with no acceptance level",
			input: []byte(`{
				"totalResults": 1,
				"sources": [
					{
						"name": "Example Org",
						"sourceIdentifiers": ["test-uuid-1234"]
					}
				]
			}`),
			wantLen: 1,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			got, err := p.ParseNVDSources(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseNVDSources() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if len(got) != tt.wantLen {
				t.Errorf("ParseNVDSources() returned %d entries, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestParseNVDSourcesFields(t *testing.T) {
	input := []byte(`{
		"totalResults": 1,
		"sources": [
			{
				"name": "kernel.org",
				"contactEmail": "cve@kernel.org",
				"sourceIdentifiers": ["416baaa9-dc9f-4396-8d5f-8c081fb06d67"],
				"lastModified": "2024-02-20T13:15:08.140",
				"created": "2024-02-20T13:15:08.140",
				"v3AcceptanceLevel": {"description": "Contributor", "lastModified": "2024-02-20T13:15:08.140"}
			}
		]
	}`)

	p := New()
	sources, err := p.ParseNVDSources(input)
	if err != nil {
		t.Fatalf("ParseNVDSources() error = %v", err)
	}

	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(sources))
	}

	s := sources[0]
	if s.Name != "kernel.org" {
		t.Errorf("Name = %q, want %q", s.Name, "kernel.org")
	}
	if s.ContactEmail != "cve@kernel.org" {
		t.Errorf("ContactEmail = %q, want %q", s.ContactEmail, "cve@kernel.org")
	}
	if s.SourceIdentifier != "416baaa9-dc9f-4396-8d5f-8c081fb06d67" {
		t.Errorf("SourceIdentifier = %q, want %q", s.SourceIdentifier, "416baaa9-dc9f-4396-8d5f-8c081fb06d67")
	}
	if s.AcceptanceLevel != "Contributor" {
		t.Errorf("AcceptanceLevel = %q, want %q", s.AcceptanceLevel, "Contributor")
	}
	if s.LastModified == nil {
		t.Fatal("LastModified is nil")
	}
	expected := time.Date(2024, 2, 20, 13, 15, 8, 140000000, time.UTC)
	if !s.LastModified.Equal(expected) {
		t.Errorf("LastModified = %v, want %v", s.LastModified, expected)
	}
	if s.CreatedAt == nil {
		t.Fatal("CreatedAt is nil")
	}
	if !s.CreatedAt.Equal(expected) {
		t.Errorf("CreatedAt = %v, want %v", s.CreatedAt, expected)
	}
}

func TestParseNVDSourcesMultipleIdentifiers(t *testing.T) {
	input := []byte(`{
		"totalResults": 1,
		"sources": [
			{
				"name": "MITRE Corporation",
				"contactEmail": "cve@mitre.org",
				"sourceIdentifiers": ["cve@mitre.org", "8254265b-2729-46b6-b9e3-3dfca2d5bfca"],
				"lastModified": "2024-01-15T10:00:00.000",
				"created": "2020-01-01T00:00:00.000"
			}
		]
	}`)

	p := New()
	sources, err := p.ParseNVDSources(input)
	if err != nil {
		t.Fatalf("ParseNVDSources() error = %v", err)
	}

	if len(sources) != 2 {
		t.Fatalf("expected 2 sources (one per identifier), got %d", len(sources))
	}

	// Both entries should have the same name and email
	for _, s := range sources {
		if s.Name != "MITRE Corporation" {
			t.Errorf("Name = %q, want %q", s.Name, "MITRE Corporation")
		}
		if s.ContactEmail != "cve@mitre.org" {
			t.Errorf("ContactEmail = %q, want %q", s.ContactEmail, "cve@mitre.org")
		}
	}

	// Check identifiers
	ids := map[string]bool{
		sources[0].SourceIdentifier: true,
		sources[1].SourceIdentifier: true,
	}
	if !ids["cve@mitre.org"] {
		t.Error("missing identifier cve@mitre.org")
	}
	if !ids["8254265b-2729-46b6-b9e3-3dfca2d5bfca"] {
		t.Error("missing identifier 8254265b-2729-46b6-b9e3-3dfca2d5bfca")
	}
}
