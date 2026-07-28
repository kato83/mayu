package fetcher

import "testing"

func TestCvelistV5URL(t *testing.T) {
	tests := []struct {
		cveID   string
		want    string
		wantErr bool
	}{
		{
			cveID: "CVE-2026-52101",
			want:  "https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/2026/52xxx/CVE-2026-52101.json",
		},
		{
			cveID: "CVE-2024-1234",
			want:  "https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/2024/1xxx/CVE-2024-1234.json",
		},
		{
			cveID: "CVE-2023-12345",
			want:  "https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/2023/12xxx/CVE-2023-12345.json",
		},
		{
			cveID: "CVE-2024-123",
			want:  "https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/2024/0xxx/CVE-2024-123.json",
		},
		{
			cveID:   "GHSA-xxxx-yyyy-zzzz",
			wantErr: true,
		},
		{
			cveID:   "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.cveID, func(t *testing.T) {
			got, err := cvelistV5URL(tt.cveID)
			if tt.wantErr {
				if err == nil {
					t.Errorf("cvelistV5URL(%q) expected error, got %q", tt.cveID, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("cvelistV5URL(%q) unexpected error: %v", tt.cveID, err)
			}
			if got != tt.want {
				t.Errorf("cvelistV5URL(%q) = %q, want %q", tt.cveID, got, tt.want)
			}
		})
	}
}
