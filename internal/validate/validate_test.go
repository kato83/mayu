package validate

import "testing"

func TestDateInput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid YYYY-MM-DD", "2024-01-15", false},
		{"valid RFC3339", "2024-01-15T10:30:00Z", false},
		{"valid RFC3339 with offset", "2024-01-15T10:30:00+09:00", false},
		{"invalid format", "01-15-2024", true},
		{"invalid date", "2024-13-45", true},
		{"empty string", "", true},
		{"random text", "yesterday", true},
		{"partial date", "2024-01", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DateInput(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DateInput(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
