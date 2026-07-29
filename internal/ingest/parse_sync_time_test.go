package ingest

import (
	"testing"
	"time"
)

func TestParseSyncTime(t *testing.T) {
	ref := time.Date(2024, 6, 15, 10, 30, 45, 0, time.UTC)

	tests := []struct {
		name    string
		input   string
		want    time.Time
		wantErr bool
	}{
		{
			name:  "RFC3339 format",
			input: "2024-06-15T10:30:45Z",
			want:  ref,
		},
		{
			name:  "RFC3339Nano format with nanoseconds",
			input: "2024-06-15T10:30:45.123456789Z",
			want:  time.Date(2024, 6, 15, 10, 30, 45, 123456789, time.UTC),
		},
		{
			name:  "RFC3339Nano format without fractional seconds",
			input: "2024-06-15T10:30:45Z",
			want:  ref,
		},
		{
			name:  "RFC3339 with timezone offset",
			input: "2024-06-15T10:30:45+00:00",
			want:  ref,
		},
		{
			name:  "RFC3339Nano with milliseconds",
			input: "2024-06-15T10:30:45.123Z",
			want:  time.Date(2024, 6, 15, 10, 30, 45, 123000000, time.UTC),
		},
		{
			name:    "invalid format",
			input:   "not-a-date",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSyncTime(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSyncTime(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !got.Equal(tt.want) {
				t.Errorf("parseSyncTime(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
