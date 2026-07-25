package store

import (
	"testing"
)

func TestSanitizeJSONB(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no null bytes",
			input: `{"key": "value"}`,
			want:  `{"key": "value"}`,
		},
		{
			name:  "single null byte escape",
			input: `{"key": "before\u0000after"}`,
			want:  `{"key": "beforeafter"}`,
		},
		{
			name:  "multiple null byte escapes",
			input: `{"a": "\u0000", "b": "x\u0000y\u0000z"}`,
			want:  `{"a": "", "b": "xyz"}`,
		},
		{
			name:  "other unicode escapes preserved",
			input: `{"key": "\u0041\u0042"}`,
			want:  `{"key": "\u0041\u0042"}`,
		},
		{
			name:  "empty input",
			input: "",
			want:  "",
		},
		{
			name:  "null byte at start",
			input: `\u0000{"key": "val"}`,
			want:  `{"key": "val"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(sanitizeJSONB([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("sanitizeJSONB(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeJSONB_NilInput(t *testing.T) {
	got := sanitizeJSONB(nil)
	if got != nil {
		t.Errorf("sanitizeJSONB(nil) = %v, want nil", got)
	}
}
