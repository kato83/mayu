package cvss

import (
	"math"
	"testing"
)

func TestBaseScore(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   float64
		ok     bool
	}{
		{
			name:   "CVSS:3.1 critical (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			want:   9.8,
			ok:     true,
		},
		{
			name:   "CVSS:3.1 high (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			want:   7.5,
			ok:     true,
		},
		{
			name:   "CVSS:3.1 medium (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N)",
			vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
			want:   5.4,
			ok:     true,
		},
		{
			name:   "CVSS:3.1 low (AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N)",
			vector: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
			want:   1.8,
			ok:     true,
		},
		{
			name:   "CVSS:3.1 scope changed critical",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			want:   10.0,
			ok:     true,
		},
		{
			name:   "CVSS:3.0 same formula",
			vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			want:   9.8,
			ok:     true,
		},
		{
			name:   "CVSS:3.1 all none (zero impact)",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			want:   0.0,
			ok:     true,
		},
		{
			name:   "CVSS:3.1 scope changed medium",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			want:   6.1,
			ok:     true,
		},
		{
			name:   "empty string",
			vector: "",
			want:   0,
			ok:     false,
		},
		{
			name:   "plain numeric (not a vector)",
			vector: "9.8",
			want:   0,
			ok:     false,
		},
		{
			name:   "CVSS v4 not supported",
			vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
			want:   0,
			ok:     false,
		},
		{
			name:   "invalid metric value",
			vector: "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			want:   0,
			ok:     false,
		},
		{
			name:   "missing required metric",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
			want:   0,
			ok:     false,
		},
		{
			name:   "with temporal metrics (ignored)",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:W/RC:R",
			want:   9.8,
			ok:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := BaseScore(tt.vector)
			if ok != tt.ok {
				t.Fatalf("BaseScore(%q) ok = %v, want %v", tt.vector, ok, tt.ok)
			}
			if !tt.ok {
				return
			}
			if math.Abs(got-tt.want) > 0.05 {
				t.Errorf("BaseScore(%q) = %.1f, want %.1f", tt.vector, got, tt.want)
			}
		})
	}
}

func TestRoundUp(t *testing.T) {
	tests := []struct {
		input float64
		want  float64
	}{
		{0.0, 0.0},
		{0.1, 0.1},
		{0.11, 0.2},
		{0.15, 0.2},
		{9.79, 9.8},
		{9.80, 9.8},
		{9.81, 9.9},
		{10.0, 10.0},
	}

	for _, tt := range tests {
		got := roundUp(tt.input)
		if math.Abs(got-tt.want) > 0.001 {
			t.Errorf("roundUp(%v) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
