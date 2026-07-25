package cvss

import (
	"math"
	"testing"
)

func TestBaseSeverity(t *testing.T) {
	tests := []struct {
		name   string
		score  float64
		vector string
		want   string
	}{
		// CVSS v3.1 boundary cases
		{name: "v3.1 10.0=CRITICAL", score: 10.0, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", want: "CRITICAL"},
		{name: "v3.1 9.0=CRITICAL", score: 9.0, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", want: "CRITICAL"},
		{name: "v3.1 8.9=HIGH", score: 8.9, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", want: "HIGH"},
		{name: "v3.1 7.0=HIGH", score: 7.0, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", want: "HIGH"},
		{name: "v3.1 6.9=MEDIUM", score: 6.9, vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", want: "MEDIUM"},
		{name: "v3.1 4.0=MEDIUM", score: 4.0, vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", want: "MEDIUM"},
		{name: "v3.1 3.9=LOW", score: 3.9, vector: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", want: "LOW"},
		{name: "v3.1 0.1=LOW", score: 0.1, vector: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", want: "LOW"},
		{name: "v3.1 0.0=NONE", score: 0.0, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", want: "NONE"},

		// CVSS v4.0 boundaries
		{name: "v4.0 10.0=CRITICAL", score: 10.0, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", want: "CRITICAL"},
		{name: "v4.0 9.0=CRITICAL", score: 9.0, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", want: "CRITICAL"},
		{name: "v4.0 8.9=HIGH", score: 8.9, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", want: "HIGH"},
		{name: "v4.0 7.0=HIGH", score: 7.0, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", want: "HIGH"},
		{name: "v4.0 6.9=MEDIUM", score: 6.9, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", want: "MEDIUM"},
		{name: "v4.0 4.0=MEDIUM", score: 4.0, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", want: "MEDIUM"},
		{name: "v4.0 3.9=LOW", score: 3.9, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", want: "LOW"},
		{name: "v4.0 0.1=LOW", score: 0.1, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", want: "LOW"},
		{name: "v4.0 0.0=NONE", score: 0.0, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", want: "NONE"},

		// CVSS v2.0 boundaries (no CRITICAL level)
		{name: "v2 10.0=HIGH", score: 10.0, vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C", want: "HIGH"},
		{name: "v2 7.0=HIGH", score: 7.0, vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C", want: "HIGH"},
		{name: "v2 6.9=MEDIUM", score: 6.9, vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P", want: "MEDIUM"},
		{name: "v2 4.0=MEDIUM", score: 4.0, vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P", want: "MEDIUM"},
		{name: "v2 3.9=LOW", score: 3.9, vector: "AV:L/AC:H/Au:N/C:P/I:N/A:N", want: "LOW"},
		{name: "v2 0.1=LOW", score: 0.1, vector: "AV:L/AC:H/Au:N/C:P/I:N/A:N", want: "LOW"},
		{name: "v2 0.0=NONE", score: 0.0, vector: "AV:L/AC:H/Au:N/C:N/I:N/A:N", want: "NONE"},
		{name: "v2 parens 9.5=HIGH", score: 9.5, vector: "(AV:N/AC:L/Au:N/C:C/I:C/A:C)", want: "HIGH"},

		// Empty vector defaults to v3 thresholds
		{name: "empty vector 9.5=CRITICAL", score: 9.5, vector: "", want: "CRITICAL"},
		{name: "empty vector 7.5=HIGH", score: 7.5, vector: "", want: "HIGH"},
		{name: "empty vector 5.0=MEDIUM", score: 5.0, vector: "", want: "MEDIUM"},
		{name: "empty vector 2.0=LOW", score: 2.0, vector: "", want: "LOW"},
		{name: "empty vector 0.0=NONE", score: 0.0, vector: "", want: "NONE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BaseSeverity(tt.score, tt.vector)
			if got != tt.want {
				t.Errorf("BaseSeverity(%v, %q) = %q, want %q", tt.score, tt.vector, got, tt.want)
			}
		})
	}
}

func TestBaseScore(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   float64
		ok     bool
	}{
		// CVSS v3.1
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
			name:   "CVSS:3.1 with temporal metrics (ignored for base)",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:W/RC:R",
			want:   9.8,
			ok:     true,
		},
		// CVSS v3.0
		{
			name:   "CVSS:3.0 critical",
			vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			want:   9.8,
			ok:     true,
		},
		// CVSS v4.0
		{
			name:   "CVSS:4.0 critical",
			vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
			want:   9.3,
			ok:     true,
		},
		{
			name:   "CVSS:4.0 scope changed high",
			vector: "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H",
			want:   5.8,
			ok:     true,
		},
		{
			name:   "CVSS:4.0 low",
			vector: "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
			want:   1.0,
			ok:     true,
		},
		// CVSS v2.0
		{
			name:   "CVSS v2.0 high",
			vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C",
			want:   10.0,
			ok:     true,
		},
		{
			name:   "CVSS v2.0 with parens",
			vector: "(AV:N/AC:L/Au:N/C:P/I:P/A:P)",
			want:   7.5,
			ok:     true,
		},
		// Invalid inputs
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
			if math.Abs(got-tt.want) > 0.1 {
				t.Errorf("BaseScore(%q) = %.1f, want %.1f", tt.vector, got, tt.want)
			}
		})
	}
}
