package score

import (
	"math"
	"testing"
	"time"
)

func float64Ptr(f float64) *float64 { return &f }

func TestCompute(t *testing.T) {
	weights := DefaultWeights()

	tests := []struct {
		name    string
		input   Input
		weights Weights
		wantMin float64
		wantMax float64
	}{
		{
			name: "all signals maximum risk",
			input: Input{
				CVSSScore:      float64Ptr(10.0),
				EPSSScore:      float64Ptr(1.0),
				LEVScore:       float64Ptr(1.0),
				InKEV:          true,
				PatchAvailable: false,
				PublishedAt:    time.Now().Add(-3 * 365 * 24 * time.Hour), // 3 years ago
			},
			weights: weights,
			wantMin: 0.95,
			wantMax: 1.0,
		},
		{
			name: "all signals minimum risk",
			input: Input{
				CVSSScore:      float64Ptr(0.0),
				EPSSScore:      float64Ptr(0.0),
				LEVScore:       float64Ptr(0.0),
				InKEV:          false,
				PatchAvailable: true,
				PublishedAt:    time.Now(), // just published
			},
			weights: weights,
			wantMin: 0.0,
			wantMax: 0.01,
		},
		{
			name: "critical CVSS only, other signals missing",
			input: Input{
				CVSSScore:      float64Ptr(9.8),
				EPSSScore:      nil,
				LEVScore:       nil,
				InKEV:          false,
				PatchAvailable: true,
				PublishedAt:    time.Time{}, // unknown
			},
			weights: weights,
			wantMin: 0.3,
			wantMax: 0.7,
		},
		{
			name: "high EPSS with medium CVSS",
			input: Input{
				CVSSScore:      float64Ptr(6.5),
				EPSSScore:      float64Ptr(0.85),
				LEVScore:       float64Ptr(0.7),
				InKEV:          false,
				PatchAvailable: false,
				PublishedAt:    time.Now().Add(-180 * 24 * time.Hour),
			},
			weights: weights,
			wantMin: 0.5,
			wantMax: 0.85,
		},
		{
			name: "in KEV always elevates score",
			input: Input{
				CVSSScore:      float64Ptr(5.0),
				EPSSScore:      float64Ptr(0.3),
				LEVScore:       float64Ptr(1.0),
				InKEV:          true,
				PatchAvailable: true,
				PublishedAt:    time.Now().Add(-365 * 24 * time.Hour),
			},
			weights: weights,
			wantMin: 0.45,
			wantMax: 0.80,
		},
		{
			name: "no data at all returns zero",
			input: Input{
				CVSSScore:      nil,
				EPSSScore:      nil,
				LEVScore:       nil,
				InKEV:          false,
				PatchAvailable: true,
				PublishedAt:    time.Time{},
			},
			weights: weights,
			wantMin: 0.0,
			wantMax: 0.01,
		},
		{
			name: "patch unavailable increases score",
			input: Input{
				CVSSScore:      float64Ptr(7.0),
				EPSSScore:      float64Ptr(0.5),
				LEVScore:       nil,
				InKEV:          false,
				PatchAvailable: false,
				PublishedAt:    time.Now().Add(-30 * 24 * time.Hour),
			},
			weights: weights,
			wantMin: 0.35,
			wantMax: 0.70,
		},
		{
			name: "custom weights emphasize EPSS",
			input: Input{
				CVSSScore:      float64Ptr(3.0),
				EPSSScore:      float64Ptr(0.95),
				LEVScore:       nil,
				InKEV:          false,
				PatchAvailable: true,
				PublishedAt:    time.Now().Add(-10 * 24 * time.Hour),
			},
			weights: Weights{
				CVSS:  0.10,
				EPSS:  0.50,
				LEV:   0.10,
				KEV:   0.10,
				Patch: 0.10,
				Age:   0.10,
			},
			wantMin: 0.4,
			wantMax: 0.70,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compute(tt.input, tt.weights)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("Compute() = %v, want in [%v, %v]", got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestNormalizeCVSS(t *testing.T) {
	tests := []struct {
		name  string
		score *float64
		want  float64
	}{
		{"nil", nil, 0.0},
		{"zero", float64Ptr(0.0), 0.0},
		{"medium", float64Ptr(5.0), 0.5},
		{"critical", float64Ptr(10.0), 1.0},
		{"above max clamped", float64Ptr(11.0), 1.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeCVSS(tt.score)
			if math.Abs(got-tt.want) > 0.001 {
				t.Errorf("normalizeCVSS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeAge(t *testing.T) {
	tests := []struct {
		name string
		pub  time.Time
		min  float64
		max  float64
	}{
		{"zero time", time.Time{}, 0.0, 0.0},
		{"just now", time.Now(), 0.0, 0.01},
		{"1 day ago", time.Now().Add(-24 * time.Hour), 0.0, 0.2},
		{"30 days ago", time.Now().Add(-30 * 24 * time.Hour), 0.4, 0.6},
		{"1 year ago", time.Now().Add(-365 * 24 * time.Hour), 0.85, 1.0},
		{"3 years ago", time.Now().Add(-3 * 365 * 24 * time.Hour), 0.95, 1.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeAge(tt.pub)
			if got < tt.min || got > tt.max {
				t.Errorf("normalizeAge() = %v, want in [%v, %v]", got, tt.min, tt.max)
			}
		})
	}
}

func TestDefaultWeightsSumToOne(t *testing.T) {
	w := DefaultWeights()
	sum := w.CVSS + w.EPSS + w.LEV + w.KEV + w.Patch + w.Age
	if math.Abs(sum-1.0) > 0.001 {
		t.Errorf("DefaultWeights sum = %v, want 1.0", sum)
	}
}

func TestComputeClampsBounds(t *testing.T) {
	// Even with extreme inputs, result should be in [0, 1]
	input := Input{
		CVSSScore:      float64Ptr(100.0), // way above max
		EPSSScore:      float64Ptr(5.0),   // way above 1.0
		LEVScore:       float64Ptr(10.0),
		InKEV:          true,
		PatchAvailable: false,
		PublishedAt:    time.Now().Add(-100 * 365 * 24 * time.Hour),
	}
	got := Compute(input, DefaultWeights())
	if got < 0 || got > 1.0 {
		t.Errorf("Compute() = %v, want in [0.0, 1.0]", got)
	}
}

func TestComputeWeightRedistribution(t *testing.T) {
	// When some signals are unavailable, their weight should be redistributed.
	// Compare: full signals at 50% vs half signals missing at 50%.
	// The key property is: if all available signals report 0.5, the result
	// should be approximately 0.5 regardless of how many signals are missing.
	halfInput := Input{
		CVSSScore:      float64Ptr(5.0), // normalized to 0.5
		EPSSScore:      float64Ptr(0.5),
		LEVScore:       float64Ptr(0.5),
		InKEV:          false, // 0.0
		PatchAvailable: true,  // 0.0
		PublishedAt:    time.Time{},
	}

	got := Compute(halfInput, DefaultWeights())
	// With CVSS=0.5, EPSS=0.5, LEV=0.5, KEV=0, Patch=0, Age redistributed:
	// Expected: somewhat below 0.5 due to KEV=0 and Patch=0 contributing
	if got < 0.2 || got > 0.5 {
		t.Errorf("Compute() with mixed signals = %v, want in [0.2, 0.5]", got)
	}
}
