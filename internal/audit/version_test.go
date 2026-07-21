package audit

import (
	"testing"

	"github.com/kato83/mayu/internal/model"
)

func TestIsAffected_VersionsList(t *testing.T) {
	affected := model.Affected{
		Versions: []string{"1.0.0", "1.0.1", "1.1.0"},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"1.0.0", true},
		{"1.0.1", true},
		{"1.1.0", true},
		{"1.2.0", false},
		{"2.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := IsAffected(tt.version, affected)
			if got != tt.want {
				t.Errorf("IsAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestIsAffected_IntroducedFixed(t *testing.T) {
	// Affected range: [0.1.0, 0.5.0) — introduced at 0.1.0, fixed at 0.5.0
	affected := model.Affected{
		Ranges: []model.Range{
			{
				Type: model.RangeTypeSemVer,
				Events: []model.Event{
					{Introduced: "0.1.0"},
					{Fixed: "0.5.0"},
				},
			},
		},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"0.0.9", false}, // before introduced
		{"0.1.0", true},  // exactly introduced
		{"0.3.0", true},  // in range
		{"0.4.99", true}, // just before fix
		{"0.5.0", false}, // exactly fixed (not affected)
		{"1.0.0", false}, // after fixed
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := IsAffected(tt.version, affected)
			if got != tt.want {
				t.Errorf("IsAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestIsAffected_IntroducedZero(t *testing.T) {
	// Affected range: [0, 1.2.0) — all versions before 1.2.0
	affected := model.Affected{
		Ranges: []model.Range{
			{
				Type: model.RangeTypeSemVer,
				Events: []model.Event{
					{Introduced: "0"},
					{Fixed: "1.2.0"},
				},
			},
		},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"0.0.1", true},
		{"0.9.0", true},
		{"1.1.9", true},
		{"1.2.0", false},
		{"2.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := IsAffected(tt.version, affected)
			if got != tt.want {
				t.Errorf("IsAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestIsAffected_LastAffected(t *testing.T) {
	// Affected range: [1.0.0, 1.5.0] — last_affected means inclusive upper bound
	affected := model.Affected{
		Ranges: []model.Range{
			{
				Type: model.RangeTypeSemVer,
				Events: []model.Event{
					{Introduced: "1.0.0"},
					{LastAffected: "1.5.0"},
				},
			},
		},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"0.9.0", false},
		{"1.0.0", true},
		{"1.3.0", true},
		{"1.5.0", true},  // last_affected is inclusive
		{"1.5.1", false}, // after last_affected
		{"2.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := IsAffected(tt.version, affected)
			if got != tt.want {
				t.Errorf("IsAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestIsAffected_MultipleRanges(t *testing.T) {
	// Two affected ranges (logical OR):
	// [1.0.0, 1.2.0) and [2.0.0, 2.1.0)
	affected := model.Affected{
		Ranges: []model.Range{
			{
				Type: model.RangeTypeSemVer,
				Events: []model.Event{
					{Introduced: "1.0.0"},
					{Fixed: "1.2.0"},
				},
			},
			{
				Type: model.RangeTypeSemVer,
				Events: []model.Event{
					{Introduced: "2.0.0"},
					{Fixed: "2.1.0"},
				},
			},
		},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"0.9.0", false},
		{"1.0.0", true},
		{"1.1.0", true},
		{"1.2.0", false},
		{"1.5.0", false},
		{"2.0.0", true},
		{"2.0.5", true},
		{"2.1.0", false},
		{"3.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := IsAffected(tt.version, affected)
			if got != tt.want {
				t.Errorf("IsAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestIsAffected_MultipleIntroducedFixed(t *testing.T) {
	// Single range with multiple introduced/fixed pairs:
	// [1.0.0, 1.2.0) and [1.5.0, 1.8.0)
	affected := model.Affected{
		Ranges: []model.Range{
			{
				Type: model.RangeTypeSemVer,
				Events: []model.Event{
					{Introduced: "1.0.0"},
					{Fixed: "1.2.0"},
					{Introduced: "1.5.0"},
					{Fixed: "1.8.0"},
				},
			},
		},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"0.9.0", false},
		{"1.0.0", true},
		{"1.1.0", true},
		{"1.2.0", false},
		{"1.3.0", false},
		{"1.5.0", true},
		{"1.7.0", true},
		{"1.8.0", false},
		{"2.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := IsAffected(tt.version, affected)
			if got != tt.want {
				t.Errorf("IsAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestIsAffected_GitRangeSkipped(t *testing.T) {
	// GIT ranges should be skipped — no match based on commit hashes
	affected := model.Affected{
		Ranges: []model.Range{
			{
				Type: model.RangeTypeGit,
				Events: []model.Event{
					{Introduced: "abc123"},
					{Fixed: "def456"},
				},
			},
		},
	}

	got := IsAffected("1.0.0", affected)
	if got {
		t.Error("IsAffected() = true for GIT range, want false (should skip GIT ranges)")
	}
}

func TestIsAffected_EcosystemRange(t *testing.T) {
	// ECOSYSTEM type ranges use the same semver-style comparison
	affected := model.Affected{
		Ranges: []model.Range{
			{
				Type: model.RangeTypeEcosystem,
				Events: []model.Event{
					{Introduced: "0"},
					{Fixed: "2.0.0"},
				},
			},
		},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"1.0.0", true},
		{"1.9.9", true},
		{"2.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := IsAffected(tt.version, affected)
			if got != tt.want {
				t.Errorf("IsAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestIsAffected_InvalidVersionFailSafe(t *testing.T) {
	// If we can't parse the version, fail safe (assume affected)
	affected := model.Affected{
		Ranges: []model.Range{
			{
				Type: model.RangeTypeSemVer,
				Events: []model.Event{
					{Introduced: "1.0.0"},
					{Fixed: "2.0.0"},
				},
			},
		},
	}

	// "not-a-version" cannot be parsed as semver
	got := IsAffected("not-a-version", affected)
	if !got {
		t.Error("IsAffected() = false for unparseable version, want true (fail safe)")
	}
}

func TestIsAffected_NoRangesNoVersions(t *testing.T) {
	// No versions and no ranges — not affected
	affected := model.Affected{}

	got := IsAffected("1.0.0", affected)
	if got {
		t.Error("IsAffected() = true for empty affected, want false")
	}
}

func TestIsAffected_Limit(t *testing.T) {
	// "limit" behaves like "fixed" (exclusive upper bound)
	affected := model.Affected{
		Ranges: []model.Range{
			{
				Type: model.RangeTypeSemVer,
				Events: []model.Event{
					{Introduced: "1.0.0"},
					{Limit: "2.0.0"},
				},
			},
		},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"1.0.0", true},
		{"1.5.0", true},
		{"1.9.9", true},
		{"2.0.0", false},
		{"2.1.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := IsAffected(tt.version, affected)
			if got != tt.want {
				t.Errorf("IsAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestIsAffected_VPrefix(t *testing.T) {
	// Versions with "v" prefix should be handled
	affected := model.Affected{
		Ranges: []model.Range{
			{
				Type: model.RangeTypeSemVer,
				Events: []model.Event{
					{Introduced: "0"},
					{Fixed: "1.5.0"},
				},
			},
		},
	}

	got := IsAffected("v1.2.3", affected)
	if !got {
		t.Error("IsAffected(v1.2.3) = false, want true (should handle v prefix)")
	}

	got = IsAffected("v1.5.0", affected)
	if got {
		t.Error("IsAffected(v1.5.0) = true, want false")
	}
}

func TestParseSemver(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"1.2.3", "1.2.3", false},
		{"v1.2.3", "1.2.3", false},
		{"0.17.0", "0.17.0", false},
		{"1.2.3-beta.1", "1.2.3-beta.1", false},
		{"1.2.3+build", "1.2.3+build", false},
		{"not-a-version", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseSemver(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("parseSemver() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSemver() error = %v", err)
			}
			if got.Original() != tt.want {
				t.Errorf("parseSemver() = %q, want %q", got.Original(), tt.want)
			}
		})
	}
}
