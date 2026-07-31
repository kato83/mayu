package triage

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Profile defines a complete triage configuration including weights,
// thresholds, and priority mappings.
type Profile struct {
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description" json:"description"`
	Base        string            `yaml:"base,omitempty" json:"base,omitempty"`
	Weights     *ExtendedWeights  `yaml:"weights" json:"weights"`
	Thresholds  *Thresholds       `yaml:"thresholds" json:"thresholds"`
	SSVCMapping map[string]string `yaml:"ssvc_mapping,omitempty" json:"ssvc_mapping,omitempty"`
}

// ExtendedWeights defines weights for all 8 risk signals.
// All weights must sum to 1.0.
type ExtendedWeights struct {
	CVSS         float64 `yaml:"cvss" json:"cvss"`
	EPSS         float64 `yaml:"epss" json:"epss"`
	LEV          float64 `yaml:"lev" json:"lev"`
	KEV          float64 `yaml:"kev" json:"kev"`
	Patch        float64 `yaml:"patch" json:"patch"`
	Age          float64 `yaml:"age" json:"age"`
	ExploitDB    float64 `yaml:"exploitdb" json:"exploitdb"`
	Reachability float64 `yaml:"reachability" json:"reachability"`
}

// Thresholds defines the score boundaries for each priority level.
type Thresholds struct {
	Critical float64 `yaml:"critical" json:"critical"`
	High     float64 `yaml:"high" json:"high"`
	Medium   float64 `yaml:"medium" json:"medium"`
}

// DefaultExtendedWeights returns the default weight configuration.
func DefaultExtendedWeights() *ExtendedWeights {
	return &ExtendedWeights{
		CVSS:         0.20,
		EPSS:         0.20,
		LEV:          0.15,
		KEV:          0.15,
		Patch:        0.08,
		Age:          0.05,
		ExploitDB:    0.10,
		Reachability: 0.07,
	}
}

// DefaultThresholds returns the default threshold configuration.
func DefaultThresholds() *Thresholds {
	return &Thresholds{
		Critical: 0.85,
		High:     0.65,
		Medium:   0.40,
	}
}

// DefaultProfile returns the built-in default profile.
func DefaultProfile() *Profile {
	return &Profile{
		Name:        "default",
		Description: "General-purpose balanced profile",
		Weights:     DefaultExtendedWeights(),
		Thresholds:  DefaultThresholds(),
		SSVCMapping: map[string]string{
			"Act":    "Critical",
			"Attend": "High",
			"Track*": "Medium",
			"Track":  "Low",
		},
	}
}

// LoadProfile reads and validates a profile from a YAML file.
func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile file: %w", err)
	}
	return ParseProfile(data)
}

// ParseProfile parses profile YAML data into a Profile.
func ParseProfile(data []byte) (*Profile, error) {
	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse profile YAML: %w", err)
	}

	// Apply base template if specified
	if p.Base != "" {
		base := findTemplate(p.Base)
		if base == nil {
			return nil, fmt.Errorf("unknown base template: %q", p.Base)
		}
		mergeProfile(&p, base)
	}

	return &p, nil
}

// findTemplate looks up a built-in template by name.
func findTemplate(name string) *Profile {
	for _, t := range BuiltinTemplates() {
		if t.Name == name {
			return &t
		}
	}
	return nil
}

// mergeProfile fills in missing fields in p from base.
func mergeProfile(p *Profile, base *Profile) {
	if p.Weights == nil {
		p.Weights = base.Weights
	}
	if p.Thresholds == nil {
		p.Thresholds = base.Thresholds
	}
	if p.SSVCMapping == nil {
		p.SSVCMapping = base.SSVCMapping
	}
}

// BuiltinTemplates returns the list of available built-in template profiles.
func BuiltinTemplates() []Profile {
	return []Profile{
		{
			Name:        "default",
			Description: "General-purpose balanced profile",
			Weights:     DefaultExtendedWeights(),
			Thresholds:  DefaultThresholds(),
			SSVCMapping: map[string]string{
				"Act": "Critical", "Attend": "High", "Track*": "Medium", "Track": "Low",
			},
		},
		{
			Name:        "internet-facing",
			Description: "Internet-facing services: emphasizes EPSS, KEV, and ExploitDB",
			Weights: &ExtendedWeights{
				CVSS: 0.15, EPSS: 0.25, LEV: 0.15, KEV: 0.20,
				Patch: 0.05, Age: 0.03, ExploitDB: 0.12, Reachability: 0.05,
			},
			Thresholds: &Thresholds{Critical: 0.80, High: 0.60, Medium: 0.35},
			SSVCMapping: map[string]string{
				"Act": "Critical", "Attend": "High", "Track*": "Medium", "Track": "Low",
			},
		},
		{
			Name:        "internal-only",
			Description: "Internal systems: emphasizes CVSS and patch availability",
			Weights: &ExtendedWeights{
				CVSS: 0.30, EPSS: 0.10, LEV: 0.10, KEV: 0.10,
				Patch: 0.15, Age: 0.08, ExploitDB: 0.10, Reachability: 0.07,
			},
			Thresholds: &Thresholds{Critical: 0.90, High: 0.70, Medium: 0.45},
			SSVCMapping: map[string]string{
				"Act": "Critical", "Attend": "High", "Track*": "Medium", "Track": "Low",
			},
		},
		{
			Name:        "air-gapped",
			Description: "Air-gapped environments: de-emphasizes KEV/EPSS, focuses on CVSS and patch",
			Weights: &ExtendedWeights{
				CVSS: 0.35, EPSS: 0.05, LEV: 0.05, KEV: 0.05,
				Patch: 0.20, Age: 0.10, ExploitDB: 0.10, Reachability: 0.10,
			},
			Thresholds: &Thresholds{Critical: 0.90, High: 0.70, Medium: 0.45},
			SSVCMapping: map[string]string{
				"Act": "Critical", "Attend": "High", "Track*": "Medium", "Track": "Low",
			},
		},
	}
}
