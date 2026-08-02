package triage

import (
	"fmt"
	"math"
)

// ValidateProfile checks a profile for structural and semantic correctness.
// Returns a list of validation errors (empty = valid).
func ValidateProfile(p *Profile) []error {
	var errs []error

	if p.Weights == nil {
		errs = append(errs, fmt.Errorf("weights must be specified"))
		return errs
	}

	if p.Thresholds == nil {
		errs = append(errs, fmt.Errorf("thresholds must be specified"))
		return errs
	}

	// 1. Weight range check: each value must be in [0.0, 1.0]
	weights := []struct {
		name  string
		value float64
	}{
		{"cvss", p.Weights.CVSS},
		{"epss", p.Weights.EPSS},
		{"lev", p.Weights.LEV},
		{"kev", p.Weights.KEV},
		{"patch", p.Weights.Patch},
		{"age", p.Weights.Age},
		{"exploitdb", p.Weights.ExploitDB},
		{"exploitability", p.Weights.Exploitability},
	}

	for _, w := range weights {
		if w.value < 0 || w.value > 1.0 {
			errs = append(errs, fmt.Errorf("weight %q: value %.4f is out of range [0.0, 1.0]", w.name, w.value))
		}
	}

	// 2. Weight sum check (tolerance ±0.001)
	sum := p.Weights.CVSS + p.Weights.EPSS + p.Weights.LEV + p.Weights.KEV +
		p.Weights.Patch + p.Weights.Age + p.Weights.ExploitDB + p.Weights.Exploitability
	if math.Abs(sum-1.0) > 0.001 {
		errs = append(errs, fmt.Errorf("weights sum %.6f does not equal 1.0 (tolerance ±0.001)", sum))
	}

	// 3. Threshold range and order check (Critical >= High >= Medium)
	if p.Thresholds.Critical < p.Thresholds.High {
		errs = append(errs, fmt.Errorf("threshold critical (%.2f) must be >= high (%.2f)", p.Thresholds.Critical, p.Thresholds.High))
	}
	if p.Thresholds.High < p.Thresholds.Medium {
		errs = append(errs, fmt.Errorf("threshold high (%.2f) must be >= medium (%.2f)", p.Thresholds.High, p.Thresholds.Medium))
	}

	return errs
}
