package triage

import (
	"math"
	"testing"

	"pgregory.net/rapid"
)

// TestProperty_ProfileValidationEquivalence verifies that ValidateProfile() passes
// if and only if all 8 non-negative weights sum to 1.0±0.001 and each is in [0.0, 1.0],
// and thresholds are correctly ordered.
//
// **Validates: Requirements 4.4**
func TestProperty_ProfileValidationEquivalence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate 8 non-negative float64 values in [0.0, 2.0] range
		// (allow values > 1.0 to test out-of-range detection)
		cvss := rapid.Float64Range(0.0, 2.0).Draw(t, "cvss")
		epss := rapid.Float64Range(0.0, 2.0).Draw(t, "epss")
		lev := rapid.Float64Range(0.0, 2.0).Draw(t, "lev")
		kev := rapid.Float64Range(0.0, 2.0).Draw(t, "kev")
		patch := rapid.Float64Range(0.0, 2.0).Draw(t, "patch")
		age := rapid.Float64Range(0.0, 2.0).Draw(t, "age")
		exploitdb := rapid.Float64Range(0.0, 2.0).Draw(t, "exploitdb")
		reachability := rapid.Float64Range(0.0, 2.0).Draw(t, "reachability")

		weights := &ExtendedWeights{
			CVSS:         cvss,
			EPSS:         epss,
			LEV:          lev,
			KEV:          kev,
			Patch:        patch,
			Age:          age,
			ExploitDB:    exploitdb,
			Reachability: reachability,
		}

		// Use valid thresholds so we only test weight validation
		thresholds := DefaultThresholds()

		p := &Profile{
			Name:       "property-test",
			Weights:    weights,
			Thresholds: thresholds,
		}

		errs := ValidateProfile(p)

		// Compute expected validity
		allInRange := cvss >= 0 && cvss <= 1.0 &&
			epss >= 0 && epss <= 1.0 &&
			lev >= 0 && lev <= 1.0 &&
			kev >= 0 && kev <= 1.0 &&
			patch >= 0 && patch <= 1.0 &&
			age >= 0 && age <= 1.0 &&
			exploitdb >= 0 && exploitdb <= 1.0 &&
			reachability >= 0 && reachability <= 1.0

		sum := cvss + epss + lev + kev + patch + age + exploitdb + reachability
		sumIsOne := math.Abs(sum-1.0) <= 0.001

		expectedValid := allInRange && sumIsOne

		actualValid := len(errs) == 0

		if expectedValid && !actualValid {
			t.Fatalf("expected valid profile (allInRange=%v, sum=%.6f) but got errors: %v",
				allInRange, sum, errs)
		}
		if !expectedValid && actualValid {
			t.Fatalf("expected invalid profile (allInRange=%v, sum=%.6f) but validation passed",
				allInRange, sum)
		}
	})
}

// TestProperty_ThresholdOrderValidation verifies that ValidateProfile() fails
// when thresholds are not in descending order (Critical >= High >= Medium).
//
// **Validates: Requirements 4.4**
func TestProperty_ThresholdOrderValidation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate 3 threshold values in [0.0, 1.0]
		critical := rapid.Float64Range(0.0, 1.0).Draw(t, "critical")
		high := rapid.Float64Range(0.0, 1.0).Draw(t, "high")
		medium := rapid.Float64Range(0.0, 1.0).Draw(t, "medium")

		thresholds := &Thresholds{
			Critical: critical,
			High:     high,
			Medium:   medium,
		}

		p := &Profile{
			Name:       "threshold-test",
			Weights:    DefaultExtendedWeights(),
			Thresholds: thresholds,
		}

		errs := ValidateProfile(p)

		// Thresholds must satisfy: Critical >= High >= Medium
		orderValid := critical >= high && high >= medium

		// With default weights (which are valid), errors should only come from threshold order
		if orderValid && len(errs) > 0 {
			t.Fatalf("expected valid thresholds (critical=%.4f >= high=%.4f >= medium=%.4f) but got errors: %v",
				critical, high, medium, errs)
		}
		if !orderValid && len(errs) == 0 {
			t.Fatalf("expected invalid thresholds (critical=%.4f, high=%.4f, medium=%.4f) but validation passed",
				critical, high, medium)
		}
	})
}
