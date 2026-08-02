package triage

import "testing"

func TestValidateProfile_Valid(t *testing.T) {
	p := DefaultProfile()
	errs := ValidateProfile(p)
	if len(errs) > 0 {
		t.Errorf("default profile should be valid, got errors: %v", errs)
	}
}

func TestValidateProfile_NilWeights(t *testing.T) {
	p := &Profile{
		Name:       "test",
		Weights:    nil,
		Thresholds: DefaultThresholds(),
	}
	errs := ValidateProfile(p)
	if len(errs) == 0 {
		t.Error("expected error for nil weights")
	}
}

func TestValidateProfile_NilThresholds(t *testing.T) {
	p := &Profile{
		Name:       "test",
		Weights:    DefaultExtendedWeights(),
		Thresholds: nil,
	}
	errs := ValidateProfile(p)
	if len(errs) == 0 {
		t.Error("expected error for nil thresholds")
	}
}

func TestValidateProfile_NegativeWeight(t *testing.T) {
	p := &Profile{
		Name: "test",
		Weights: &ExtendedWeights{
			CVSS: -0.1, EPSS: 0.25, LEV: 0.20, KEV: 0.15,
			Patch: 0.10, Age: 0.05, ExploitDB: 0.10, Exploitability: 0.25,
		},
		Thresholds: DefaultThresholds(),
	}
	errs := ValidateProfile(p)
	found := false
	for _, e := range errs {
		if e.Error() != "" {
			found = true
		}
	}
	if !found {
		t.Error("expected error for negative weight")
	}
}

func TestValidateProfile_WeightSumNotOne(t *testing.T) {
	p := &Profile{
		Name: "test",
		Weights: &ExtendedWeights{
			CVSS: 0.50, EPSS: 0.25, LEV: 0.20, KEV: 0.15,
			Patch: 0.10, Age: 0.05, ExploitDB: 0.10, Exploitability: 0.10,
		},
		Thresholds: DefaultThresholds(),
	}
	errs := ValidateProfile(p)
	foundSumErr := false
	for _, e := range errs {
		if e != nil {
			foundSumErr = true
		}
	}
	if !foundSumErr {
		t.Error("expected error for weights sum != 1.0")
	}
}

func TestValidateProfile_ThresholdOrder(t *testing.T) {
	p := &Profile{
		Name:    "test",
		Weights: DefaultExtendedWeights(),
		Thresholds: &Thresholds{
			Critical: 0.50, // Critical < High
			High:     0.70,
			Medium:   0.30,
		},
	}
	errs := ValidateProfile(p)
	if len(errs) == 0 {
		t.Error("expected error for incorrect threshold order")
	}
}

func TestValidateProfile_AllBuiltinTemplates(t *testing.T) {
	templates := BuiltinTemplates()
	for _, tmpl := range templates {
		t.Run(tmpl.Name, func(t *testing.T) {
			errs := ValidateProfile(&tmpl)
			if len(errs) > 0 {
				t.Errorf("built-in template %q should be valid, got errors: %v", tmpl.Name, errs)
			}
		})
	}
}
