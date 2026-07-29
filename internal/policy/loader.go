package policy

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadFile reads and parses a policy YAML file from disk.
func LoadFile(path string) (*PolicyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return Parse(data)
}

// Parse parses policy YAML data into a PolicyFile.
func Parse(data []byte) (*PolicyFile, error) {
	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse policy YAML: %w", err)
	}
	return &pf, nil
}

// Validate checks that a PolicyFile is well-formed and returns all validation
// errors found. Returns nil if the file is valid.
func Validate(pf *PolicyFile) []error {
	var errs []error

	if len(pf.Policies) == 0 {
		errs = append(errs, fmt.Errorf("policies list is empty"))
		return errs
	}

	names := make(map[string]bool)
	for i, p := range pf.Policies {
		prefix := fmt.Sprintf("policy[%d]", i)

		// Name is required and must be unique
		if p.Name == "" {
			errs = append(errs, fmt.Errorf("%s: name is required", prefix))
		} else {
			if names[p.Name] {
				errs = append(errs, fmt.Errorf("%s: duplicate policy name %q", prefix, p.Name))
			}
			names[p.Name] = true
			prefix = fmt.Sprintf("policy[%d] %q", i, p.Name)
		}

		// Action is required and must be valid
		if p.Action == "" {
			errs = append(errs, fmt.Errorf("%s: action is required", prefix))
		} else if _, ok := ValidActions[strings.ToLower(p.Action)]; !ok {
			errs = append(errs, fmt.Errorf("%s: invalid action %q (valid: block, warn, suppress)", prefix, p.Action))
		}

		// Validate severity values
		for _, sev := range p.Conditions.Severity {
			if !ValidSeverities[strings.ToUpper(sev)] {
				errs = append(errs, fmt.Errorf("%s: invalid severity %q (valid: CRITICAL, HIGH, MEDIUM, LOW, NONE)", prefix, sev))
			}
		}

		// Validate EPSS thresholds
		if p.Conditions.EPSSAbove != nil {
			v := *p.Conditions.EPSSAbove
			if v < 0 || v > 1 {
				errs = append(errs, fmt.Errorf("%s: epss_above must be between 0.0 and 1.0, got %v", prefix, v))
			}
		}
		if p.Conditions.EPSSBelow != nil {
			v := *p.Conditions.EPSSBelow
			if v < 0 || v > 1 {
				errs = append(errs, fmt.Errorf("%s: epss_below must be between 0.0 and 1.0, got %v", prefix, v))
			}
		}

		// Validate LEV threshold
		if p.Conditions.LEVAbove != nil {
			v := *p.Conditions.LEVAbove
			if v < 0 || v > 1 {
				errs = append(errs, fmt.Errorf("%s: lev_above must be between 0.0 and 1.0, got %v", prefix, v))
			}
		}

		// Validate age_days_above
		if p.Conditions.AgeDays != nil && *p.Conditions.AgeDays < 0 {
			errs = append(errs, fmt.Errorf("%s: age_days_above must be non-negative, got %d", prefix, *p.Conditions.AgeDays))
		}

		// At least one condition should be specified
		if len(p.Conditions.Severity) == 0 &&
			p.Conditions.InKEV == nil &&
			p.Conditions.EPSSAbove == nil &&
			p.Conditions.EPSSBelow == nil &&
			p.Conditions.LEVAbove == nil &&
			p.Conditions.HasFix == nil &&
			len(p.Conditions.CWE) == 0 &&
			len(p.Conditions.Ecosystem) == 0 &&
			p.Conditions.AgeDays == nil {
			errs = append(errs, fmt.Errorf("%s: at least one condition is required", prefix))
		}
	}

	return errs
}
