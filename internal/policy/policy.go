// Package policy provides YAML-based policy rules for filtering and gating
// audit/scan findings. Policies define conditions (severity, EPSS, KEV, etc.)
// and actions (block, warn, suppress) to apply when conditions match.
package policy

// Action represents the decision a policy can make for a finding.
type Action string

const (
	// ActionBlock marks a finding as blocked — triggers exit code 1.
	ActionBlock Action = "block"
	// ActionWarn marks a finding as a warning — displayed but does not affect exit code.
	ActionWarn Action = "warn"
	// ActionSuppress marks a finding as suppressed — excluded from output.
	ActionSuppress Action = "suppress"
	// ActionAllow is the default action when no policy matches — finding passes through.
	ActionAllow Action = "allow"
)

// ValidActions is the set of valid action strings that can appear in a policy file.
var ValidActions = map[string]Action{
	"block":    ActionBlock,
	"warn":     ActionWarn,
	"suppress": ActionSuppress,
}

// ValidSeverities is the set of valid severity labels.
var ValidSeverities = map[string]bool{
	"CRITICAL": true,
	"HIGH":     true,
	"MEDIUM":   true,
	"LOW":      true,
	"NONE":     true,
}

// PolicyFile represents the top-level YAML policy configuration.
type PolicyFile struct {
	Policies []Policy `yaml:"policies"`
}

// Policy defines a single policy rule with conditions and an action.
type Policy struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Conditions  Conditions `yaml:"conditions"`
	Action      string     `yaml:"action"` // block, warn, suppress
}

// Conditions specifies the matching criteria for a policy rule.
// All non-nil conditions must match (AND logic) for the policy to apply.
type Conditions struct {
	Severity  []string `yaml:"severity"`       // CRITICAL, HIGH, MEDIUM, LOW, NONE
	InKEV     *bool    `yaml:"in_kev"`         // whether the finding is in CISA KEV
	EPSSAbove *float64 `yaml:"epss_above"`     // EPSS score > threshold
	EPSSBelow *float64 `yaml:"epss_below"`     // EPSS score < threshold
	LEVAbove  *float64 `yaml:"lev_above"`      // LEV score > threshold
	HasFix    *bool    `yaml:"has_fix"`        // whether a fix version is known
	CWE       []string `yaml:"cwe"`            // CWE IDs to match (any)
	Ecosystem []string `yaml:"ecosystem"`      // ecosystems to match (any)
	AgeDays   *int     `yaml:"age_days_above"` // published more than N days ago
}

// FindingContext holds the relevant attributes of a finding for policy evaluation.
type FindingContext struct {
	Severity     string   // CRITICAL, HIGH, MEDIUM, LOW, NONE
	EPSS         float64  // EPSS probability score (0.0-1.0)
	LEV          float64  // LEV probability score (0.0-1.0)
	InKEV        bool     // whether in CISA KEV catalog
	HasFix       bool     // whether a fix version is available
	CWEs         []string // associated CWE IDs (e.g., "CWE-79")
	Ecosystem    string   // ecosystem name (e.g., "Go", "npm")
	PublishedAge int      // days since published
}

// EvalResult contains the outcome of evaluating a finding against policies.
type EvalResult struct {
	Action     Action // block, warn, suppress, allow
	PolicyName string // name of the matched policy (empty if allow)
}
