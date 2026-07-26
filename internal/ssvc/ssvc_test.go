package ssvc

import "testing"

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name            string
		exploitation    Exploitation
		automatable     Automatable
		technicalImpact TechnicalImpact
		want            Decision
	}{
		// None exploitation
		{"none/no/partial", ExploitationNone, AutomatableNo, TechnicalImpactPartial, DecisionTrack},
		{"none/no/total", ExploitationNone, AutomatableNo, TechnicalImpactTotal, DecisionTrackStar},
		{"none/yes/partial", ExploitationNone, AutomatableYes, TechnicalImpactPartial, DecisionAttend},
		{"none/yes/total", ExploitationNone, AutomatableYes, TechnicalImpactTotal, DecisionAttend},
		// POC exploitation
		{"poc/no/partial", ExploitationPOC, AutomatableNo, TechnicalImpactPartial, DecisionTrackStar},
		{"poc/no/total", ExploitationPOC, AutomatableNo, TechnicalImpactTotal, DecisionAttend},
		{"poc/yes/partial", ExploitationPOC, AutomatableYes, TechnicalImpactPartial, DecisionAttend},
		{"poc/yes/total", ExploitationPOC, AutomatableYes, TechnicalImpactTotal, DecisionAttend},
		// Active exploitation
		{"active/no/partial", ExploitationActive, AutomatableNo, TechnicalImpactPartial, DecisionAttend},
		{"active/no/total", ExploitationActive, AutomatableNo, TechnicalImpactTotal, DecisionAct},
		{"active/yes/partial", ExploitationActive, AutomatableYes, TechnicalImpactPartial, DecisionAct},
		{"active/yes/total", ExploitationActive, AutomatableYes, TechnicalImpactTotal, DecisionAct},
		// Invalid input
		{"invalid exploitation", "unknown", AutomatableNo, TechnicalImpactPartial, ""},
		{"invalid automatable", ExploitationNone, "maybe", TechnicalImpactPartial, ""},
		{"invalid tech impact", ExploitationNone, AutomatableNo, "medium", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.exploitation, tt.automatable, tt.technicalImpact)
			if got != tt.want {
				t.Errorf("Evaluate(%q, %q, %q) = %q, want %q",
					tt.exploitation, tt.automatable, tt.technicalImpact, got, tt.want)
			}
		})
	}
}

func TestEvaluateFromOptions(t *testing.T) {
	tests := []struct {
		name    string
		options map[string]string
		want    Decision
		wantOK  bool
	}{
		{
			name:    "MITRE format (capitalized keys)",
			options: map[string]string{"Exploitation": "poc", "Automatable": "no", "Technical Impact": "total"},
			want:    DecisionAttend,
			wantOK:  true,
		},
		{
			name:    "NVD format (camelCase keys)",
			options: map[string]string{"exploitation": "active", "automatable": "yes", "technicalImpact": "total"},
			want:    DecisionAct,
			wantOK:  true,
		},
		{
			name:    "none/no/partial",
			options: map[string]string{"Exploitation": "none", "Automatable": "no", "Technical Impact": "partial"},
			want:    DecisionTrack,
			wantOK:  true,
		},
		{
			name:    "missing exploitation",
			options: map[string]string{"Automatable": "no", "Technical Impact": "partial"},
			want:    "",
			wantOK:  false,
		},
		{
			name:    "empty options",
			options: map[string]string{},
			want:    "",
			wantOK:  false,
		},
		{
			name:    "public poc as exploitation value",
			options: map[string]string{"Exploitation": "public poc", "Automatable": "yes", "Technical Impact": "partial"},
			want:    DecisionAttend,
			wantOK:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := EvaluateFromOptions(tt.options)
			if ok != tt.wantOK {
				t.Errorf("EvaluateFromOptions() ok = %v, wantOK %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("EvaluateFromOptions() = %q, want %q", got, tt.want)
			}
		})
	}
}
