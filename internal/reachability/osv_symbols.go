package reachability

import "encoding/json"

// goEcosystemSpecific represents the Go-specific ecosystem_specific field in OSV data.
// See: https://go.dev/security/vuln/database#schema
type goEcosystemSpecific struct {
	Imports []goImport `json:"imports"`
}

// goImport represents a single import entry with vulnerable symbols.
type goImport struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols"`
}

// ExtractVulnSymbols extracts vulnerable symbols from an OSV affected entry's
// ecosystem_specific field. This is specific to the Go ecosystem where the
// OSV schema includes imports[].path and imports[].symbols.
//
// Returns nil if the data is nil, not valid JSON, or contains no symbol information.
func ExtractVulnSymbols(vulnID string, ecosystemSpecific json.RawMessage) []VulnSymbol {
	if ecosystemSpecific == nil {
		return nil
	}

	var eco goEcosystemSpecific
	if err := json.Unmarshal(ecosystemSpecific, &eco); err != nil {
		return nil
	}

	var symbols []VulnSymbol
	for _, imp := range eco.Imports {
		if imp.Path == "" {
			continue
		}
		for _, sym := range imp.Symbols {
			if sym == "" {
				continue
			}
			symbols = append(symbols, VulnSymbol{
				VulnID:  vulnID,
				Package: imp.Path,
				Symbol:  sym,
			})
		}
	}
	return symbols
}
