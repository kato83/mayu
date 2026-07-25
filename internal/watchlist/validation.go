package watchlist

import "fmt"

// validMatchTypes are the allowed values for match_type.
var validMatchTypes = map[string]bool{
	MatchTypePackage:   true,
	MatchTypePurl:      true,
	MatchTypeCPE:       true,
	MatchTypeEcosystem: true,
}

// validateCreateRequest validates a create watchlist request.
func validateCreateRequest(req *createWatchlistRequest) error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}

	if !validMatchTypes[req.MatchType] {
		return fmt.Errorf("invalid match_type %q: must be one of package, purl, cpe, ecosystem", req.MatchType)
	}

	// Validate required fields per match_type
	switch req.MatchType {
	case MatchTypePackage:
		if req.Ecosystem == nil || *req.Ecosystem == "" {
			return fmt.Errorf("ecosystem is required for match_type 'package'")
		}
		if req.PackageName == nil || *req.PackageName == "" {
			return fmt.Errorf("package_name is required for match_type 'package'")
		}
	case MatchTypePurl:
		if req.PurlPattern == nil || *req.PurlPattern == "" {
			return fmt.Errorf("purl_pattern is required for match_type 'purl'")
		}
	case MatchTypeCPE:
		if req.CpePattern == nil || *req.CpePattern == "" {
			return fmt.Errorf("cpe_pattern is required for match_type 'cpe'")
		}
	case MatchTypeEcosystem:
		if req.Ecosystem == nil || *req.Ecosystem == "" {
			return fmt.Errorf("ecosystem is required for match_type 'ecosystem'")
		}
	}

	// Validate severity_min if set
	if req.SeverityMin != nil {
		if *req.SeverityMin < 1 || *req.SeverityMin > 5 {
			return fmt.Errorf("severity_min must be between 1 and 5")
		}
	}

	// Validate epss_threshold if set
	if req.EpssThreshold != nil {
		if *req.EpssThreshold < 0.0 || *req.EpssThreshold > 1.0 {
			return fmt.Errorf("epss_threshold must be between 0.0 and 1.0")
		}
	}

	return nil
}

// validateUpdateRequest validates an update watchlist request.
func validateUpdateRequest(req *updateWatchlistRequest) error {
	if req.MatchType != nil {
		if !validMatchTypes[*req.MatchType] {
			return fmt.Errorf("invalid match_type %q: must be one of package, purl, cpe, ecosystem", *req.MatchType)
		}
	}

	// Validate severity_min if set
	if req.SeverityMin != nil {
		if *req.SeverityMin < 1 || *req.SeverityMin > 5 {
			return fmt.Errorf("severity_min must be between 1 and 5")
		}
	}

	// Validate epss_threshold if set
	if req.EpssThreshold != nil {
		if *req.EpssThreshold < 0.0 || *req.EpssThreshold > 1.0 {
			return fmt.Errorf("epss_threshold must be between 0.0 and 1.0")
		}
	}

	return nil
}
