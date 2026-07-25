// Package watchlist provides data models, store interface, and implementation
// for the watchlist feature, which allows users to register packages/products
// of interest and receive notifications when related vulnerabilities are found.
package watchlist

import "time"

// MatchType defines the type of matching criteria for a watchlist entry.
const (
	MatchTypePackage   = "package"
	MatchTypePurl      = "purl"
	MatchTypeCPE       = "cpe"
	MatchTypeEcosystem = "ecosystem"
)

// Watchlist represents a user-defined watch condition for vulnerability monitoring.
type Watchlist struct {
	ID            int64
	UserID        int64
	Name          string
	MatchType     string // one of: package, purl, cpe, ecosystem
	Ecosystem     *string
	PackageName   *string
	PurlPattern   *string
	CpePattern    *string
	SeverityMin   *int16
	EpssThreshold *float64
	Enabled       bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// WatchlistMatch represents a recorded match between a watchlist and a vulnerability.
type WatchlistMatch struct {
	ID              int64
	WatchlistID     int64
	VulnerabilityID string
	MatchedAt       time.Time
	Notified        bool
	NotifiedAt      *time.Time
}

// CreateWatchlistInput holds the input data for creating a new watchlist entry.
type CreateWatchlistInput struct {
	Name          string
	MatchType     string
	Ecosystem     *string
	PackageName   *string
	PurlPattern   *string
	CpePattern    *string
	SeverityMin   *int16
	EpssThreshold *float64
	Enabled       bool
}

// UpdateWatchlistInput holds the input data for updating an existing watchlist entry.
type UpdateWatchlistInput struct {
	ID            int64
	Name          *string
	MatchType     *string
	Ecosystem     *string
	PackageName   *string
	PurlPattern   *string
	CpePattern    *string
	SeverityMin   *int16
	EpssThreshold *float64
	Enabled       *bool
}
