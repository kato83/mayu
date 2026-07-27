// Package store defines the interface and implementation for persisting
// vulnerability data in PostgreSQL.
//
// The schema separates concerns:
//   - vulnerabilities: unified master table (source-agnostic, no source column)
//   - vulnerability_aliases + alias_sources: CVE/GHSA/etc cross-references with provenance
//   - vulnerability_summary: pre-computed derived data for list/filter views
//   - product_identifiers: unified package/product search table (purl/CPE decomposed)
//   - osv_entries + osv_*: OSV-specific detail tables
//   - nvd_entries + nvd_*: NVD-specific detail tables
//   - mitre_entries + mitre_*: MITRE-specific detail tables
//   - epss_scores: EPSS scoring data
//   - kev_entries: CISA KEV catalog data
package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/kato83/mayu/internal/model"
)

// Store defines the interface for vulnerability data persistence.
type Store interface {
	// Insert stores a single vulnerability and all its related data.
	// If a vulnerability with the same ID already exists, it is replaced (upsert).
	Insert(ctx context.Context, vuln *model.Vulnerability) error

	// UpsertBatch stores multiple vulnerabilities in a single transaction.
	// Each vulnerability is upserted (insert or replace).
	UpsertBatch(ctx context.Context, vulns []*model.Vulnerability) error

	// GetByID retrieves a single vulnerability by its OSV ID.
	// Returns nil, nil if not found.
	GetByID(ctx context.Context, id string) (*model.Vulnerability, error)

	// GetVulnerabilityDetail retrieves enriched vulnerability information by ID,
	// combining OSV, NVD, and MITRE data. The id can be a vulnerability_id,
	// osv_id, or alias. Returns nil, nil if not found.
	GetVulnerabilityDetail(ctx context.Context, id string) (*model.VulnerabilityDetail, error)

	// Search finds vulnerabilities matching the given query parameters.
	Search(ctx context.Context, query SearchQuery) ([]*model.Vulnerability, error)

	// Count returns the number of vulnerabilities matching the given query parameters.
	Count(ctx context.Context, query SearchQuery) (int64, error)

	// RefreshSummary recomputes vulnerability_summary rows for the given vulnerability IDs.
	// It aggregates scores from all sources (OSV severity, NVD metrics, MITRE metrics),
	// EPSS, KEV, LEV, ecosystems, and CWEs into the pre-computed summary table.
	// Called synchronously at the end of each import pipeline.
	RefreshSummary(ctx context.Context, vulnIDs []string) error

	// RefreshEPSSSummary performs a lightweight update of vulnerability_summary
	// for EPSS-related fields only (epss_score, epss_percentile).
	// Unlike RefreshSummary, this does not recompute severity, CWEs, or ecosystems.
	// Used by the EPSS ingest pipeline for significantly better performance.
	RefreshEPSSSummary(ctx context.Context, vulnIDs []string) error

	// UpsertProductIdentifiers stores product identifiers for vulnerabilities.
	// It replaces all existing identifiers for the given (vulnerability_id, source)
	// combination and inserts the new ones.
	UpsertProductIdentifiers(ctx context.Context, identifiers []*model.ProductIdentifier) error

	// GetSyncState retrieves the sync state for a given source.
	// Returns nil, nil if no sync state exists for the source.
	GetSyncState(ctx context.Context, source string) (*SyncState, error)

	// UpdateSyncState creates or updates the sync state for a source.
	UpdateSyncState(ctx context.Context, state *SyncState) error

	// ListSyncStates returns all sync state records ordered by source_type and source.
	ListSyncStates(ctx context.Context) ([]SyncState, error)

	// GetEPSSCoverage returns summary statistics about EPSS data coverage.
	GetEPSSCoverage(ctx context.Context) (*EPSSCoverage, error)

	// Close releases any resources held by the store.
	Close() error

	// ListOSVEcosystems returns all known OSV ecosystem names, sorted alphabetically.
	ListOSVEcosystems(ctx context.Context) ([]string, error)

	// UpsertOSVEcosystems inserts ecosystem names into osv_ecosystems (ignoring duplicates).
	UpsertOSVEcosystems(ctx context.Context, names []string) error

	// SearchByPackages queries vulnerabilities for multiple packages in a single batch.
	// Returns a map keyed by "ecosystem/name" with matching vulnerabilities (including
	// full affected data needed for version range checking).
	SearchByPackages(ctx context.Context, packages []PackageQuery) (map[string][]*model.Vulnerability, error)

	// CreateIngestJob records a new ingest job. Returns the auto-generated ID.
	// Prunes old jobs to keep only the 100 most recent.
	CreateIngestJob(ctx context.Context, job *IngestJob) (int64, error)

	// UpdateIngestJob updates an existing ingest job (status, counts, finish time).
	UpdateIngestJob(ctx context.Context, job *IngestJob) error

	// RecordIngestFailure records a single failure for an ingest job.
	RecordIngestFailure(ctx context.Context, failure *IngestFailure) error

	// RecordIngestFailures records multiple failures for an ingest job in a batch.
	RecordIngestFailures(ctx context.Context, failures []IngestFailure) error

	// ListIngestJobs returns recent ingest jobs ordered by start time (newest first).
	ListIngestJobs(ctx context.Context, limit int) ([]IngestJob, error)

	// GetIngestJob retrieves an ingest job by ID, including its failures.
	GetIngestJob(ctx context.Context, id int64) (*IngestJob, error)

	// GetSeveritiesByIDs returns a map of vulnerability ID to worst severity level (1-5)
	// for the given IDs by querying the vulnerability_summary table.
	GetSeveritiesByIDs(ctx context.Context, ids []string) (map[string]int, error)

	// GetEPSSHistory returns the full EPSS score history for a vulnerability.
	// Results are ordered by date ascending.
	GetEPSSHistory(ctx context.Context, vulnID string) ([]EPSSHistoryEntry, error)

	// UpsertEOLProduct upserts a product from endoflife.date.
	UpsertEOLProduct(ctx context.Context, product EOLProduct) error

	// UpsertEOLRelease upserts a release cycle from endoflife.date.
	UpsertEOLRelease(ctx context.Context, release EOLRelease) error

	// UpsertEOLIdentifier upserts a product identifier (purl/cpe) mapping.
	UpsertEOLIdentifier(ctx context.Context, ident EOLIdentifier) error

	// GetEOLByProduct returns EOL info for a product name.
	GetEOLByProduct(ctx context.Context, productName string) (*EOLProductDetail, error)

	// GetEOLByIdentifier finds EOL info by a purl or cpe identifier.
	GetEOLByIdentifier(ctx context.Context, identifierType, identifier string) (*EOLProductDetail, error)

	// GetDashboardSummary returns summary counts for the dashboard overview cards.
	GetDashboardSummary(ctx context.Context) (*DashboardSummary, error)

	// GetDashboardTrends returns time-series data for dashboard trend charts.
	// days specifies how many days of history to return (e.g., 30, 90).
	GetDashboardTrends(ctx context.Context, days int) (*DashboardTrends, error)

	// GetDashboardDistributions returns distribution data for dashboard charts
	// (severity, ecosystem, EPSS histogram, LEV histogram).
	GetDashboardDistributions(ctx context.Context) (*DashboardDistributions, error)

	// GetDashboardTopRisks returns top risky CVEs by EPSS and LEV scores.
	GetDashboardTopRisks(ctx context.Context, limit int) (*DashboardTopRisks, error)

	// GetTranslations retrieves available translations for a vulnerability detail
	// in the requested locales. Returns nil if no locales are requested.
	GetTranslations(ctx context.Context, q TranslationQuery) (*TranslationResult, error)

	// GetTranslatableTexts fetches all translatable text fields for a vulnerability.
	GetTranslatableTexts(ctx context.Context, vulnID string) (*TranslatableTexts, error)

	// ResolveVulnerabilityID resolves an input ID (CVE, OSV, alias) to a vulnerabilities.id.
	// Returns ("", nil) if not found.
	ResolveVulnerabilityID(ctx context.Context, id string) (string, error)

	// SaveVulnerabilityTranslation upserts a translation for a vulnerability's summary/details.
	SaveVulnerabilityTranslation(ctx context.Context, vulnID, locale, summary, details string, translatedAt time.Time) error

	// SaveKEVTranslation upserts a translation for KEV entry text fields.
	SaveKEVTranslation(ctx context.Context, kevEntryID int64, locale, vulnName, shortDesc, reqAction, notes string, translatedAt time.Time) error

	// SaveNVDDescriptionTranslation upserts a translation for an NVD description.
	SaveNVDDescriptionTranslation(ctx context.Context, nvdDescID int64, locale, value string, translatedAt time.Time) error

	// SaveOSVEntryTranslation upserts a translation for an OSV entry's summary/details.
	SaveOSVEntryTranslation(ctx context.Context, osvEntryID, locale, summary, details string, translatedAt time.Time) error

	// CreateTranslationJob records a new translation job and returns the auto-generated ID.
	CreateTranslationJob(ctx context.Context, job *TranslationJob) (int64, error)

	// UpdateTranslationJob updates an existing translation job (status, fields_translated, finish time).
	UpdateTranslationJob(ctx context.Context, job *TranslationJob) error

	// GetTranslationJob retrieves a translation job by ID. Returns nil, nil if not found.
	GetTranslationJob(ctx context.Context, id int64) (*TranslationJob, error)

	// ListTranslationJobs returns recent translation jobs ordered by start time (newest first).
	ListTranslationJobs(ctx context.Context, limit int) ([]TranslationJob, error)
}

// PackageQuery identifies a package to search for in the vulnerability database.
type PackageQuery struct {
	Ecosystem string
	Name      string
}

// SearchQuery defines parameters for searching vulnerabilities.
type SearchQuery struct {
	// ID searches by exact vulnerability ID (e.g., "CVE-2024-1234", "GO-2024-2687")
	ID string

	// Ecosystem filters by package ecosystem (e.g., "Go", "PyPI")
	Ecosystem string

	// PackageName filters by package name (e.g., "golang.org/x/crypto")
	PackageName string

	// Purl searches by Package URL (e.g., "pkg:npm/express")
	Purl string

	// CPE searches by CPE URI prefix (e.g., "cpe:2.3:a:apache:http_server")
	CPE string

	// Severity filters by normalized severity level (critical, high, medium, low, none).
	// Uses range overlap on vulnerability_summary.severity_worst/severity_best.
	Severity string

	// Since filters vulnerabilities modified on or after this date (RFC3339 or YYYY-MM-DD)
	Since string

	// Version filters by affected version (checks version ranges)
	Version string

	// InKEV filters to only vulnerabilities in the CISA KEV catalog
	InKEV *bool

	// Limit sets the maximum number of results (default: 100)
	Limit int

	// Offset for pagination (legacy, used when Cursor is empty)
	Offset int

	// Cursor is an opaque cursor string for keyset pagination.
	// When set, it takes precedence over Offset.
	// The cursor encodes (published, id) for stable ordering.
	Cursor string

	// Fields restricts the response to the specified fields only.
	// When set, the search uses a lightweight query that avoids fetching raw_json.
	// Supported fields: id, summary, modified, severity, ecosystem
	Fields []string

	// Sort specifies the sort order for results.
	// Valid values: "modified_desc" (default), "modified_asc", "published_desc", "published_asc"
	Sort string
}

// SyncState tracks the incremental import state for a data source.
type SyncState struct {
	Source         string // e.g., "Go", "npm", "NVD:2024", "GHSA:owner/repo"
	SourceType     string // osv, nvd, mitre, epss, kev, ghsa
	LastModifiedAt string // ISO 8601 timestamp from modified_id.csv
	LastSyncedAt   string // ISO 8601 timestamp when mayu last synced (from DB default NOW())
	RecordCount    int64
}

// EPSSCoverage holds summary statistics about EPSS data coverage.
type EPSSCoverage struct {
	TotalDays    int      // Total number of distinct dates with EPSS scores
	FirstDate    string   // Earliest EPSS score date (YYYY-MM-DD)
	LastDate     string   // Latest EPSS score date (YYYY-MM-DD)
	TotalScores  int64    // Total number of EPSS score records
	MissingDates []string // Dates in [FirstDate, LastDate] range that have no EPSS scores
}

// EPSSHistoryEntry represents a single EPSS score data point.
type EPSSHistoryEntry struct {
	Date       string  `json:"date"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
}

// EOLProduct represents a product for storage.
type EOLProduct struct {
	Name           string
	Label          string
	Category       string
	Tags           []string
	VersionCommand string
	LastModifiedAt *time.Time
	RawJSON        []byte
}

// EOLRelease represents a release cycle for storage.
type EOLRelease struct {
	ProductName       string
	ReleaseName       string
	Label             string
	Codename          sql.NullString
	ReleaseDate       *time.Time
	IsLts             *bool
	LtsFrom           *time.Time
	IsEoas            *bool
	EoasFrom          *time.Time
	IsEol             *bool
	EolFrom           *time.Time
	IsEoes            *bool
	EoesFrom          *time.Time
	IsMaintained      *bool
	LatestVersion     string
	LatestVersionDate *time.Time
	LatestVersionLink string
}

// EOLIdentifier represents a product identifier mapping for storage.
type EOLIdentifier struct {
	ProductName    string
	IdentifierType string
	Identifier     string
}

// EOLProductDetail is the enriched view of an EOL product with its releases.
type EOLProductDetail struct {
	Name           string           `json:"name"`
	Label          string           `json:"label"`
	Category       string           `json:"category,omitempty"`
	Tags           []string         `json:"tags,omitempty"`
	VersionCommand string           `json:"version_command,omitempty"`
	Releases       []EOLReleaseInfo `json:"releases,omitempty"`
}

// EOLReleaseInfo is the API-facing release information.
type EOLReleaseInfo struct {
	Name          string `json:"name"`
	Label         string `json:"label,omitempty"`
	Codename      string `json:"codename,omitempty"`
	ReleaseDate   string `json:"release_date,omitempty"`
	IsLts         *bool  `json:"is_lts,omitempty"`
	IsEol         *bool  `json:"is_eol,omitempty"`
	EolFrom       string `json:"eol_from,omitempty"`
	IsEoas        *bool  `json:"is_eoas,omitempty"`
	EoasFrom      string `json:"eoas_from,omitempty"`
	IsMaintained  *bool  `json:"is_maintained,omitempty"`
	LatestVersion string `json:"latest_version,omitempty"`
}

// DashboardSummary holds overview counts for the dashboard.
type DashboardSummary struct {
	TotalVulnerabilities int64 `json:"total_vulnerabilities"`
	Last7Days            int64 `json:"last_7_days"`
	Last30Days           int64 `json:"last_30_days"`
	CriticalCount        int64 `json:"critical_count"`
	HighCount            int64 `json:"high_count"`
	InKEVCount           int64 `json:"in_kev_count"`
}

// DashboardTrends holds time-series data for trend charts.
type DashboardTrends struct {
	// Daily new vulnerability counts
	DailyNewVulns []TrendDataPoint `json:"daily_new_vulns"`
}

// TrendDataPoint is a single date+count data point.
type TrendDataPoint struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

// DashboardDistributions holds distribution data for charts.
type DashboardDistributions struct {
	// Severity distribution (severity_worst counts) — pessimistic view
	Severity []DistributionItem `json:"severity"`
	// Severity distribution (severity_best counts) — optimistic view
	SeverityBest []DistributionItem `json:"severity_best"`
	// Top ecosystems by vulnerability count
	Ecosystems []DistributionItem `json:"ecosystems"`
	// EPSS score distribution (histogram buckets)
	EPSSHistogram []HistogramBucket `json:"epss_histogram"`
	// LEV score distribution (histogram buckets)
	LEVHistogram []HistogramBucket `json:"lev_histogram"`
}

// DistributionItem is a label+count pair for pie/bar charts.
type DistributionItem struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

// HistogramBucket is a range+count pair for histogram charts.
type HistogramBucket struct {
	RangeLabel string  `json:"range_label"`
	Min        float64 `json:"min"`
	Max        float64 `json:"max"`
	Count      int64   `json:"count"`
}

// DashboardTopRisks holds top risky CVEs.
type DashboardTopRisks struct {
	TopEPSS []RiskEntry `json:"top_epss"`
	TopLEV  []RiskEntry `json:"top_lev"`
}

// RiskEntry represents a single high-risk vulnerability.
type RiskEntry struct {
	VulnerabilityID string  `json:"vulnerability_id"`
	Summary         string  `json:"summary"`
	Score           float64 `json:"score"`
	Percentile      float64 `json:"percentile,omitempty"`
	Severity        string  `json:"severity,omitempty"`
}
