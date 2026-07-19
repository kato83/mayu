package fetcher

import (
	"context"
	"fmt"

	"github.com/kato83/mayu/internal/model"
)

const (
	// kevCatalogURL is the URL for the CISA KEV catalog JSON feed.
	kevCatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// FetchKEVCatalog downloads the full CISA KEV (Known Exploited Vulnerabilities)
// catalog and returns parsed KEVRecord entries ready for storage.
//
// The catalog is a single JSON file (~1-2 MB) containing all known exploited
// vulnerabilities. Unlike EPSS (daily snapshots), KEV is a cumulative catalog
// that only grows — entries are never removed.
func (f *Fetcher) FetchKEVCatalog(ctx context.Context) (*model.KEVCatalog, error) {
	data, err := f.download(ctx, kevCatalogURL)
	if err != nil {
		return nil, fmt.Errorf("download KEV catalog: %w", err)
	}

	catalog, err := model.ParseKEVCatalog(data)
	if err != nil {
		return nil, fmt.Errorf("parse KEV catalog: %w", err)
	}

	return catalog, nil
}

// FetchKEVCatalogFromURL downloads the KEV catalog from a custom URL.
// This is useful for testing or using a mirrored/cached copy.
func (f *Fetcher) FetchKEVCatalogFromURL(ctx context.Context, url string) (*model.KEVCatalog, error) {
	data, err := f.download(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("download KEV catalog from %s: %w", url, err)
	}

	catalog, err := model.ParseKEVCatalog(data)
	if err != nil {
		return nil, fmt.Errorf("parse KEV catalog: %w", err)
	}

	return catalog, nil
}
