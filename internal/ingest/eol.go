package ingest

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/store"
)

// ImportEOL imports all product lifecycle data from endoflife.date.
// It fetches the product list, then fetches each product's detail (with releases).
func ImportEOL(ctx context.Context, s store.Store, update bool) error {
	log.Println("Fetching endoflife.date product list...")

	// Check sync state for delta
	if update {
		state, err := s.GetSyncState(ctx, "EOL")
		if err != nil {
			return fmt.Errorf("get sync state: %w", err)
		}
		if state != nil {
			lastSynced, parseErr := time.Parse(time.RFC3339Nano, state.LastSyncedAt)
			if parseErr == nil && time.Since(lastSynced) < 24*time.Hour {
				log.Printf("EOL data synced %s ago (< 24h), skipping update", time.Since(lastSynced).Round(time.Minute))
				return nil
			}
		}
	}

	products, err := fetcher.FetchEOLProducts(ctx)
	if err != nil {
		return err
	}
	log.Printf("Found %d products on endoflife.date", len(products))

	var imported, failed int
	for i, p := range products {
		if ctx.Err() != nil {
			log.Printf("EOL import interrupted after %d/%d products", i, len(products))
			break
		}

		if err := importEOLProduct(ctx, s, p.Name); err != nil {
			log.Printf("  [%d/%d] FAILED %s: %v", i+1, len(products), p.Name, err)
			failed++
			continue
		}
		imported++

		if (i+1)%50 == 0 {
			log.Printf("  [%d/%d] imported %d products...", i+1, len(products), imported)
		}

		// Rate limiting: 100ms between requests to be respectful
		select {
		case <-ctx.Done():
			continue
		case <-time.After(100 * time.Millisecond):
		}
	}

	log.Printf("EOL import complete: %d imported, %d failed (total %d)", imported, failed, len(products))

	// Update sync state
	if err := s.UpdateSyncState(ctx, &store.SyncState{
		Source:         "EOL",
		SourceType:     "eol",
		LastModifiedAt: time.Now().Format(time.RFC3339),
		RecordCount:    int64(imported),
	}); err != nil {
		return fmt.Errorf("update sync state: %w", err)
	}

	return nil
}

// importEOLProduct fetches and stores a single product's detail.
func importEOLProduct(ctx context.Context, s store.Store, productName string) error {
	detail, rawJSON, err := fetcher.FetchEOLProductDetail(ctx, productName)
	if err != nil {
		return err
	}

	product := detail.Result

	// Parse last_modified
	var lastModified *time.Time
	if detail.LastModified != "" {
		t, err := time.Parse(time.RFC3339, detail.LastModified)
		if err == nil {
			lastModified = &t
		}
	}

	// Upsert product
	ep := store.EOLProduct{
		Name:           product.Name,
		Label:          product.Label,
		Category:       product.Category,
		Tags:           product.Tags,
		VersionCommand: product.VersionCommand,
		LastModifiedAt: lastModified,
		RawJSON:        rawJSON,
	}
	if err := s.UpsertEOLProduct(ctx, ep); err != nil {
		return fmt.Errorf("upsert product: %w", err)
	}

	// Upsert releases
	for _, r := range product.Releases {
		er := store.EOLRelease{
			ProductName:  product.Name,
			ReleaseName:  r.Name,
			Label:        r.Label,
			ReleaseDate:  parseDate(r.ReleaseDate),
			IsLts:        r.IsLts,
			LtsFrom:      parseDatePtr(r.LtsFrom),
			IsEoas:       r.IsEoas,
			EoasFrom:     parseDatePtr(r.EoasFrom),
			IsEol:        r.IsEol,
			EolFrom:      parseDatePtr(r.EolFrom),
			IsEoes:       r.IsEoes,
			EoesFrom:     parseDatePtr(r.EoesFrom),
			IsMaintained: r.IsMaintained,
		}
		if r.Codename != nil {
			er.Codename = sql.NullString{String: *r.Codename, Valid: true}
		}
		if r.Latest != nil {
			er.LatestVersion = r.Latest.Name
			er.LatestVersionDate = parseDate(r.Latest.Date)
			er.LatestVersionLink = r.Latest.Link
		}
		if err := s.UpsertEOLRelease(ctx, er); err != nil {
			return fmt.Errorf("upsert release %s/%s: %w", product.Name, r.Name, err)
		}
	}

	// Upsert identifiers
	for _, ident := range product.Identifiers {
		if ident.Type == "purl" || ident.Type == "cpe" {
			ei := store.EOLIdentifier{
				ProductName:    product.Name,
				IdentifierType: ident.Type,
				Identifier:     ident.ID,
			}
			if err := s.UpsertEOLIdentifier(ctx, ei); err != nil {
				return fmt.Errorf("upsert identifier %s/%s: %w", ident.Type, ident.ID, err)
			}
		}
	}

	return nil
}

// parseDate parses a date string (YYYY-MM-DD) into *time.Time.
func parseDate(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil
	}
	return &t
}

// parseDatePtr parses a *string date (YYYY-MM-DD) into *time.Time.
func parseDatePtr(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	return parseDate(*s)
}
