//go:build integration

package store

import (
	"context"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/model"
)

func TestUpsertNVDSources(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)

	t.Run("insert new sources", func(t *testing.T) {
		sources := []model.NVDSource{
			{
				Name:             "kernel.org",
				ContactEmail:     "cve@kernel.org",
				SourceIdentifier: "416baaa9-dc9f-4396-8d5f-8c081fb06d67",
				AcceptanceLevel:  "Contributor",
				LastModified:     &now,
				CreatedAt:        &now,
			},
			{
				Name:             "CISA-ADP",
				ContactEmail:     "",
				SourceIdentifier: "134c704f-9b21-4f2e-91b3-4a467353bcc0",
				AcceptanceLevel:  "Partner",
				LastModified:     &now,
				CreatedAt:        &now,
			},
		}

		if err := store.UpsertNVDSources(ctx, sources); err != nil {
			t.Fatalf("UpsertNVDSources (insert) failed: %v", err)
		}

		// Verify rows exist in database
		var count int
		err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM nvd_sources`).Scan(&count)
		if err != nil {
			t.Fatalf("count nvd_sources: %v", err)
		}
		if count != 2 {
			t.Errorf("expected 2 rows, got %d", count)
		}

		// Verify specific row
		var name, contactEmail string
		err = store.db.QueryRowContext(ctx,
			`SELECT name, COALESCE(contact_email, '') FROM nvd_sources WHERE source_identifier = $1`,
			"416baaa9-dc9f-4396-8d5f-8c081fb06d67").Scan(&name, &contactEmail)
		if err != nil {
			t.Fatalf("query kernel.org source: %v", err)
		}
		if name != "kernel.org" {
			t.Errorf("name = %q, want %q", name, "kernel.org")
		}
		if contactEmail != "cve@kernel.org" {
			t.Errorf("contact_email = %q, want %q", contactEmail, "cve@kernel.org")
		}
	})

	t.Run("upsert updates existing source", func(t *testing.T) {
		updated := []model.NVDSource{
			{
				Name:             "Linux Kernel Organization",
				ContactEmail:     "security@kernel.org",
				SourceIdentifier: "416baaa9-dc9f-4396-8d5f-8c081fb06d67",
				AcceptanceLevel:  "Authorized",
				LastModified:     timePtr(now.Add(time.Hour)),
				CreatedAt:        &now,
			},
		}

		if err := store.UpsertNVDSources(ctx, updated); err != nil {
			t.Fatalf("UpsertNVDSources (update) failed: %v", err)
		}

		// Verify name was updated
		var name, contactEmail, acceptanceLevel string
		err := store.db.QueryRowContext(ctx,
			`SELECT name, COALESCE(contact_email, ''), COALESCE(acceptance_level, '') FROM nvd_sources WHERE source_identifier = $1`,
			"416baaa9-dc9f-4396-8d5f-8c081fb06d67").Scan(&name, &contactEmail, &acceptanceLevel)
		if err != nil {
			t.Fatalf("query updated source: %v", err)
		}
		if name != "Linux Kernel Organization" {
			t.Errorf("name = %q, want %q", name, "Linux Kernel Organization")
		}
		if contactEmail != "security@kernel.org" {
			t.Errorf("contact_email = %q, want %q", contactEmail, "security@kernel.org")
		}
		if acceptanceLevel != "Authorized" {
			t.Errorf("acceptance_level = %q, want %q", acceptanceLevel, "Authorized")
		}

		// Verify total count unchanged
		var count int
		err = store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM nvd_sources`).Scan(&count)
		if err != nil {
			t.Fatalf("count after update: %v", err)
		}
		if count != 2 {
			t.Errorf("expected 2 rows after update, got %d", count)
		}
	})

	t.Run("empty slice is no-op", func(t *testing.T) {
		if err := store.UpsertNVDSources(ctx, nil); err != nil {
			t.Fatalf("UpsertNVDSources (nil) failed: %v", err)
		}
		if err := store.UpsertNVDSources(ctx, []model.NVDSource{}); err != nil {
			t.Fatalf("UpsertNVDSources (empty) failed: %v", err)
		}
	})
}

func TestGetNVDSourceName(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)

	// Insert test data
	sources := []model.NVDSource{
		{
			Name:             "kernel.org",
			ContactEmail:     "cve@kernel.org",
			SourceIdentifier: "416baaa9-dc9f-4396-8d5f-8c081fb06d67",
			AcceptanceLevel:  "Contributor",
			LastModified:     &now,
			CreatedAt:        &now,
		},
		{
			Name:             "NVD NIST",
			ContactEmail:     "nvd@nist.gov",
			SourceIdentifier: "nvd@nist.gov",
			AcceptanceLevel:  "",
			LastModified:     &now,
			CreatedAt:        &now,
		},
	}
	if err := store.UpsertNVDSources(ctx, sources); err != nil {
		t.Fatalf("setup UpsertNVDSources failed: %v", err)
	}

	// Clear cache to test database fallback
	store.nvdSourceCache.loadAll(make(map[string]string))

	t.Run("get by UUID", func(t *testing.T) {
		name, err := store.GetNVDSourceName(ctx, "416baaa9-dc9f-4396-8d5f-8c081fb06d67")
		if err != nil {
			t.Fatalf("GetNVDSourceName (UUID) failed: %v", err)
		}
		if name != "kernel.org" {
			t.Errorf("name = %q, want %q", name, "kernel.org")
		}
	})

	t.Run("get by email", func(t *testing.T) {
		name, err := store.GetNVDSourceName(ctx, "nvd@nist.gov")
		if err != nil {
			t.Fatalf("GetNVDSourceName (email) failed: %v", err)
		}
		if name != "NVD NIST" {
			t.Errorf("name = %q, want %q", name, "NVD NIST")
		}
	})

	t.Run("not found returns empty string", func(t *testing.T) {
		name, err := store.GetNVDSourceName(ctx, "nonexistent-uuid-1234")
		if err != nil {
			t.Fatalf("GetNVDSourceName (not found) failed: %v", err)
		}
		if name != "" {
			t.Errorf("expected empty string for nonexistent key, got %q", name)
		}
	})

	t.Run("empty identifier returns empty string", func(t *testing.T) {
		name, err := store.GetNVDSourceName(ctx, "")
		if err != nil {
			t.Fatalf("GetNVDSourceName (empty) failed: %v", err)
		}
		if name != "" {
			t.Errorf("expected empty string for empty identifier, got %q", name)
		}
	})

	t.Run("cache is populated after DB lookup", func(t *testing.T) {
		// Clear cache again
		store.nvdSourceCache.loadAll(make(map[string]string))

		// First call hits DB
		_, err := store.GetNVDSourceName(ctx, "416baaa9-dc9f-4396-8d5f-8c081fb06d67")
		if err != nil {
			t.Fatalf("GetNVDSourceName failed: %v", err)
		}

		// Verify cache was populated
		cached := store.nvdSourceCache.get("416baaa9-dc9f-4396-8d5f-8c081fb06d67")
		if cached != "kernel.org" {
			t.Errorf("cache not populated: got %q, want %q", cached, "kernel.org")
		}
	})
}

func TestGetNVDSourceNames(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)

	// Insert test data
	sources := []model.NVDSource{
		{
			Name:             "kernel.org",
			ContactEmail:     "cve@kernel.org",
			SourceIdentifier: "416baaa9-dc9f-4396-8d5f-8c081fb06d67",
			LastModified:     &now,
			CreatedAt:        &now,
		},
		{
			Name:             "CISA-ADP",
			SourceIdentifier: "134c704f-9b21-4f2e-91b3-4a467353bcc0",
			LastModified:     &now,
			CreatedAt:        &now,
		},
		{
			Name:             "NVD NIST",
			ContactEmail:     "nvd@nist.gov",
			SourceIdentifier: "nvd@nist.gov",
			LastModified:     &now,
			CreatedAt:        &now,
		},
	}
	if err := store.UpsertNVDSources(ctx, sources); err != nil {
		t.Fatalf("setup UpsertNVDSources failed: %v", err)
	}

	// Clear cache to test full DB fetch path
	store.nvdSourceCache.loadAll(make(map[string]string))

	t.Run("batch resolve multiple identifiers", func(t *testing.T) {
		ids := []string{
			"416baaa9-dc9f-4396-8d5f-8c081fb06d67",
			"134c704f-9b21-4f2e-91b3-4a467353bcc0",
			"nvd@nist.gov",
			"unknown-identifier",
		}

		result, err := store.GetNVDSourceNames(ctx, ids)
		if err != nil {
			t.Fatalf("GetNVDSourceNames failed: %v", err)
		}

		if len(result) != 3 {
			t.Errorf("expected 3 results, got %d", len(result))
		}
		if result["416baaa9-dc9f-4396-8d5f-8c081fb06d67"] != "kernel.org" {
			t.Errorf("kernel.org UUID = %q, want %q", result["416baaa9-dc9f-4396-8d5f-8c081fb06d67"], "kernel.org")
		}
		if result["134c704f-9b21-4f2e-91b3-4a467353bcc0"] != "CISA-ADP" {
			t.Errorf("CISA UUID = %q, want %q", result["134c704f-9b21-4f2e-91b3-4a467353bcc0"], "CISA-ADP")
		}
		if result["nvd@nist.gov"] != "NVD NIST" {
			t.Errorf("nvd@nist.gov = %q, want %q", result["nvd@nist.gov"], "NVD NIST")
		}
		if _, ok := result["unknown-identifier"]; ok {
			t.Error("unknown-identifier should not be in result map")
		}
	})

	t.Run("cache hit avoids DB query", func(t *testing.T) {
		// Pre-populate cache
		store.nvdSourceCache.loadAll(map[string]string{
			"cached-id": "Cached Org",
		})

		result, err := store.GetNVDSourceNames(ctx, []string{"cached-id"})
		if err != nil {
			t.Fatalf("GetNVDSourceNames (cache hit) failed: %v", err)
		}
		if result["cached-id"] != "Cached Org" {
			t.Errorf("cached-id = %q, want %q", result["cached-id"], "Cached Org")
		}
	})

	t.Run("empty identifiers returns nil", func(t *testing.T) {
		result, err := store.GetNVDSourceNames(ctx, nil)
		if err != nil {
			t.Fatalf("GetNVDSourceNames (nil) failed: %v", err)
		}
		if result != nil {
			t.Errorf("expected nil for empty identifiers, got %v", result)
		}
	})
}

func TestLoadNVDSourceCache(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)

	// Insert test data directly
	sources := []model.NVDSource{
		{
			Name:             "kernel.org",
			ContactEmail:     "cve@kernel.org",
			SourceIdentifier: "416baaa9-dc9f-4396-8d5f-8c081fb06d67",
			LastModified:     &now,
			CreatedAt:        &now,
		},
		{
			Name:             "CISA-ADP",
			SourceIdentifier: "134c704f-9b21-4f2e-91b3-4a467353bcc0",
			LastModified:     &now,
			CreatedAt:        &now,
		},
		{
			Name:             "NVD NIST",
			ContactEmail:     "nvd@nist.gov",
			SourceIdentifier: "nvd@nist.gov",
			LastModified:     &now,
			CreatedAt:        &now,
		},
	}
	if err := store.UpsertNVDSources(ctx, sources); err != nil {
		t.Fatalf("setup UpsertNVDSources failed: %v", err)
	}

	// Clear the cache completely
	store.nvdSourceCache.loadAll(make(map[string]string))

	// Load cache from DB
	if err := store.LoadNVDSourceCache(ctx); err != nil {
		t.Fatalf("LoadNVDSourceCache failed: %v", err)
	}

	// Verify all entries are now in cache
	tests := []struct {
		identifier string
		wantName   string
	}{
		{"416baaa9-dc9f-4396-8d5f-8c081fb06d67", "kernel.org"},
		{"134c704f-9b21-4f2e-91b3-4a467353bcc0", "CISA-ADP"},
		{"nvd@nist.gov", "NVD NIST"},
	}

	for _, tt := range tests {
		name := store.nvdSourceCache.get(tt.identifier)
		if name != tt.wantName {
			t.Errorf("cache[%q] = %q, want %q", tt.identifier, name, tt.wantName)
		}
	}

	// Verify unknown key still returns empty
	if name := store.nvdSourceCache.get("unknown"); name != "" {
		t.Errorf("expected empty for unknown, got %q", name)
	}

	// Verify that GetNVDSourceName works purely from cache (no DB query needed)
	// by testing it still works after verifying cache state
	name, err := store.GetNVDSourceName(ctx, "416baaa9-dc9f-4396-8d5f-8c081fb06d67")
	if err != nil {
		t.Fatalf("GetNVDSourceName (from cache) failed: %v", err)
	}
	if name != "kernel.org" {
		t.Errorf("GetNVDSourceName from cache = %q, want %q", name, "kernel.org")
	}
}
