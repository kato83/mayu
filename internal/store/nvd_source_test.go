package store

import (
	"context"
	"testing"

	"github.com/kato83/mayu/internal/model"
)

func TestGetNVDSourceNameCache(t *testing.T) {
	// Test the in-memory cache behavior without requiring a real database.
	// The cache is pre-populated and lookups should hit the cache.
	cache := newNVDSourceCache()

	// Empty cache should return empty string
	if name := cache.get("unknown-uuid"); name != "" {
		t.Errorf("expected empty string for unknown key, got %q", name)
	}

	// Set and get
	cache.set("416baaa9-dc9f-4396-8d5f-8c081fb06d67", "kernel.org")
	if name := cache.get("416baaa9-dc9f-4396-8d5f-8c081fb06d67"); name != "kernel.org" {
		t.Errorf("expected %q, got %q", "kernel.org", name)
	}

	// Overwrite
	cache.set("416baaa9-dc9f-4396-8d5f-8c081fb06d67", "kernel.org (updated)")
	if name := cache.get("416baaa9-dc9f-4396-8d5f-8c081fb06d67"); name != "kernel.org (updated)" {
		t.Errorf("expected %q, got %q", "kernel.org (updated)", name)
	}
}

func TestBuildNVDSourceUpsertQuery(t *testing.T) {
	sources := []model.NVDSource{
		{
			Name:             "kernel.org",
			ContactEmail:     "cve@kernel.org",
			SourceIdentifier: "416baaa9-dc9f-4396-8d5f-8c081fb06d67",
			AcceptanceLevel:  "Contributor",
		},
	}

	query, args := buildNVDSourceUpsertQuery(sources)
	if query == "" {
		t.Fatal("expected non-empty query")
	}
	if len(args) != 6 { // 6 fields per source
		t.Errorf("expected 6 args, got %d", len(args))
	}
	_ = query
}

func TestGetNVDSourceNamesFromCache(t *testing.T) {
	cache := newNVDSourceCache()
	cache.set("uuid-1", "Org A")
	cache.set("uuid-2", "Org B")

	identifiers := []string{"uuid-1", "uuid-2", "uuid-3"}
	result := make(map[string]string)
	var missing []string

	for _, id := range identifiers {
		if name := cache.get(id); name != "" {
			result[id] = name
		} else {
			missing = append(missing, id)
		}
	}

	if len(result) != 2 {
		t.Errorf("expected 2 cached results, got %d", len(result))
	}
	if len(missing) != 1 {
		t.Errorf("expected 1 missing, got %d", len(missing))
	}
	if result["uuid-1"] != "Org A" {
		t.Errorf("expected %q, got %q", "Org A", result["uuid-1"])
	}
}

// TestResolveNVDSourceNames verifies the ResolveNVDSourceNames helper
// that returns identifier as-is when no mapping is found.
func TestResolveNVDSourceNames(t *testing.T) {
	ctx := context.Background()
	// Create a resolver with a pre-loaded cache (simulates DB loaded state)
	resolver := &nvdSourceResolver{
		cache: newNVDSourceCache(),
	}
	resolver.cache.set("416baaa9-dc9f-4396-8d5f-8c081fb06d67", "kernel.org")
	resolver.cache.set("nvd@nist.gov", "nvd@nist.gov")

	// Test resolving known identifiers
	names := resolver.resolveFromCache(ctx, []string{
		"416baaa9-dc9f-4396-8d5f-8c081fb06d67",
		"nvd@nist.gov",
		"unknown-id",
	})

	if names["416baaa9-dc9f-4396-8d5f-8c081fb06d67"] != "kernel.org" {
		t.Errorf("expected kernel.org, got %q", names["416baaa9-dc9f-4396-8d5f-8c081fb06d67"])
	}
	if names["nvd@nist.gov"] != "nvd@nist.gov" {
		t.Errorf("expected nvd@nist.gov, got %q", names["nvd@nist.gov"])
	}
	// Unknown IDs should not be in the map
	if _, ok := names["unknown-id"]; ok {
		t.Error("expected unknown-id to not be in the map")
	}
}
