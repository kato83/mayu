//go:build integration

package store

import (
	"context"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/model"
)

func TestSearchWithSince(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	old := now.Add(-30 * 24 * time.Hour) // 30 days ago

	// Insert old vulnerability
	vulnOld := &model.Vulnerability{
		ID:       "GO-2024-OLD1",
		Modified: old,
		Summary:  "Old vulnerability",
		Affected: []model.Affected{{
			Package: model.Package{Ecosystem: "Go", Name: "example.com/old"},
		}},
	}

	// Insert recent vulnerability
	vulnNew := &model.Vulnerability{
		ID:       "GO-2024-NEW1",
		Modified: now,
		Summary:  "New vulnerability",
		Affected: []model.Affected{{
			Package: model.Package{Ecosystem: "Go", Name: "example.com/new"},
		}},
	}

	if err := store.UpsertBatch(ctx, []*model.Vulnerability{vulnOld, vulnNew}); err != nil {
		t.Fatalf("UpsertBatch failed: %v", err)
	}
	refreshAllSummaries(t, store, ctx)

	// Search with --since (should only return the new one)
	sinceDate := now.Add(-1 * time.Hour).Format("2006-01-02T15:04:05Z")
	results, err := store.Search(ctx, SearchQuery{
		Ecosystem: "Go",
		Since:     sinceDate,
	})
	if err != nil {
		t.Fatalf("Search with since failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result with --since, got %d", len(results))
	}
	if results[0].ID != "GO-2024-NEW1" {
		t.Errorf("expected GO-2024-NEW1, got %s", results[0].ID)
	}
}

func TestSearchWithVersion(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)

	// Insert vulnerability with enumerated versions
	vuln := &model.Vulnerability{
		ID:       "GO-2024-VER1",
		Modified: now,
		Summary:  "Version-specific vulnerability",
		Affected: []model.Affected{{
			Package:  model.Package{Ecosystem: "Go", Name: "example.com/pkg"},
			Versions: []string{"1.0.0", "1.1.0", "1.2.0", "1.3.0"},
		}},
	}

	// Insert vulnerability without the target version
	vulnOther := &model.Vulnerability{
		ID:       "GO-2024-VER2",
		Modified: now,
		Summary:  "Other vulnerability",
		Affected: []model.Affected{{
			Package:  model.Package{Ecosystem: "Go", Name: "example.com/other"},
			Versions: []string{"2.0.0", "2.1.0"},
		}},
	}

	if err := store.UpsertBatch(ctx, []*model.Vulnerability{vuln, vulnOther}); err != nil {
		t.Fatalf("UpsertBatch failed: %v", err)
	}

	// Search by version that exists
	results, err := store.Search(ctx, SearchQuery{
		Version: "1.2.0",
	})
	if err != nil {
		t.Fatalf("Search with version failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for version 1.2.0, got %d", len(results))
	}
	if results[0].ID != "GO-2024-VER1" {
		t.Errorf("expected GO-2024-VER1, got %s", results[0].ID)
	}

	// Search by version that doesn't exist
	results, err = store.Search(ctx, SearchQuery{
		Version: "9.9.9",
	})
	if err != nil {
		t.Fatalf("Search with non-existent version failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for version 9.9.9, got %d", len(results))
	}
}

func TestSearchWithOffset(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)

	// Insert 5 vulnerabilities
	vulns := make([]*model.Vulnerability, 5)
	for i := range vulns {
		vulns[i] = &model.Vulnerability{
			ID:       "GO-2024-OFF" + string(rune('A'+i)),
			Modified: now.Add(time.Duration(i) * time.Hour),
			Summary:  "Offset test vulnerability",
			Affected: []model.Affected{{
				Package: model.Package{Ecosystem: "Go", Name: "example.com/offset"},
			}},
		}
	}

	if err := store.UpsertBatch(ctx, vulns); err != nil {
		t.Fatalf("UpsertBatch failed: %v", err)
	}

	// Get first 2
	results1, err := store.Search(ctx, SearchQuery{
		PackageName: "example.com/offset",
		Limit:       2,
		Offset:      0,
	})
	if err != nil {
		t.Fatalf("Search page 1 failed: %v", err)
	}
	if len(results1) != 2 {
		t.Fatalf("expected 2 results for page 1, got %d", len(results1))
	}

	// Get next 2
	results2, err := store.Search(ctx, SearchQuery{
		PackageName: "example.com/offset",
		Limit:       2,
		Offset:      2,
	})
	if err != nil {
		t.Fatalf("Search page 2 failed: %v", err)
	}
	if len(results2) != 2 {
		t.Fatalf("expected 2 results for page 2, got %d", len(results2))
	}

	// Ensure no overlap between pages
	for _, r1 := range results1 {
		for _, r2 := range results2 {
			if r1.ID == r2.ID {
				t.Errorf("overlapping result between pages: %s", r1.ID)
			}
		}
	}
}

func TestCount(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)

	// Insert 3 vulnerabilities
	vulns := []*model.Vulnerability{
		{
			ID:       "GO-2024-CNT1",
			Modified: now,
			Summary:  "Count test 1",
			Affected: []model.Affected{{
				Package: model.Package{Ecosystem: "Go", Name: "example.com/count"},
			}},
		},
		{
			ID:       "GO-2024-CNT2",
			Modified: now.Add(time.Hour),
			Summary:  "Count test 2",
			Affected: []model.Affected{{
				Package: model.Package{Ecosystem: "Go", Name: "example.com/count"},
			}},
		},
		{
			ID:       "PYSEC-2024-CNT1",
			Modified: now,
			Summary:  "Count test PyPI",
			Affected: []model.Affected{{
				Package: model.Package{Ecosystem: "PyPI", Name: "example-pkg"},
			}},
		},
	}

	if err := store.UpsertBatch(ctx, vulns); err != nil {
		t.Fatalf("UpsertBatch failed: %v", err)
	}
	refreshAllSummaries(t, store, ctx)

	t.Run("count all", func(t *testing.T) {
		count, err := store.Count(ctx, SearchQuery{})
		if err != nil {
			t.Fatalf("Count failed: %v", err)
		}
		if count != 3 {
			t.Errorf("expected count=3, got %d", count)
		}
	})

	t.Run("count by ecosystem", func(t *testing.T) {
		count, err := store.Count(ctx, SearchQuery{Ecosystem: "Go"})
		if err != nil {
			t.Fatalf("Count by ecosystem failed: %v", err)
		}
		if count != 2 {
			t.Errorf("expected count=2 for Go, got %d", count)
		}
	})

	t.Run("count by package", func(t *testing.T) {
		count, err := store.Count(ctx, SearchQuery{PackageName: "example.com/count"})
		if err != nil {
			t.Fatalf("Count by package failed: %v", err)
		}
		if count != 2 {
			t.Errorf("expected count=2 for example.com/count, got %d", count)
		}
	})

	t.Run("count with since", func(t *testing.T) {
		sinceDate := now.Add(30 * time.Minute).Format("2006-01-02T15:04:05Z")
		count, err := store.Count(ctx, SearchQuery{
			Ecosystem: "Go",
			Since:     sinceDate,
		})
		if err != nil {
			t.Fatalf("Count with since failed: %v", err)
		}
		if count != 1 {
			t.Errorf("expected count=1 for Go since %s, got %d", sinceDate, count)
		}
	})

	t.Run("count no results", func(t *testing.T) {
		count, err := store.Count(ctx, SearchQuery{ID: "NONEXISTENT"})
		if err != nil {
			t.Fatalf("Count no results failed: %v", err)
		}
		if count != 0 {
			t.Errorf("expected count=0, got %d", count)
		}
	})
}

func TestSearchWithSeverity(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)

	// Note: Severity filter uses the cvss_base_score SQL function from migration 000006.
	// Insert vulnerabilities with severity scores stored in osv_severity table.
	vulnCritical := &model.Vulnerability{
		ID:       "GO-2024-SEV1",
		Modified: now,
		Summary:  "Critical severity",
		Severity: []model.Severity{
			{Type: model.SeverityTypeCVSSV3, Score: "9.8"},
		},
		Affected: []model.Affected{{
			Package: model.Package{Ecosystem: "Go", Name: "example.com/critical"},
		}},
	}

	vulnLow := &model.Vulnerability{
		ID:       "GO-2024-SEV2",
		Modified: now,
		Summary:  "Low severity",
		Severity: []model.Severity{
			{Type: model.SeverityTypeCVSSV3, Score: "2.5"},
		},
		Affected: []model.Affected{{
			Package: model.Package{Ecosystem: "Go", Name: "example.com/low"},
		}},
	}

	vulnNoSev := &model.Vulnerability{
		ID:       "GO-2024-SEV3",
		Modified: now,
		Summary:  "No severity",
		Affected: []model.Affected{{
			Package: model.Package{Ecosystem: "Go", Name: "example.com/nosev"},
		}},
	}

	if err := store.UpsertBatch(ctx, []*model.Vulnerability{vulnCritical, vulnLow, vulnNoSev}); err != nil {
		t.Fatalf("UpsertBatch failed: %v", err)
	}

	// Refresh vulnerability_summary so severity filter works
	if err := store.RefreshSummary(ctx, []string{"GO-2024-SEV1", "GO-2024-SEV2", "GO-2024-SEV3"}); err != nil {
		t.Fatalf("RefreshSummary failed: %v", err)
	}

	t.Run("critical filter", func(t *testing.T) {
		results, err := store.Search(ctx, SearchQuery{
			Ecosystem: "Go",
			Severity:  "critical",
		})
		if err != nil {
			t.Fatalf("Search with severity=critical failed: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 critical result, got %d", len(results))
		}
		if results[0].ID != "GO-2024-SEV1" {
			t.Errorf("expected GO-2024-SEV1, got %s", results[0].ID)
		}
	})

	t.Run("low filter", func(t *testing.T) {
		results, err := store.Search(ctx, SearchQuery{
			Ecosystem: "Go",
			Severity:  "low",
		})
		if err != nil {
			t.Fatalf("Search with severity=low failed: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 low result, got %d", len(results))
		}
		if results[0].ID != "GO-2024-SEV2" {
			t.Errorf("expected GO-2024-SEV2, got %s", results[0].ID)
		}
	})
}
