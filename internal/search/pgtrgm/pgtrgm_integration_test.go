//go:build integration

package pgtrgm_test

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kato83/mayu/internal/search"
	"github.com/kato83/mayu/internal/search/pgtrgm"
	"github.com/kato83/mayu/internal/testhelper"
)

func setupDB(t *testing.T) *sql.DB {
	t.Helper()
	pg := testhelper.SetupPostgres(t)
	db, err := sql.Open("pgx", pg.DatabaseURL)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func seedTestData(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()

	// Insert test vulnerabilities
	vulns := []struct {
		id      string
		summary string
		details string
	}{
		{"CVE-2021-44228", "Remote code injection in Log4j", "Apache Log4j2 allows remote code execution via JNDI lookups."},
		{"CVE-2023-38831", "RARLAB WinRAR code execution vulnerability", "WinRAR before 6.23 allows arbitrary code execution via crafted ZIP archives."},
		{"CVE-2024-3094", "Xz: malicious code in distributed source", "XZ Utils 5.6.0 and 5.6.1 contain a backdoor enabling remote code execution on SSH servers."},
		{"CVE-2014-0160", "Heartbleed - OpenSSL TLS heartbeat read overrun", "The TLS heartbeat extension in OpenSSL allows remote attackers to read memory contents."},
		{"CVE-2017-5638", "Apache Struts remote code execution", "Apache Struts 2 allows remote code execution via a crafted Content-Type header."},
	}

	for _, v := range vulns {
		_, err := db.ExecContext(ctx,
			`INSERT INTO vulnerabilities (id, summary, details) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
			v.id, v.summary, v.details,
		)
		if err != nil {
			t.Fatalf("failed to insert vulnerability %s: %v", v.id, err)
		}
	}

	// Insert Japanese translations
	translations := []struct {
		vulnID  string
		summary string
		details string
	}{
		{"CVE-2021-44228", "Apache Log4j2のリモートコード実行の脆弱性", "Apache Log4j2においてJNDI機能を利用したリモートコード実行が可能です。"},
		{"CVE-2023-38831", "WinRARにおける任意コード実行の脆弱性", "WinRAR 6.23より前のバージョンで細工されたZIPアーカイブにより任意のコードが実行されます。"},
		{"CVE-2024-3094", "XZ Utilsのバックドア脆弱性", "XZ Utils 5.6.0および5.6.1にバックドアが仕込まれSSHサーバーへのリモートコード実行を可能にします。"},
	}

	for _, tr := range translations {
		_, err := db.ExecContext(ctx,
			`INSERT INTO vulnerabilities_translation (vulnerability_id, locale, summary, details) VALUES ($1, 'ja', $2, $3) ON CONFLICT DO NOTHING`,
			tr.vulnID, tr.summary, tr.details,
		)
		if err != nil {
			t.Fatalf("failed to insert translation for %s: %v", tr.vulnID, err)
		}
	}
}

func TestEngine_Init(t *testing.T) {
	db := setupDB(t)
	engine := pgtrgm.New(db)
	ctx := context.Background()

	// Before init, Available should return ErrNotInitialized
	err := engine.Available(ctx)
	if err != search.ErrNotInitialized {
		t.Fatalf("expected ErrNotInitialized before Init, got: %v", err)
	}

	// Run Init
	var steps []string
	progress := func(step string, current, total int) {
		steps = append(steps, step)
	}
	if err := engine.Init(ctx, progress); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify progress was reported
	if len(steps) == 0 {
		t.Error("expected progress callbacks, got none")
	}

	// After init, Available should return nil
	if err := engine.Available(ctx); err != nil {
		t.Fatalf("expected Available to succeed after Init, got: %v", err)
	}
}

func TestEngine_Init_Idempotent(t *testing.T) {
	db := setupDB(t)
	engine := pgtrgm.New(db)
	ctx := context.Background()

	// Init twice should not error
	if err := engine.Init(ctx, nil); err != nil {
		t.Fatalf("first Init failed: %v", err)
	}
	if err := engine.Init(ctx, nil); err != nil {
		t.Fatalf("second Init failed: %v", err)
	}
}

func TestEngine_Search_English(t *testing.T) {
	db := setupDB(t)
	engine := pgtrgm.New(db)
	ctx := context.Background()

	if err := engine.Init(ctx, nil); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	seedTestData(t, db)

	tests := []struct {
		name     string
		query    string
		minCount int
		wantIDs  []string // at least these IDs should appear
	}{
		{
			name:     "search by keyword in summary",
			query:    "remote code execution",
			minCount: 3,
			wantIDs:  []string{"CVE-2021-44228", "CVE-2024-3094", "CVE-2017-5638"},
		},
		{
			name:     "search by specific product name",
			query:    "WinRAR",
			minCount: 1,
			wantIDs:  []string{"CVE-2023-38831"},
		},
		{
			name:     "search in details field",
			query:    "heartbeat",
			minCount: 1,
			wantIDs:  []string{"CVE-2014-0160"},
		},
		{
			name:     "search with no results",
			query:    "zzzznonexistentkeywordxyz",
			minCount: 0,
			wantIDs:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, total, err := engine.Search(ctx, search.Query{
				Text:  tt.query,
				Limit: 20,
			})
			if err != nil {
				t.Fatalf("Search failed: %v", err)
			}

			if int(total) < tt.minCount {
				t.Errorf("expected at least %d results, got %d", tt.minCount, total)
			}

			if tt.wantIDs != nil {
				resultIDs := make(map[string]bool)
				for _, r := range results {
					resultIDs[r.VulnerabilityID] = true
				}
				for _, wantID := range tt.wantIDs {
					if !resultIDs[wantID] {
						t.Errorf("expected %s in results, not found. Got: %v", wantID, resultIDs)
					}
				}
			}
		})
	}
}

func TestEngine_Search_Japanese(t *testing.T) {
	db := setupDB(t)
	engine := pgtrgm.New(db)
	ctx := context.Background()

	if err := engine.Init(ctx, nil); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	seedTestData(t, db)

	tests := []struct {
		name    string
		query   string
		wantIDs []string
	}{
		{
			name:    "Japanese: remote code execution",
			query:   "リモートコード実行",
			wantIDs: []string{"CVE-2021-44228", "CVE-2024-3094"},
		},
		{
			name:    "Japanese: backdoor",
			query:   "バックドア",
			wantIDs: []string{"CVE-2024-3094"},
		},
		{
			name:    "Japanese: arbitrary code",
			query:   "任意のコード",
			wantIDs: []string{"CVE-2023-38831"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, _, err := engine.Search(ctx, search.Query{
				Text:  tt.query,
				Limit: 20,
			})
			if err != nil {
				t.Fatalf("Search failed: %v", err)
			}

			resultIDs := make(map[string]bool)
			for _, r := range results {
				resultIDs[r.VulnerabilityID] = true
			}
			for _, wantID := range tt.wantIDs {
				if !resultIDs[wantID] {
					t.Errorf("expected %s in results for query %q, not found. Got: %v", wantID, tt.query, resultIDs)
				}
			}
		})
	}
}

func TestEngine_Search_Pagination(t *testing.T) {
	db := setupDB(t)
	engine := pgtrgm.New(db)
	ctx := context.Background()

	if err := engine.Init(ctx, nil); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	seedTestData(t, db)

	// Search with limit=2
	results1, total, err := engine.Search(ctx, search.Query{
		Text:  "code",
		Limit: 2,
	})
	if err != nil {
		t.Fatalf("Search page 1 failed: %v", err)
	}
	if len(results1) != 2 {
		t.Fatalf("expected 2 results on page 1, got %d", len(results1))
	}
	if total <= 2 {
		t.Fatalf("expected total > 2 for 'code', got %d", total)
	}

	// Search with offset=2
	results2, _, err := engine.Search(ctx, search.Query{
		Text:   "code",
		Limit:  2,
		Offset: 2,
	})
	if err != nil {
		t.Fatalf("Search page 2 failed: %v", err)
	}

	// Results should be different
	if len(results2) > 0 && results1[0].VulnerabilityID == results2[0].VulnerabilityID {
		t.Error("page 1 and page 2 returned the same first result; pagination not working")
	}
}

func TestEngine_Search_EmptyQuery(t *testing.T) {
	db := setupDB(t)
	engine := pgtrgm.New(db)
	ctx := context.Background()

	if err := engine.Init(ctx, nil); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	results, total, err := engine.Search(ctx, search.Query{
		Text:  "",
		Limit: 20,
	})
	if err != nil {
		t.Fatalf("Search with empty query failed: %v", err)
	}
	if total != 0 || len(results) != 0 {
		t.Errorf("expected 0 results for empty query, got %d results (total=%d)", len(results), total)
	}
}

func TestEngine_Search_SpecialCharacters(t *testing.T) {
	db := setupDB(t)
	engine := pgtrgm.New(db)
	ctx := context.Background()

	if err := engine.Init(ctx, nil); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	seedTestData(t, db)

	// These should not cause SQL errors
	specialQueries := []string{
		"100%",
		"it's",
		"test_value",
		`"quoted"`,
		"back\\slash",
		"semi;colon",
	}

	for _, q := range specialQueries {
		t.Run(q, func(t *testing.T) {
			_, _, err := engine.Search(ctx, search.Query{
				Text:  q,
				Limit: 5,
			})
			if err != nil {
				t.Errorf("Search with special chars %q failed: %v", q, err)
			}
		})
	}
}
