//go:build integration

package auth

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping database: %v", err)
	}

	// Clean up auth tables before test
	_, _ = db.ExecContext(ctx, "DELETE FROM sessions")
	_, _ = db.ExecContext(ctx, "DELETE FROM api_keys")
	_, _ = db.ExecContext(ctx, "DELETE FROM users")

	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM sessions")
		_, _ = db.ExecContext(ctx, "DELETE FROM api_keys")
		_, _ = db.ExecContext(ctx, "DELETE FROM users")
		_ = db.Close()
	})

	return db
}

func TestPostgresAuthStore_UserCRUD(t *testing.T) {
	db := setupTestDB(t)
	store := NewPostgresAuthStore(db)
	ctx := context.Background()

	// Create user
	user, err := store.CreateUser(ctx, "test@example.com", "Test User", RoleAdmin, "hashed-password")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.ID == 0 {
		t.Error("expected non-zero user ID")
	}
	if user.Email != "test@example.com" {
		t.Errorf("got email %q, want %q", user.Email, "test@example.com")
	}

	// Get by email
	uwp, err := store.GetUserByEmail(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if uwp == nil {
		t.Fatal("expected user, got nil")
	}
	if uwp.PasswordHash != "hashed-password" {
		t.Errorf("got password_hash %q, want %q", uwp.PasswordHash, "hashed-password")
	}

	// Get by ID
	fetched, err := store.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if fetched == nil {
		t.Fatal("expected user, got nil")
	}
	if fetched.Email != "test@example.com" {
		t.Errorf("got email %q, want %q", fetched.Email, "test@example.com")
	}

	// List users
	users, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) < 1 {
		t.Error("expected at least 1 user")
	}

	// Update OIDC subject
	err = store.UpdateUserOIDCSubject(ctx, user.ID, "oidc-subject-123")
	if err != nil {
		t.Fatalf("UpdateUserOIDCSubject: %v", err)
	}

	// Get by OIDC subject
	oidcUser, err := store.GetUserByOIDCSubject(ctx, "oidc-subject-123")
	if err != nil {
		t.Fatalf("GetUserByOIDCSubject: %v", err)
	}
	if oidcUser == nil {
		t.Fatal("expected user, got nil")
	}
	if oidcUser.ID != user.ID {
		t.Errorf("got user ID %d, want %d", oidcUser.ID, user.ID)
	}

	// Get non-existent user by email
	notFound, err := store.GetUserByEmail(ctx, "nonexistent@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail (not found): %v", err)
	}
	if notFound != nil {
		t.Error("expected nil for non-existent user")
	}
}

func TestPostgresAuthStore_APIKeyCRUD(t *testing.T) {
	db := setupTestDB(t)
	store := NewPostgresAuthStore(db)
	ctx := context.Background()

	// Create a user first
	user, err := store.CreateUser(ctx, "apikey-user@example.com", "API User", RoleViewer, "")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Create API key
	expires := time.Now().Add(24 * time.Hour)
	key, err := store.CreateAPIKey(ctx, user.ID, "My Test Key", "sha256hash123", "abcdefgh", &expires)
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if key.ID == 0 {
		t.Error("expected non-zero key ID")
	}
	if key.KeyPrefix != "abcdefgh" {
		t.Errorf("got prefix %q, want %q", key.KeyPrefix, "abcdefgh")
	}

	// List API keys
	keys, err := store.ListAPIKeys(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	// Get by prefix
	candidates, err := store.GetAPIKeyByPrefix(ctx, "abcdefgh")
	if err != nil {
		t.Fatalf("GetAPIKeyByPrefix: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	if candidates[0].KeyHash != "sha256hash123" {
		t.Errorf("got hash %q, want %q", candidates[0].KeyHash, "sha256hash123")
	}

	// Delete API key
	err = store.DeleteAPIKey(ctx, key.ID, user.ID)
	if err != nil {
		t.Fatalf("DeleteAPIKey: %v", err)
	}

	// Verify deletion
	keys, err = store.ListAPIKeys(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListAPIKeys after delete: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys after delete, got %d", len(keys))
	}
}

func TestPostgresAuthStore_SessionCRUD(t *testing.T) {
	db := setupTestDB(t)
	store := NewPostgresAuthStore(db)
	ctx := context.Background()

	// Create a user first
	user, err := store.CreateUser(ctx, "session-user@example.com", "Session User", RoleAdmin, "")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	sessionID := fmt.Sprintf("test-session-%d", time.Now().UnixNano())
	expiresAt := time.Now().Add(1 * time.Hour).Truncate(time.Microsecond)

	// Create session
	err = store.CreateSession(ctx, sessionID, user.ID, expiresAt)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Get session
	sess, err := store.GetSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess == nil {
		t.Fatal("expected session, got nil")
	}
	if sess.UserID != user.ID {
		t.Errorf("got userID %d, want %d", sess.UserID, user.ID)
	}

	// Delete session
	err = store.DeleteSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	// Verify deletion
	sess, err = store.GetSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("GetSession after delete: %v", err)
	}
	if sess != nil {
		t.Error("expected nil after delete")
	}

	// Test DeleteExpiredSessions
	expiredID := fmt.Sprintf("expired-session-%d", time.Now().UnixNano())
	err = store.CreateSession(ctx, expiredID, user.ID, time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("CreateSession (expired): %v", err)
	}

	err = store.DeleteExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}

	sess, err = store.GetSession(ctx, expiredID)
	if err != nil {
		t.Fatalf("GetSession (expired): %v", err)
	}
	if sess != nil {
		t.Error("expected expired session to be deleted")
	}
}
