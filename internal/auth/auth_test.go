package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// --- Mock stores ---

type mockUserStore struct {
	getUserByEmailFn    func(ctx context.Context, email string) (*UserWithPassword, error)
	getUserByIDFn       func(ctx context.Context, id int64) (*User, error)
	createUserFn        func(ctx context.Context, email, name, role, passwordHash string) (*User, error)
	listUsersFn         func(ctx context.Context) ([]*User, error)
	updateUserOIDCFn    func(ctx context.Context, userID int64, subject string) error
	getUserByOIDCSubjFn func(ctx context.Context, subject string) (*User, error)
}

func (m *mockUserStore) CreateUser(ctx context.Context, email, name, role, passwordHash string) (*User, error) {
	if m.createUserFn != nil {
		return m.createUserFn(ctx, email, name, role, passwordHash)
	}
	return nil, nil
}

func (m *mockUserStore) GetUserByEmail(ctx context.Context, email string) (*UserWithPassword, error) {
	if m.getUserByEmailFn != nil {
		return m.getUserByEmailFn(ctx, email)
	}
	return nil, nil
}

func (m *mockUserStore) GetUserByID(ctx context.Context, id int64) (*User, error) {
	if m.getUserByIDFn != nil {
		return m.getUserByIDFn(ctx, id)
	}
	return nil, nil
}

func (m *mockUserStore) ListUsers(ctx context.Context) ([]*User, error) {
	if m.listUsersFn != nil {
		return m.listUsersFn(ctx)
	}
	return nil, nil
}

func (m *mockUserStore) UpdateUserOIDCSubject(ctx context.Context, userID int64, subject string) error {
	if m.updateUserOIDCFn != nil {
		return m.updateUserOIDCFn(ctx, userID, subject)
	}
	return nil
}

func (m *mockUserStore) GetUserByOIDCSubject(ctx context.Context, subject string) (*User, error) {
	if m.getUserByOIDCSubjFn != nil {
		return m.getUserByOIDCSubjFn(ctx, subject)
	}
	return nil, nil
}

type mockAPIKeyStore struct {
	getAPIKeyByPrefixFn func(ctx context.Context, prefix string) ([]*APIKeyWithHash, error)
	createAPIKeyFn      func(ctx context.Context, userID int64, name string, keyHash string, keyPrefix string, expiresAt *time.Time) (*APIKey, error)
	listAPIKeysFn       func(ctx context.Context, userID int64) ([]*APIKey, error)
	deleteAPIKeyFn      func(ctx context.Context, id int64, userID int64) (int64, error)
}

func (m *mockAPIKeyStore) CreateAPIKey(ctx context.Context, userID int64, name string, keyHash string, keyPrefix string, expiresAt *time.Time) (*APIKey, error) {
	if m.createAPIKeyFn != nil {
		return m.createAPIKeyFn(ctx, userID, name, keyHash, keyPrefix, expiresAt)
	}
	return nil, nil
}

func (m *mockAPIKeyStore) ListAPIKeys(ctx context.Context, userID int64) ([]*APIKey, error) {
	if m.listAPIKeysFn != nil {
		return m.listAPIKeysFn(ctx, userID)
	}
	return nil, nil
}

func (m *mockAPIKeyStore) DeleteAPIKey(ctx context.Context, id int64, userID int64) (int64, error) {
	if m.deleteAPIKeyFn != nil {
		return m.deleteAPIKeyFn(ctx, id, userID)
	}
	return 1, nil
}

func (m *mockAPIKeyStore) GetAPIKeyByPrefix(ctx context.Context, prefix string) ([]*APIKeyWithHash, error) {
	if m.getAPIKeyByPrefixFn != nil {
		return m.getAPIKeyByPrefixFn(ctx, prefix)
	}
	return nil, nil
}

type mockSessionStore struct {
	createSessionFn         func(ctx context.Context, id string, userID int64, expiresAt time.Time) error
	getSessionFn            func(ctx context.Context, id string) (*Session, error)
	deleteSessionFn         func(ctx context.Context, id string) error
	deleteExpiredSessionsFn func(ctx context.Context) error
}

func (m *mockSessionStore) CreateSession(ctx context.Context, id string, userID int64, expiresAt time.Time) error {
	if m.createSessionFn != nil {
		return m.createSessionFn(ctx, id, userID, expiresAt)
	}
	return nil
}

func (m *mockSessionStore) GetSession(ctx context.Context, id string) (*Session, error) {
	if m.getSessionFn != nil {
		return m.getSessionFn(ctx, id)
	}
	return nil, nil
}

func (m *mockSessionStore) DeleteSession(ctx context.Context, id string) error {
	if m.deleteSessionFn != nil {
		return m.deleteSessionFn(ctx, id)
	}
	return nil
}

func (m *mockSessionStore) DeleteExpiredSessions(ctx context.Context) error {
	if m.deleteExpiredSessionsFn != nil {
		return m.deleteExpiredSessionsFn(ctx)
	}
	return nil
}

// --- LocalAuthProvider tests ---

func TestLocalAuthProvider_Authenticate(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)

	tests := []struct {
		name      string
		email     string
		password  string
		userStore *mockUserStore
		wantErr   error
		wantUser  *User
	}{
		{
			name:     "successful authentication",
			email:    "alice@example.com",
			password: "correct-password",
			userStore: &mockUserStore{
				getUserByEmailFn: func(_ context.Context, email string) (*UserWithPassword, error) {
					return &UserWithPassword{
						User:         User{ID: 1, Email: email, Name: "Alice", Role: RoleAdmin},
						PasswordHash: string(hash),
					}, nil
				},
			},
			wantErr:  nil,
			wantUser: &User{ID: 1, Email: "alice@example.com", Name: "Alice", Role: RoleAdmin},
		},
		{
			name:     "wrong password",
			email:    "alice@example.com",
			password: "wrong-password",
			userStore: &mockUserStore{
				getUserByEmailFn: func(_ context.Context, email string) (*UserWithPassword, error) {
					return &UserWithPassword{
						User:         User{ID: 1, Email: email, Name: "Alice", Role: RoleAdmin},
						PasswordHash: string(hash),
					}, nil
				},
			},
			wantErr:  ErrInvalidCredentials,
			wantUser: nil,
		},
		{
			name:     "user not found",
			email:    "unknown@example.com",
			password: "any-password",
			userStore: &mockUserStore{
				getUserByEmailFn: func(_ context.Context, _ string) (*UserWithPassword, error) {
					return nil, nil
				},
			},
			wantErr:  ErrInvalidCredentials,
			wantUser: nil,
		},
		{
			name:     "user with no password hash",
			email:    "oidc@example.com",
			password: "any-password",
			userStore: &mockUserStore{
				getUserByEmailFn: func(_ context.Context, email string) (*UserWithPassword, error) {
					return &UserWithPassword{
						User:         User{ID: 2, Email: email, Name: "OIDC User", Role: RoleViewer},
						PasswordHash: "",
					}, nil
				},
			},
			wantErr:  ErrInvalidCredentials,
			wantUser: nil,
		},
		{
			name:     "store error",
			email:    "alice@example.com",
			password: "any-password",
			userStore: &mockUserStore{
				getUserByEmailFn: func(_ context.Context, _ string) (*UserWithPassword, error) {
					return nil, errors.New("db connection failed")
				},
			},
			wantErr:  nil, // non-nil error, but not ErrInvalidCredentials
			wantUser: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewLocalAuthProvider(tt.userStore, &mockAPIKeyStore{}, &mockSessionStore{}, 3600)
			user, err := provider.Authenticate(context.Background(), tt.email, tt.password)

			if tt.name == "store error" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got error %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if user.ID != tt.wantUser.ID || user.Email != tt.wantUser.Email {
				t.Errorf("got user %+v, want %+v", user, tt.wantUser)
			}
		})
	}
}

func TestLocalAuthProvider_ValidateSession(t *testing.T) {
	tests := []struct {
		name         string
		sessionID    string
		sessionStore *mockSessionStore
		userStore    *mockUserStore
		wantErr      error
		wantUser     *User
	}{
		{
			name:      "valid session",
			sessionID: "valid-session-id",
			sessionStore: &mockSessionStore{
				getSessionFn: func(_ context.Context, id string) (*Session, error) {
					return &Session{
						ID:        id,
						UserID:    1,
						ExpiresAt: time.Now().Add(1 * time.Hour),
					}, nil
				},
			},
			userStore: &mockUserStore{
				getUserByIDFn: func(_ context.Context, id int64) (*User, error) {
					return &User{ID: id, Email: "alice@example.com", Name: "Alice", Role: RoleAdmin}, nil
				},
			},
			wantErr:  nil,
			wantUser: &User{ID: 1, Email: "alice@example.com", Name: "Alice", Role: RoleAdmin},
		},
		{
			name:      "expired session",
			sessionID: "expired-session-id",
			sessionStore: &mockSessionStore{
				getSessionFn: func(_ context.Context, id string) (*Session, error) {
					return &Session{
						ID:        id,
						UserID:    1,
						ExpiresAt: time.Now().Add(-1 * time.Hour),
					}, nil
				},
				deleteSessionFn: func(_ context.Context, _ string) error {
					return nil
				},
			},
			userStore: &mockUserStore{},
			wantErr:   ErrSessionExpired,
			wantUser:  nil,
		},
		{
			name:      "session not found",
			sessionID: "nonexistent-session-id",
			sessionStore: &mockSessionStore{
				getSessionFn: func(_ context.Context, _ string) (*Session, error) {
					return nil, nil
				},
			},
			userStore: &mockUserStore{},
			wantErr:   ErrSessionExpired,
			wantUser:  nil,
		},
		{
			name:      "session valid but user deleted",
			sessionID: "orphan-session-id",
			sessionStore: &mockSessionStore{
				getSessionFn: func(_ context.Context, id string) (*Session, error) {
					return &Session{
						ID:        id,
						UserID:    999,
						ExpiresAt: time.Now().Add(1 * time.Hour),
					}, nil
				},
			},
			userStore: &mockUserStore{
				getUserByIDFn: func(_ context.Context, _ int64) (*User, error) {
					return nil, nil
				},
			},
			wantErr:  ErrSessionExpired,
			wantUser: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewLocalAuthProvider(tt.userStore, &mockAPIKeyStore{}, tt.sessionStore, 3600)
			user, err := provider.ValidateSession(context.Background(), tt.sessionID)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got error %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if user.ID != tt.wantUser.ID || user.Email != tt.wantUser.Email {
				t.Errorf("got user %+v, want %+v", user, tt.wantUser)
			}
		})
	}
}

func TestLocalAuthProvider_ValidateAPIKey(t *testing.T) {
	// Generate a test key: prefix (8 chars) + rest
	rawKey := "abcdefgh1234567890abcdef"
	keyHash := HashAPIKey(rawKey)
	prefix := APIKeyPrefix(rawKey)

	expiredTime := time.Now().Add(-1 * time.Hour)
	validTime := time.Now().Add(24 * time.Hour)

	tests := []struct {
		name        string
		rawKey      string
		apiKeyStore *mockAPIKeyStore
		userStore   *mockUserStore
		wantErr     error
		wantUser    *User
	}{
		{
			name:   "valid key",
			rawKey: rawKey,
			apiKeyStore: &mockAPIKeyStore{
				getAPIKeyByPrefixFn: func(_ context.Context, p string) ([]*APIKeyWithHash, error) {
					if p != prefix {
						return nil, nil
					}
					return []*APIKeyWithHash{
						{
							APIKey:  APIKey{ID: 1, UserID: 1, KeyPrefix: prefix, ExpiresAt: &validTime},
							KeyHash: keyHash,
						},
					}, nil
				},
			},
			userStore: &mockUserStore{
				getUserByIDFn: func(_ context.Context, id int64) (*User, error) {
					return &User{ID: id, Email: "alice@example.com", Name: "Alice", Role: RoleAdmin}, nil
				},
			},
			wantErr:  nil,
			wantUser: &User{ID: 1, Email: "alice@example.com", Name: "Alice", Role: RoleAdmin},
		},
		{
			name:   "valid key without expiration",
			rawKey: rawKey,
			apiKeyStore: &mockAPIKeyStore{
				getAPIKeyByPrefixFn: func(_ context.Context, p string) ([]*APIKeyWithHash, error) {
					return []*APIKeyWithHash{
						{
							APIKey:  APIKey{ID: 1, UserID: 1, KeyPrefix: prefix, ExpiresAt: nil},
							KeyHash: keyHash,
						},
					}, nil
				},
			},
			userStore: &mockUserStore{
				getUserByIDFn: func(_ context.Context, id int64) (*User, error) {
					return &User{ID: id, Email: "alice@example.com", Name: "Alice", Role: RoleAdmin}, nil
				},
			},
			wantErr:  nil,
			wantUser: &User{ID: 1, Email: "alice@example.com", Name: "Alice", Role: RoleAdmin},
		},
		{
			name:   "expired key",
			rawKey: rawKey,
			apiKeyStore: &mockAPIKeyStore{
				getAPIKeyByPrefixFn: func(_ context.Context, _ string) ([]*APIKeyWithHash, error) {
					return []*APIKeyWithHash{
						{
							APIKey:  APIKey{ID: 1, UserID: 1, KeyPrefix: prefix, ExpiresAt: &expiredTime},
							KeyHash: keyHash,
						},
					}, nil
				},
			},
			userStore: &mockUserStore{},
			wantErr:   ErrAPIKeyExpired,
			wantUser:  nil,
		},
		{
			name:   "wrong key (hash mismatch)",
			rawKey: "abcdefghWRONGKEY1234567",
			apiKeyStore: &mockAPIKeyStore{
				getAPIKeyByPrefixFn: func(_ context.Context, _ string) ([]*APIKeyWithHash, error) {
					return []*APIKeyWithHash{
						{
							APIKey:  APIKey{ID: 1, UserID: 1, KeyPrefix: prefix, ExpiresAt: &validTime},
							KeyHash: keyHash,
						},
					}, nil
				},
			},
			userStore: &mockUserStore{},
			wantErr:   ErrInvalidAPIKey,
			wantUser:  nil,
		},
		{
			name:        "key too short",
			rawKey:      "short",
			apiKeyStore: &mockAPIKeyStore{},
			userStore:   &mockUserStore{},
			wantErr:     ErrInvalidAPIKey,
			wantUser:    nil,
		},
		{
			name:   "no matching prefix",
			rawKey: "xxxxxxxx1234567890abcdef",
			apiKeyStore: &mockAPIKeyStore{
				getAPIKeyByPrefixFn: func(_ context.Context, _ string) ([]*APIKeyWithHash, error) {
					return nil, nil
				},
			},
			userStore: &mockUserStore{},
			wantErr:   ErrInvalidAPIKey,
			wantUser:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewLocalAuthProvider(tt.userStore, tt.apiKeyStore, &mockSessionStore{}, 3600)
			user, err := provider.ValidateAPIKey(context.Background(), tt.rawKey)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got error %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if user.ID != tt.wantUser.ID || user.Email != tt.wantUser.Email {
				t.Errorf("got user %+v, want %+v", user, tt.wantUser)
			}
		})
	}
}

func TestLocalAuthProvider_CreateSession(t *testing.T) {
	var createdID string
	var createdUserID int64

	sessionStore := &mockSessionStore{
		createSessionFn: func(_ context.Context, id string, userID int64, _ time.Time) error {
			createdID = id
			createdUserID = userID
			return nil
		},
	}

	provider := NewLocalAuthProvider(&mockUserStore{}, &mockAPIKeyStore{}, sessionStore, 3600)
	sessionID, err := provider.CreateSession(context.Background(), 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sessionID == "" {
		t.Error("expected non-empty session ID")
	}
	if createdID != sessionID {
		t.Errorf("store received different ID: got %q, want %q", createdID, sessionID)
	}
	if createdUserID != 42 {
		t.Errorf("store received wrong userID: got %d, want 42", createdUserID)
	}
}

func TestLocalAuthProvider_DeleteSession(t *testing.T) {
	var deletedID string
	sessionStore := &mockSessionStore{
		deleteSessionFn: func(_ context.Context, id string) error {
			deletedID = id
			return nil
		},
	}

	provider := NewLocalAuthProvider(&mockUserStore{}, &mockAPIKeyStore{}, sessionStore, 3600)
	err := provider.DeleteSession(context.Background(), "session-to-delete")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deletedID != "session-to-delete" {
		t.Errorf("got deleted ID %q, want %q", deletedID, "session-to-delete")
	}
}

func TestLocalAuthProvider_Mode(t *testing.T) {
	provider := NewLocalAuthProvider(&mockUserStore{}, &mockAPIKeyStore{}, &mockSessionStore{}, 3600)
	if got := provider.Mode(); got != "local" {
		t.Errorf("got mode %q, want %q", got, "local")
	}
}

// --- NoAuthProvider tests ---

func TestNoAuthProvider_Authenticate(t *testing.T) {
	provider := NewNoAuthProvider()
	user, err := provider.Authenticate(context.Background(), "any@example.com", "any-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Role != RoleAdmin {
		t.Errorf("got role %q, want %q", user.Role, RoleAdmin)
	}
	if user.Email != "admin@localhost" {
		t.Errorf("got email %q, want %q", user.Email, "admin@localhost")
	}
}

func TestNoAuthProvider_ValidateSession(t *testing.T) {
	provider := NewNoAuthProvider()
	user, err := provider.ValidateSession(context.Background(), "any-session-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Role != RoleAdmin {
		t.Errorf("got role %q, want %q", user.Role, RoleAdmin)
	}
}

func TestNoAuthProvider_ValidateAPIKey(t *testing.T) {
	provider := NewNoAuthProvider()
	user, err := provider.ValidateAPIKey(context.Background(), "any-api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Role != RoleAdmin {
		t.Errorf("got role %q, want %q", user.Role, RoleAdmin)
	}
}

func TestNoAuthProvider_CreateSession(t *testing.T) {
	provider := NewNoAuthProvider()
	sessionID, err := provider.CreateSession(context.Background(), 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessionID != "no-auth-session" {
		t.Errorf("got session ID %q, want %q", sessionID, "no-auth-session")
	}
}

func TestNoAuthProvider_DeleteSession(t *testing.T) {
	provider := NewNoAuthProvider()
	err := provider.DeleteSession(context.Background(), "any-session-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNoAuthProvider_Mode(t *testing.T) {
	provider := NewNoAuthProvider()
	if got := provider.Mode(); got != "none" {
		t.Errorf("got mode %q, want %q", got, "none")
	}
}

// --- Helper function tests ---

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("my-secure-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}

	// Verify the hash is valid bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("my-secure-password"))
	if err != nil {
		t.Errorf("hash did not verify: %v", err)
	}

	// Verify wrong password fails
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong-password"))
	if err == nil {
		t.Error("expected error for wrong password")
	}
}

func TestHashAPIKey(t *testing.T) {
	hash1 := HashAPIKey("test-key-1")
	hash2 := HashAPIKey("test-key-2")
	hash1Again := HashAPIKey("test-key-1")

	if hash1 == hash2 {
		t.Error("different keys should produce different hashes")
	}
	if hash1 != hash1Again {
		t.Error("same key should produce same hash")
	}
	if len(hash1) != 64 { // SHA-256 hex output
		t.Errorf("expected 64-char hex hash, got %d chars", len(hash1))
	}
}

func TestAPIKeyPrefix(t *testing.T) {
	tests := []struct {
		name   string
		rawKey string
		want   string
	}{
		{"normal key", "abcdefgh12345678", "abcdefgh"},
		{"exactly 8 chars", "abcdefgh", "abcdefgh"},
		{"short key", "abc", "abc"},
		{"empty key", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := APIKeyPrefix(tt.rawKey)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
