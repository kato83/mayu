package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockAuthProvider implements AuthProvider for testing.
type mockAuthProvider struct {
	authenticateFunc    func(ctx context.Context, email, password string) (*User, error)
	validateSessionFunc func(ctx context.Context, sessionID string) (*User, error)
	validateAPIKeyFunc  func(ctx context.Context, rawKey string) (*User, error)
	createSessionFunc   func(ctx context.Context, userID int64) (string, error)
	deleteSessionFunc   func(ctx context.Context, sessionID string) error
	mode                string
}

func (m *mockAuthProvider) Authenticate(ctx context.Context, email, password string) (*User, error) {
	if m.authenticateFunc != nil {
		return m.authenticateFunc(ctx, email, password)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAuthProvider) ValidateSession(ctx context.Context, sessionID string) (*User, error) {
	if m.validateSessionFunc != nil {
		return m.validateSessionFunc(ctx, sessionID)
	}
	return nil, errors.New("invalid session")
}

func (m *mockAuthProvider) ValidateAPIKey(ctx context.Context, rawKey string) (*User, error) {
	if m.validateAPIKeyFunc != nil {
		return m.validateAPIKeyFunc(ctx, rawKey)
	}
	return nil, errors.New("invalid api key")
}

func (m *mockAuthProvider) CreateSession(ctx context.Context, userID int64) (string, error) {
	if m.createSessionFunc != nil {
		return m.createSessionFunc(ctx, userID)
	}
	return "test-session-id", nil
}

func (m *mockAuthProvider) DeleteSession(ctx context.Context, sessionID string) error {
	if m.deleteSessionFunc != nil {
		return m.deleteSessionFunc(ctx, sessionID)
	}
	return nil
}

func (m *mockAuthProvider) Mode() string {
	if m.mode != "" {
		return m.mode
	}
	return "local"
}

var testUser = &User{
	ID:    1,
	Email: "user@example.com",
	Name:  "Test User",
	Role:  RoleViewer,
}

var testAdmin = &User{
	ID:    2,
	Email: "admin@example.com",
	Name:  "Admin User",
	Role:  RoleAdmin,
}

// okHandler is a simple handler that confirms the request passed through middleware.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestSessionMiddleware_ValidSession(t *testing.T) {
	provider := &mockAuthProvider{
		validateSessionFunc: func(_ context.Context, sessionID string) (*User, error) {
			if sessionID == "valid-session" {
				return testUser, nil
			}
			return nil, errors.New("invalid")
		},
	}

	handler := SessionMiddleware(provider)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "mayu_session", Value: "valid-session"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestSessionMiddleware_MissingCookie(t *testing.T) {
	provider := &mockAuthProvider{}

	handler := SessionMiddleware(provider)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestSessionMiddleware_InvalidSession(t *testing.T) {
	provider := &mockAuthProvider{
		validateSessionFunc: func(_ context.Context, _ string) (*User, error) {
			return nil, errors.New("session expired")
		},
	}

	handler := SessionMiddleware(provider)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "mayu_session", Value: "expired-session"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAPIKeyMiddleware_ValidKey(t *testing.T) {
	provider := &mockAuthProvider{
		validateAPIKeyFunc: func(_ context.Context, rawKey string) (*User, error) {
			if rawKey == "valid-api-key-token" {
				return testUser, nil
			}
			return nil, errors.New("invalid")
		},
	}

	handler := APIKeyMiddleware(provider)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-api-key-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAPIKeyMiddleware_MissingHeader(t *testing.T) {
	provider := &mockAuthProvider{}

	handler := APIKeyMiddleware(provider)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAPIKeyMiddleware_InvalidKey(t *testing.T) {
	provider := &mockAuthProvider{
		validateAPIKeyFunc: func(_ context.Context, _ string) (*User, error) {
			return nil, ErrInvalidAPIKey
		},
	}

	handler := APIKeyMiddleware(provider)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bad-key")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAPIKeyMiddleware_ExpiredKey(t *testing.T) {
	provider := &mockAuthProvider{
		validateAPIKeyFunc: func(_ context.Context, _ string) (*User, error) {
			return nil, ErrAPIKeyExpired
		},
	}

	handler := APIKeyMiddleware(provider)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer expired-key")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCombinedAuthMiddleware_APIKeyFirst(t *testing.T) {
	provider := &mockAuthProvider{
		validateAPIKeyFunc: func(_ context.Context, rawKey string) (*User, error) {
			if rawKey == "api-key-123" {
				return testAdmin, nil
			}
			return nil, errors.New("invalid")
		},
		validateSessionFunc: func(_ context.Context, _ string) (*User, error) {
			// Should not be called when API key succeeds
			return testUser, nil
		},
	}

	handler := CombinedAuthMiddleware(provider)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			t.Fatal("expected user in context")
		}
		// API key user should be the admin, not the session user
		if user.Role != RoleAdmin {
			t.Errorf("expected admin role from API key, got %q", user.Role)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer api-key-123")
	req.AddCookie(&http.Cookie{Name: "mayu_session", Value: "valid-session"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestCombinedAuthMiddleware_FallbackToSession(t *testing.T) {
	provider := &mockAuthProvider{
		validateAPIKeyFunc: func(_ context.Context, _ string) (*User, error) {
			return nil, errors.New("invalid api key")
		},
		validateSessionFunc: func(_ context.Context, sessionID string) (*User, error) {
			if sessionID == "good-session" {
				return testUser, nil
			}
			return nil, errors.New("invalid session")
		},
	}

	handler := CombinedAuthMiddleware(provider)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			t.Fatal("expected user in context")
		}
		if user.Email != testUser.Email {
			t.Errorf("expected session user, got %q", user.Email)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bad-key")
	req.AddCookie(&http.Cookie{Name: "mayu_session", Value: "good-session"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestCombinedAuthMiddleware_SessionOnly(t *testing.T) {
	provider := &mockAuthProvider{
		validateSessionFunc: func(_ context.Context, sessionID string) (*User, error) {
			if sessionID == "my-session" {
				return testUser, nil
			}
			return nil, errors.New("invalid")
		},
	}

	handler := CombinedAuthMiddleware(provider)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "mayu_session", Value: "my-session"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestCombinedAuthMiddleware_NeitherValid(t *testing.T) {
	provider := &mockAuthProvider{
		validateAPIKeyFunc: func(_ context.Context, _ string) (*User, error) {
			return nil, errors.New("invalid")
		},
		validateSessionFunc: func(_ context.Context, _ string) (*User, error) {
			return nil, errors.New("invalid")
		},
	}

	handler := CombinedAuthMiddleware(provider)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bad")
	req.AddCookie(&http.Cookie{Name: "mayu_session", Value: "bad"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRequireRole_Allowed(t *testing.T) {
	handler := RequireRole(RoleAdmin, RoleViewer)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := withUser(req.Context(), testUser) // viewer
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRequireRole_Forbidden(t *testing.T) {
	handler := RequireRole(RoleAdmin)(okHandler()) // only admin allowed

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := withUser(req.Context(), testUser) // viewer
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireRole_NoUser(t *testing.T) {
	handler := RequireRole(RoleAdmin)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestOptionalAuth_WithValidAPIKey(t *testing.T) {
	provider := &mockAuthProvider{
		validateAPIKeyFunc: func(_ context.Context, rawKey string) (*User, error) {
			if rawKey == "good-key" {
				return testUser, nil
			}
			return nil, errors.New("invalid")
		},
	}

	handler := OptionalAuth(provider)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			t.Fatal("expected user in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer good-key")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestOptionalAuth_WithValidSession(t *testing.T) {
	provider := &mockAuthProvider{
		validateSessionFunc: func(_ context.Context, sessionID string) (*User, error) {
			if sessionID == "sess-123" {
				return testUser, nil
			}
			return nil, errors.New("invalid")
		},
	}

	handler := OptionalAuth(provider)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			t.Fatal("expected user in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "mayu_session", Value: "sess-123"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestOptionalAuth_NoCredentials(t *testing.T) {
	provider := &mockAuthProvider{}

	handler := OptionalAuth(provider)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user != nil {
			t.Fatal("expected no user in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestOptionalAuth_InvalidCredentials(t *testing.T) {
	provider := &mockAuthProvider{
		validateAPIKeyFunc: func(_ context.Context, _ string) (*User, error) {
			return nil, errors.New("invalid")
		},
		validateSessionFunc: func(_ context.Context, _ string) (*User, error) {
			return nil, errors.New("invalid")
		},
	}

	handler := OptionalAuth(provider)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user != nil {
			t.Fatal("expected no user in context with invalid credentials")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bad")
	req.AddCookie(&http.Cookie{Name: "mayu_session", Value: "bad"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestNoAuthMiddleware(t *testing.T) {
	handler := NoAuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			t.Fatal("expected synthetic admin in context")
		}
		if user.Role != RoleAdmin {
			t.Errorf("expected admin role, got %q", user.Role)
		}
		if user.Email != "admin@localhost" {
			t.Errorf("expected admin@localhost, got %q", user.Email)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestUserFromContext_Nil(t *testing.T) {
	ctx := context.Background()
	user := UserFromContext(ctx)
	if user != nil {
		t.Fatal("expected nil user from empty context")
	}
}

func TestUserFromContext_WithUser(t *testing.T) {
	ctx := withUser(context.Background(), testUser)
	user := UserFromContext(ctx)
	if user == nil {
		t.Fatal("expected user from context")
	}
	if user.ID != testUser.ID {
		t.Errorf("expected user ID %d, got %d", testUser.ID, user.ID)
	}
}
