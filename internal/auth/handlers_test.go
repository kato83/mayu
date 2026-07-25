package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleLogin_Success(t *testing.T) {
	provider := &mockAuthProvider{
		authenticateFunc: func(_ context.Context, email, password string) (*User, error) {
			if email == "user@example.com" && password == "secret123" {
				return testUser, nil
			}
			return nil, ErrInvalidCredentials
		},
		createSessionFunc: func(_ context.Context, userID int64) (string, error) {
			if userID != testUser.ID {
				t.Errorf("expected userID %d, got %d", testUser.ID, userID)
			}
			return "session-token-abc", nil
		},
	}

	handler := HandleLogin(provider)
	body := `{"email":"user@example.com","password":"secret123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Check cookie
	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == CookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie to be set")
	}
	if sessionCookie.Value != "session-token-abc" {
		t.Errorf("expected cookie value session-token-abc, got %q", sessionCookie.Value)
	}
	if !sessionCookie.HttpOnly {
		t.Error("expected HttpOnly cookie")
	}

	// Check response body
	var resp loginResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.User.Email != testUser.Email {
		t.Errorf("expected email %q, got %q", testUser.Email, resp.User.Email)
	}
	if resp.User.Role != testUser.Role {
		t.Errorf("expected role %q, got %q", testUser.Role, resp.User.Role)
	}
}

func TestHandleLogin_WrongCredentials(t *testing.T) {
	provider := &mockAuthProvider{
		authenticateFunc: func(_ context.Context, _, _ string) (*User, error) {
			return nil, ErrInvalidCredentials
		},
	}

	handler := HandleLogin(provider)
	body := `{"email":"user@example.com","password":"wrong"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] != "invalid credentials" {
		t.Errorf("expected 'invalid credentials' error, got %q", resp["error"])
	}
}

func TestHandleLogin_MissingFields(t *testing.T) {
	provider := &mockAuthProvider{}

	tests := []struct {
		name string
		body string
	}{
		{"missing email", `{"password":"secret"}`},
		{"missing password", `{"email":"user@example.com"}`},
		{"both empty", `{"email":"","password":""}`},
		{"empty body", `{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := HandleLogin(provider)
			req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandleLogin_InvalidJSON(t *testing.T) {
	provider := &mockAuthProvider{}

	handler := HandleLogin(provider)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleLogin_CreateSessionError(t *testing.T) {
	provider := &mockAuthProvider{
		authenticateFunc: func(_ context.Context, _, _ string) (*User, error) {
			return testUser, nil
		},
		createSessionFunc: func(_ context.Context, _ int64) (string, error) {
			return "", errors.New("db error")
		},
	}

	handler := HandleLogin(provider)
	body := `{"email":"user@example.com","password":"secret123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestHandleLogout_Success(t *testing.T) {
	var deletedSession string
	provider := &mockAuthProvider{
		deleteSessionFunc: func(_ context.Context, sessionID string) error {
			deletedSession = sessionID
			return nil
		},
	}

	handler := HandleLogout(provider)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "session-to-delete"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	if deletedSession != "session-to-delete" {
		t.Errorf("expected session 'session-to-delete' to be deleted, got %q", deletedSession)
	}

	// Check that cookie is cleared
	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == CookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected cookie to be set (cleared)")
	}
	if sessionCookie.MaxAge != -1 {
		t.Errorf("expected MaxAge -1 (delete cookie), got %d", sessionCookie.MaxAge)
	}
}

func TestHandleLogout_NoCookie(t *testing.T) {
	provider := &mockAuthProvider{}

	handler := HandleLogout(provider)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should still succeed even without a cookie
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestHandleAuthConfig(t *testing.T) {
	tests := []struct {
		mode     string
		expected string
	}{
		{"local", "local"},
		{"none", "none"},
		{"oidc", "oidc"},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			handler := HandleAuthConfig(tt.mode)
			req := httptest.NewRequest(http.MethodGet, "/auth/config", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", w.Code)
			}

			var resp authConfigResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if resp.Mode != tt.expected {
				t.Errorf("expected mode %q, got %q", tt.expected, resp.Mode)
			}
		})
	}
}

func TestHandleMe_Authenticated(t *testing.T) {
	handler := HandleMe()

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	ctx := withUser(req.Context(), testUser)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp userResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.ID != testUser.ID {
		t.Errorf("expected ID %d, got %d", testUser.ID, resp.ID)
	}
	if resp.Email != testUser.Email {
		t.Errorf("expected email %q, got %q", testUser.Email, resp.Email)
	}
	if resp.Name != testUser.Name {
		t.Errorf("expected name %q, got %q", testUser.Name, resp.Name)
	}
	if resp.Role != testUser.Role {
		t.Errorf("expected role %q, got %q", testUser.Role, resp.Role)
	}
}

func TestHandleMe_NotAuthenticated(t *testing.T) {
	handler := HandleMe()

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}
