package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/config"
)

// testRSAKey generates a test RSA key pair for JWT signing.
func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

// signJWT creates a signed JWT with the given claims using RS256.
func signJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()

	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	hash := sha256.Sum256([]byte(signingInput))

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return headerB64 + "." + claimsB64 + "." + sigB64
}

// jwksJSON builds a JWKS response from a public key.
func jwksJSON(t *testing.T, key *rsa.PublicKey, kid string) []byte {
	t.Helper()

	nB64 := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	eBytes := big.NewInt(int64(key.E)).Bytes()
	eB64 := base64.RawURLEncoding.EncodeToString(eBytes)

	jwks := map[string]interface{}{
		"keys": []map[string]string{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": kid,
				"alg": "RS256",
				"n":   nB64,
				"e":   eB64,
			},
		},
	}
	data, _ := json.Marshal(jwks)
	return data
}

// setupMockOIDCServer creates a mock OIDC provider for testing.
func setupMockOIDCServer(t *testing.T, key *rsa.PrivateKey, kid string, opts mockOIDCOpts) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// We need to know the server URL for the discovery doc
		baseURL := "http://" + r.Host
		disc := map[string]string{
			"issuer":                 baseURL,
			"authorization_endpoint": baseURL + "/authorize",
			"token_endpoint":         baseURL + "/token",
			"userinfo_endpoint":      baseURL + "/userinfo",
			"jwks_uri":               baseURL + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(disc)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON(t, &key.PublicKey, kid))
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if opts.tokenError {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}

		code := r.FormValue("code")
		if code != opts.expectedCode {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_grant","error_description":"code expired"}`))
			return
		}

		claims := map[string]interface{}{
			"sub":   opts.sub,
			"email": opts.email,
			"name":  opts.name,
			"iss":   "http://" + r.Host,
			"aud":   "test-client-id",
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
			"iat":   time.Now().Unix(),
		}

		idToken := signJWT(t, key, kid, claims)

		resp := map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"id_token":     idToken,
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{
			"sub":   opts.sub,
			"email": opts.email,
			"name":  opts.name,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

type mockOIDCOpts struct {
	sub          string
	email        string
	name         string
	expectedCode string
	tokenError   bool
}

func TestOIDCAuthProvider_Mode(t *testing.T) {
	provider := NewOIDCProvider(
		config.OIDCConfig{Issuer: "http://example.com"},
		&mockUserStore{}, &mockAPIKeyStore{}, &mockSessionStore{}, 3600,
	)
	if got := provider.Mode(); got != "oidc" {
		t.Errorf("got mode %q, want %q", got, "oidc")
	}
}

func TestOIDCAuthProvider_Authenticate(t *testing.T) {
	provider := NewOIDCProvider(
		config.OIDCConfig{Issuer: "http://example.com"},
		&mockUserStore{}, &mockAPIKeyStore{}, &mockSessionStore{}, 3600,
	)
	_, err := provider.Authenticate(context.Background(), "user@example.com", "password")
	if !errors.Is(err, ErrOIDCNotSupported) {
		t.Errorf("got error %v, want %v", err, ErrOIDCNotSupported)
	}
}

func TestOIDCAuthProvider_AuthorizationURL(t *testing.T) {
	key := testRSAKey(t)
	server := setupMockOIDCServer(t, key, "test-kid", mockOIDCOpts{})

	provider := NewOIDCProvider(
		config.OIDCConfig{
			Issuer:       server.URL,
			ClientID:     "test-client-id",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost:8080/auth/callback",
			Scopes:       []string{"openid", "email", "profile"},
		},
		&mockUserStore{}, &mockAPIKeyStore{}, &mockSessionStore{}, 3600,
	)

	authURL, err := provider.AuthorizationURL("test-state")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("invalid URL: %v", err)
	}

	if !strings.HasPrefix(authURL, server.URL+"/authorize") {
		t.Errorf("URL does not start with authorization endpoint: %s", authURL)
	}

	params := parsed.Query()
	if got := params.Get("client_id"); got != "test-client-id" {
		t.Errorf("client_id = %q, want %q", got, "test-client-id")
	}
	if got := params.Get("redirect_uri"); got != "http://localhost:8080/auth/callback" {
		t.Errorf("redirect_uri = %q, want %q", got, "http://localhost:8080/auth/callback")
	}
	if got := params.Get("response_type"); got != "code" {
		t.Errorf("response_type = %q, want %q", got, "code")
	}
	if got := params.Get("state"); got != "test-state" {
		t.Errorf("state = %q, want %q", got, "test-state")
	}
	if got := params.Get("scope"); got != "openid email profile" {
		t.Errorf("scope = %q, want %q", got, "openid email profile")
	}
}

func TestOIDCAuthProvider_HandleCallback_Success_NewUser(t *testing.T) {
	key := testRSAKey(t)
	server := setupMockOIDCServer(t, key, "test-kid", mockOIDCOpts{
		sub:          "oidc-subject-123",
		email:        "newuser@example.com",
		name:         "New User",
		expectedCode: "valid-code",
	})

	var createdEmail, createdName, createdRole string
	userStore := &mockUserStore{
		getUserByOIDCSubjFn: func(_ context.Context, _ string) (*User, error) {
			return nil, nil
		},
		getUserByEmailFn: func(_ context.Context, _ string) (*UserWithPassword, error) {
			return nil, nil
		},
		createUserFn: func(_ context.Context, email, name, role, _ string) (*User, error) {
			createdEmail = email
			createdName = name
			createdRole = role
			return &User{ID: 1, Email: email, Name: name, Role: role}, nil
		},
		updateUserOIDCFn: func(_ context.Context, _ int64, _ string) error {
			return nil
		},
	}

	provider := NewOIDCProvider(
		config.OIDCConfig{
			Issuer:       server.URL,
			ClientID:     "test-client-id",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost:8080/auth/callback",
			Scopes:       []string{"openid", "email", "profile"},
		},
		userStore, &mockAPIKeyStore{}, &mockSessionStore{}, 3600,
	)

	user, err := provider.HandleCallback(context.Background(), "valid-code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.Email != "newuser@example.com" {
		t.Errorf("user email = %q, want %q", user.Email, "newuser@example.com")
	}
	if createdEmail != "newuser@example.com" {
		t.Errorf("created email = %q, want %q", createdEmail, "newuser@example.com")
	}
	if createdName != "New User" {
		t.Errorf("created name = %q, want %q", createdName, "New User")
	}
	if createdRole != RoleViewer {
		t.Errorf("created role = %q, want %q", createdRole, RoleViewer)
	}
}

func TestOIDCAuthProvider_HandleCallback_ExistingUser_ByEmail(t *testing.T) {
	key := testRSAKey(t)
	server := setupMockOIDCServer(t, key, "test-kid", mockOIDCOpts{
		sub:          "oidc-subject-456",
		email:        "existing@example.com",
		name:         "Existing User",
		expectedCode: "valid-code",
	})

	var updatedSubject string
	userStore := &mockUserStore{
		getUserByOIDCSubjFn: func(_ context.Context, _ string) (*User, error) {
			return nil, nil
		},
		getUserByEmailFn: func(_ context.Context, email string) (*UserWithPassword, error) {
			return &UserWithPassword{
				User: User{ID: 5, Email: email, Name: "Existing User", Role: RoleAdmin},
			}, nil
		},
		updateUserOIDCFn: func(_ context.Context, _ int64, subject string) error {
			updatedSubject = subject
			return nil
		},
	}

	provider := NewOIDCProvider(
		config.OIDCConfig{
			Issuer:       server.URL,
			ClientID:     "test-client-id",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost:8080/auth/callback",
			Scopes:       []string{"openid", "email", "profile"},
		},
		userStore, &mockAPIKeyStore{}, &mockSessionStore{}, 3600,
	)

	user, err := provider.HandleCallback(context.Background(), "valid-code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.ID != 5 {
		t.Errorf("user ID = %d, want 5", user.ID)
	}
	if user.Role != RoleAdmin {
		t.Errorf("existing user role should be preserved, got %q", user.Role)
	}
	if updatedSubject != "oidc-subject-456" {
		t.Errorf("OIDC subject not updated: got %q, want %q", updatedSubject, "oidc-subject-456")
	}
}

func TestOIDCAuthProvider_HandleCallback_ExistingUser_BySubject(t *testing.T) {
	key := testRSAKey(t)
	server := setupMockOIDCServer(t, key, "test-kid", mockOIDCOpts{
		sub:          "known-subject",
		email:        "user@example.com",
		name:         "Known User",
		expectedCode: "valid-code",
	})

	userStore := &mockUserStore{
		getUserByOIDCSubjFn: func(_ context.Context, subject string) (*User, error) {
			if subject == "known-subject" {
				return &User{ID: 10, Email: "user@example.com", Name: "Known User", Role: RoleAdmin}, nil
			}
			return nil, nil
		},
	}

	provider := NewOIDCProvider(
		config.OIDCConfig{
			Issuer:       server.URL,
			ClientID:     "test-client-id",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost:8080/auth/callback",
			Scopes:       []string{"openid", "email", "profile"},
		},
		userStore, &mockAPIKeyStore{}, &mockSessionStore{}, 3600,
	)

	user, err := provider.HandleCallback(context.Background(), "valid-code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.ID != 10 {
		t.Errorf("user ID = %d, want 10", user.ID)
	}
}

func TestOIDCAuthProvider_HandleCallback_ExpiredCode(t *testing.T) {
	key := testRSAKey(t)
	server := setupMockOIDCServer(t, key, "test-kid", mockOIDCOpts{
		expectedCode: "valid-code",
	})

	provider := NewOIDCProvider(
		config.OIDCConfig{
			Issuer:       server.URL,
			ClientID:     "test-client-id",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost:8080/auth/callback",
		},
		&mockUserStore{}, &mockAPIKeyStore{}, &mockSessionStore{}, 3600,
	)

	_, err := provider.HandleCallback(context.Background(), "expired-code")
	if err == nil {
		t.Fatal("expected error for expired code, got nil")
	}
	if !errors.Is(err, ErrOIDCCodeExchange) {
		t.Errorf("got error %v, want %v", err, ErrOIDCCodeExchange)
	}
}

func TestOIDCAuthProvider_HandleCallback_MissingEmail(t *testing.T) {
	key := testRSAKey(t)
	server := setupMockOIDCServer(t, key, "test-kid", mockOIDCOpts{
		sub:          "subject-no-email",
		email:        "", // Missing email
		name:         "No Email",
		expectedCode: "valid-code",
	})

	provider := NewOIDCProvider(
		config.OIDCConfig{
			Issuer:       server.URL,
			ClientID:     "test-client-id",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost:8080/auth/callback",
		},
		&mockUserStore{}, &mockAPIKeyStore{}, &mockSessionStore{}, 3600,
	)

	_, err := provider.HandleCallback(context.Background(), "valid-code")
	if err == nil {
		t.Fatal("expected error for missing email, got nil")
	}
	if !errors.Is(err, ErrOIDCMissingEmail) {
		t.Errorf("got error %v, want %v", err, ErrOIDCMissingEmail)
	}
}

func TestOIDCAuthProvider_ValidateSession(t *testing.T) {
	provider := NewOIDCProvider(
		config.OIDCConfig{Issuer: "http://example.com"},
		&mockUserStore{
			getUserByIDFn: func(_ context.Context, id int64) (*User, error) {
				return &User{ID: id, Email: "user@example.com", Name: "User", Role: RoleViewer}, nil
			},
		},
		&mockAPIKeyStore{},
		&mockSessionStore{
			getSessionFn: func(_ context.Context, id string) (*Session, error) {
				return &Session{
					ID:        id,
					UserID:    1,
					ExpiresAt: time.Now().Add(1 * time.Hour),
				}, nil
			},
		},
		3600,
	)

	user, err := provider.ValidateSession(context.Background(), "valid-session")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.ID != 1 {
		t.Errorf("user ID = %d, want 1", user.ID)
	}
}

func TestOIDCAuthProvider_CreateSession(t *testing.T) {
	var createdUserID int64
	sessionStore := &mockSessionStore{
		createSessionFn: func(_ context.Context, _ string, userID int64, _ time.Time) error {
			createdUserID = userID
			return nil
		},
	}

	provider := NewOIDCProvider(
		config.OIDCConfig{Issuer: "http://example.com"},
		&mockUserStore{}, &mockAPIKeyStore{}, sessionStore, 3600,
	)

	sessionID, err := provider.CreateSession(context.Background(), 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessionID == "" {
		t.Error("expected non-empty session ID")
	}
	if createdUserID != 42 {
		t.Errorf("created session for user %d, want 42", createdUserID)
	}
}

// --- Handler tests ---

func TestHandleOIDCLogin(t *testing.T) {
	key := testRSAKey(t)
	server := setupMockOIDCServer(t, key, "test-kid", mockOIDCOpts{})

	provider := NewOIDCProvider(
		config.OIDCConfig{
			Issuer:       server.URL,
			ClientID:     "test-client-id",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost:8080/auth/callback",
			Scopes:       []string{"openid", "email"},
		},
		&mockUserStore{}, &mockAPIKeyStore{}, &mockSessionStore{}, 3600,
	)

	handler := HandleOIDCLogin(provider)
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}

	location := resp.Header.Get("Location")
	if !strings.HasPrefix(location, server.URL+"/authorize") {
		t.Errorf("redirect location = %q, should start with %q", location, server.URL+"/authorize")
	}

	// Verify state cookie is set
	var stateCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == OIDCStateCookieName {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("state cookie not set")
	}
	if stateCookie.Value == "" {
		t.Error("state cookie value is empty")
	}
	if !stateCookie.HttpOnly {
		t.Error("state cookie should be HttpOnly")
	}

	// Verify state in cookie matches state in URL
	parsed, _ := url.Parse(location)
	if parsed.Query().Get("state") != stateCookie.Value {
		t.Errorf("state mismatch: URL=%q, cookie=%q", parsed.Query().Get("state"), stateCookie.Value)
	}
}

func TestHandleOIDCCallback_Success(t *testing.T) {
	key := testRSAKey(t)
	server := setupMockOIDCServer(t, key, "test-kid", mockOIDCOpts{
		sub:          "callback-subject",
		email:        "callback@example.com",
		name:         "Callback User",
		expectedCode: "auth-code-123",
	})

	userStore := &mockUserStore{
		getUserByOIDCSubjFn: func(_ context.Context, _ string) (*User, error) {
			return nil, nil
		},
		getUserByEmailFn: func(_ context.Context, _ string) (*UserWithPassword, error) {
			return nil, nil
		},
		createUserFn: func(_ context.Context, email, name, role, _ string) (*User, error) {
			return &User{ID: 1, Email: email, Name: name, Role: role}, nil
		},
		updateUserOIDCFn: func(_ context.Context, _ int64, _ string) error {
			return nil
		},
	}

	sessionStore := &mockSessionStore{
		createSessionFn: func(_ context.Context, _ string, _ int64, _ time.Time) error {
			return nil
		},
	}

	provider := NewOIDCProvider(
		config.OIDCConfig{
			Issuer:       server.URL,
			ClientID:     "test-client-id",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost:8080/auth/callback",
			Scopes:       []string{"openid", "email", "profile"},
		},
		userStore, &mockAPIKeyStore{}, sessionStore, 3600,
	)

	handler := HandleOIDCCallback(provider)
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=auth-code-123&state=test-state-value", nil)
	req.AddCookie(&http.Cookie{
		Name:  OIDCStateCookieName,
		Value: "test-state-value",
	})
	rec := httptest.NewRecorder()

	handler(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("redirect location = %q, want %q", loc, "/")
	}

	// Verify session cookie is set
	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == CookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("session cookie not set")
	}
	if sessionCookie.Value == "" {
		t.Error("session cookie value is empty")
	}
}

func TestHandleOIDCCallback_InvalidState(t *testing.T) {
	provider := NewOIDCProvider(
		config.OIDCConfig{Issuer: "http://example.com"},
		&mockUserStore{}, &mockAPIKeyStore{}, &mockSessionStore{}, 3600,
	)

	handler := HandleOIDCCallback(provider)

	tests := []struct {
		name       string
		queryState string
		cookieVal  string
	}{
		{"missing cookie", "some-state", ""},
		{"state mismatch", "state-a", "state-b"},
		{"empty query state", "", "cookie-state"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqURL := fmt.Sprintf("/auth/callback?code=some-code&state=%s", tt.queryState)
			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			if tt.cookieVal != "" {
				req.AddCookie(&http.Cookie{
					Name:  OIDCStateCookieName,
					Value: tt.cookieVal,
				})
			}
			rec := httptest.NewRecorder()
			handler(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
			}
		})
	}
}

func TestHandleOIDCCallback_MissingCode(t *testing.T) {
	provider := NewOIDCProvider(
		config.OIDCConfig{Issuer: "http://example.com"},
		&mockUserStore{}, &mockAPIKeyStore{}, &mockSessionStore{}, 3600,
	)

	handler := HandleOIDCCallback(provider)
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=valid-state", nil)
	req.AddCookie(&http.Cookie{
		Name:  OIDCStateCookieName,
		Value: "valid-state",
	})
	rec := httptest.NewRecorder()

	handler(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestOIDCAuthProvider_DefaultScopes(t *testing.T) {
	key := testRSAKey(t)
	server := setupMockOIDCServer(t, key, "test-kid", mockOIDCOpts{})

	// No scopes configured - should use defaults
	provider := NewOIDCProvider(
		config.OIDCConfig{
			Issuer:       server.URL,
			ClientID:     "test-client-id",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost:8080/auth/callback",
			Scopes:       nil,
		},
		&mockUserStore{}, &mockAPIKeyStore{}, &mockSessionStore{}, 3600,
	)

	authURL, err := provider.AuthorizationURL("test-state")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, _ := url.Parse(authURL)
	scope := parsed.Query().Get("scope")
	if scope != "openid email profile" {
		t.Errorf("default scope = %q, want %q", scope, "openid email profile")
	}
}
