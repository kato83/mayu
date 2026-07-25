package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kato83/mayu/internal/config"
)

// Common errors returned by the OIDC auth provider.
var (
	ErrOIDCNotSupported = errors.New("direct authentication not supported for OIDC; use /auth/oidc/login")
	ErrOIDCCodeExchange = errors.New("failed to exchange authorization code")
	ErrOIDCMissingEmail = errors.New("OIDC token missing required email claim")
	ErrOIDCInvalidToken = errors.New("invalid ID token")
)

// oidcDiscovery represents the relevant fields from /.well-known/openid-configuration.
type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// oidcTokenResponse represents the token endpoint response.
type oidcTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

// oidcClaims represents the claims extracted from an ID token or userinfo.
type oidcClaims struct {
	Sub   string        `json:"sub"`
	Email string        `json:"email"`
	Name  string        `json:"name"`
	Iss   string        `json:"iss"`
	Aud   stringOrArray `json:"aud"`
	Exp   int64         `json:"exp"`
}

// stringOrArray handles the OIDC "aud" claim which can be either a single
// string or an array of strings per RFC 7519 Section 4.1.3.
type stringOrArray []string

func (s *stringOrArray) UnmarshalJSON(data []byte) error {
	// Try as a single string first
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = []string{single}
		return nil
	}
	// Try as an array of strings
	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return fmt.Errorf("aud must be a string or array of strings: %w", err)
	}
	*s = multi
	return nil
}

// Contains checks if the audience list contains the given value.
func (s stringOrArray) Contains(val string) bool {
	for _, v := range s {
		if v == val {
			return true
		}
	}
	return false
}

// jwksResponse represents a JSON Web Key Set response.
type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

// jwkKey represents a single JSON Web Key (RSA public key).
type jwkKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwtHeader represents the header portion of a JWT.
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// discoveryTTL is how long the OIDC discovery document is cached before re-fetching.
const discoveryTTL = 1 * time.Hour

// jwksTTL is how long JWKS keys are cached before re-fetching.
const jwksTTL = 24 * time.Hour

// clockSkewTolerance is the tolerance for clock differences when validating token expiry.
const clockSkewTolerance = 2 * time.Minute

// OIDCAuthProvider implements AuthProvider for OpenID Connect authentication.
// It handles the authorization code flow with callback, user auto-provisioning,
// and delegates session/API key validation to the underlying stores.
type OIDCAuthProvider struct {
	cfg      config.OIDCConfig
	users    UserStore
	apiKeys  APIKeyStore
	sessions SessionStore
	maxAge   time.Duration
	client   *http.Client

	// Cached discovery document with TTL
	mu             sync.RWMutex
	discovery      *oidcDiscovery
	discoveryFetch time.Time
	jwks           map[string]*rsa.PublicKey
	jwksFetch      time.Time
}

// NewOIDCProvider creates a new OIDCAuthProvider.
// sessionMaxAge specifies the session lifetime in seconds; if zero, defaults to 24 hours.
func NewOIDCProvider(cfg config.OIDCConfig, userStore UserStore, apiKeyStore APIKeyStore, sessionStore SessionStore, sessionMaxAge int) *OIDCAuthProvider {
	duration := time.Duration(sessionMaxAge) * time.Second
	if duration <= 0 {
		duration = 24 * time.Hour
	}
	return &OIDCAuthProvider{
		cfg:      cfg,
		users:    userStore,
		apiKeys:  apiKeyStore,
		sessions: sessionStore,
		maxAge:   duration,
		client:   &http.Client{Timeout: 10 * time.Second},
		jwks:     make(map[string]*rsa.PublicKey),
	}
}

// Authenticate is not supported for OIDC. Users must authenticate via the
// OIDC login flow (/auth/oidc/login).
func (p *OIDCAuthProvider) Authenticate(_ context.Context, _, _ string) (*User, error) {
	return nil, ErrOIDCNotSupported
}

// ValidateSession checks whether a session ID is valid and not expired.
func (p *OIDCAuthProvider) ValidateSession(ctx context.Context, sessionID string) (*User, error) {
	sess, err := p.sessions.GetSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("validate session: %w", err)
	}
	if sess == nil {
		return nil, ErrSessionExpired
	}
	if time.Now().After(sess.ExpiresAt) {
		_ = p.sessions.DeleteSession(ctx, sessionID)
		return nil, ErrSessionExpired
	}

	user, err := p.users.GetUserByID(ctx, sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("validate session user: %w", err)
	}
	if user == nil {
		return nil, ErrSessionExpired
	}
	return user, nil
}

// ValidateAPIKey validates a raw API key.
func (p *OIDCAuthProvider) ValidateAPIKey(ctx context.Context, rawKey string) (*User, error) {
	if len(rawKey) < apiKeyPrefixLen {
		return nil, ErrInvalidAPIKey
	}

	prefix := rawKey[:apiKeyPrefixLen]
	candidates, err := p.apiKeys.GetAPIKeyByPrefix(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("validate api key: %w", err)
	}
	if len(candidates) == 0 {
		return nil, ErrInvalidAPIKey
	}

	rawHash := HashAPIKey(rawKey)

	for _, candidate := range candidates {
		if subtle.ConstantTimeCompare([]byte(rawHash), []byte(candidate.KeyHash)) == 1 {
			if candidate.ExpiresAt != nil && time.Now().After(*candidate.ExpiresAt) {
				return nil, ErrAPIKeyExpired
			}
			user, err := p.users.GetUserByID(ctx, candidate.UserID)
			if err != nil {
				return nil, fmt.Errorf("validate api key user: %w", err)
			}
			if user == nil {
				return nil, ErrInvalidAPIKey
			}
			return user, nil
		}
	}

	return nil, ErrInvalidAPIKey
}

// CreateSession generates a new random session token and stores it.
func (p *OIDCAuthProvider) CreateSession(ctx context.Context, userID int64) (string, error) {
	token, err := generateToken(32)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}

	expiresAt := time.Now().Add(p.maxAge)
	if err := p.sessions.CreateSession(ctx, token, userID, expiresAt); err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return token, nil
}

// DeleteSession invalidates the given session.
func (p *OIDCAuthProvider) DeleteSession(ctx context.Context, sessionID string) error {
	return p.sessions.DeleteSession(ctx, sessionID)
}

// Mode returns "oidc".
func (p *OIDCAuthProvider) Mode() string {
	return "oidc"
}

// AuthorizationURL builds the OIDC authorization URL with configured scopes
// and the given state parameter.
func (p *OIDCAuthProvider) AuthorizationURL(state string) (string, error) {
	disc, err := p.getDiscovery()
	if err != nil {
		return "", fmt.Errorf("get discovery: %w", err)
	}

	params := url.Values{}
	params.Set("client_id", p.cfg.ClientID)
	params.Set("redirect_uri", p.cfg.RedirectURL)
	params.Set("response_type", "code")
	params.Set("state", state)

	scopes := p.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	params.Set("scope", strings.Join(scopes, " "))

	return disc.AuthorizationEndpoint + "?" + params.Encode(), nil
}

// HandleCallback exchanges the authorization code for tokens, extracts user
// claims, and upserts the user. Returns the user record.
func (p *OIDCAuthProvider) HandleCallback(ctx context.Context, code string) (*User, error) {
	disc, err := p.getDiscovery()
	if err != nil {
		return nil, fmt.Errorf("get discovery: %w", err)
	}

	// Exchange code for tokens
	tokenResp, err := p.exchangeCode(ctx, disc.TokenEndpoint, code)
	if err != nil {
		return nil, err
	}

	// Extract claims from ID token or userinfo endpoint
	claims, err := p.extractClaims(ctx, disc, tokenResp)
	if err != nil {
		return nil, err
	}

	if claims.Email == "" {
		return nil, ErrOIDCMissingEmail
	}

	// Upsert user: match by oidc_subject first, then by email
	user, err := p.upsertUser(ctx, claims)
	if err != nil {
		return nil, fmt.Errorf("upsert user: %w", err)
	}

	return user, nil
}

// getDiscovery fetches and caches the OIDC discovery document with TTL-based refresh.
func (p *OIDCAuthProvider) getDiscovery() (*oidcDiscovery, error) {
	p.mu.RLock()
	if p.discovery != nil && time.Since(p.discoveryFetch) < discoveryTTL {
		disc := p.discovery
		p.mu.RUnlock()
		return disc, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if p.discovery != nil && time.Since(p.discoveryFetch) < discoveryTTL {
		return p.discovery, nil
	}

	discoveryURL := strings.TrimRight(p.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	resp, err := p.client.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("fetch discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	var disc oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return nil, fmt.Errorf("decode discovery document: %w", err)
	}

	p.discovery = &disc
	p.discoveryFetch = time.Now()
	return &disc, nil
}

// exchangeCode performs the token exchange with the OIDC provider.
func (p *OIDCAuthProvider) exchangeCode(ctx context.Context, tokenEndpoint, code string) (*oidcTokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", p.cfg.RedirectURL)
	data.Set("client_id", p.cfg.ClientID)
	data.Set("client_secret", p.cfg.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOIDCCodeExchange, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: token endpoint returned %d: %s", ErrOIDCCodeExchange, resp.StatusCode, string(body))
	}

	var tokenResp oidcTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("%w: decode token response: %v", ErrOIDCCodeExchange, err)
	}

	return &tokenResp, nil
}

// extractClaims extracts user claims from the ID token. If the ID token is
// present, it decodes and verifies it. Otherwise, it falls back to the
// userinfo endpoint.
func (p *OIDCAuthProvider) extractClaims(ctx context.Context, disc *oidcDiscovery, tokenResp *oidcTokenResponse) (*oidcClaims, error) {
	if tokenResp.IDToken != "" {
		claims, err := p.decodeIDToken(disc, tokenResp.IDToken)
		if err == nil {
			return claims, nil
		}
		// Fall back to userinfo if ID token parsing fails
	}

	// Use userinfo endpoint
	if disc.UserinfoEndpoint == "" {
		return nil, ErrOIDCInvalidToken
	}

	return p.fetchUserinfo(ctx, disc.UserinfoEndpoint, tokenResp.AccessToken)
}

// decodeIDToken decodes a JWT ID token and verifies its RSA signature and claims.
func (p *OIDCAuthProvider) decodeIDToken(disc *oidcDiscovery, idToken string) (*oidcClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, ErrOIDCInvalidToken
	}

	// Decode header
	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode JWT header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parse JWT header: %w", err)
	}

	// Verify signature
	if err := p.verifySignature(disc, parts, header.Kid); err != nil {
		return nil, err
	}

	// Decode payload
	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}

	var claims oidcClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("parse JWT claims: %w", err)
	}

	// Validate issuer
	if claims.Iss != disc.Issuer {
		return nil, fmt.Errorf("%w: issuer mismatch", ErrOIDCInvalidToken)
	}

	// Validate audience
	if !claims.Aud.Contains(p.cfg.ClientID) {
		return nil, fmt.Errorf("%w: audience mismatch", ErrOIDCInvalidToken)
	}

	// Validate expiration (with clock skew tolerance)
	if time.Now().After(time.Unix(claims.Exp, 0).Add(clockSkewTolerance)) {
		return nil, fmt.Errorf("%w: token expired", ErrOIDCInvalidToken)
	}

	return &claims, nil
}

// verifySignature verifies the RSA signature of a JWT using the JWKS.
func (p *OIDCAuthProvider) verifySignature(disc *oidcDiscovery, parts []string, kid string) error {
	key, err := p.getPublicKey(disc.JWKSURI, kid)
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}

	sigBytes, err := base64URLDecode(parts[2])
	if err != nil {
		return fmt.Errorf("decode JWT signature: %w", err)
	}

	// Compute the hash of the signed portion (header.payload)
	signedContent := []byte(parts[0] + "." + parts[1])

	if err := verifyRSASignature(key, signedContent, sigBytes); err != nil {
		return fmt.Errorf("RSA signature verification failed: %w", err)
	}

	return nil
}

// getPublicKey fetches and caches the RSA public key from the JWKS endpoint.
// If the kid is not found in cache or the cache is expired, it re-fetches JWKS.
func (p *OIDCAuthProvider) getPublicKey(jwksURI, kid string) (*rsa.PublicKey, error) {
	p.mu.RLock()
	if key, ok := p.jwks[kid]; ok && time.Since(p.jwksFetch) < jwksTTL {
		p.mu.RUnlock()
		return key, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check: if cache is still valid and kid exists, return it
	if key, ok := p.jwks[kid]; ok && time.Since(p.jwksFetch) < jwksTTL {
		return key, nil
	}

	// Fetch JWKS (either expired cache or unknown kid)
	resp, err := p.client.Get(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}

	// Replace cached keys with fresh set
	newKeys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pubKey, err := parseRSAPublicKey(k)
		if err != nil {
			continue
		}
		newKeys[k.Kid] = pubKey
	}
	p.jwks = newKeys
	p.jwksFetch = time.Now()

	key, ok := p.jwks[kid]
	if !ok {
		return nil, fmt.Errorf("key %q not found in JWKS", kid)
	}
	return key, nil
}

// fetchUserinfo calls the OIDC userinfo endpoint with the access token.
func (p *OIDCAuthProvider) fetchUserinfo(ctx context.Context, userinfoURL, accessToken string) (*oidcClaims, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned status %d", resp.StatusCode)
	}

	var claims oidcClaims
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("decode userinfo response: %w", err)
	}

	return &claims, nil
}

// upsertUser creates or updates a user based on OIDC claims.
// Match order: oidc_subject first, then email. New users get role=viewer.
func (p *OIDCAuthProvider) upsertUser(ctx context.Context, claims *oidcClaims) (*User, error) {
	// Try matching by OIDC subject
	if claims.Sub != "" {
		user, err := p.users.GetUserByOIDCSubject(ctx, claims.Sub)
		if err != nil {
			return nil, err
		}
		if user != nil {
			return user, nil
		}
	}

	// Try matching by email
	userWithPw, err := p.users.GetUserByEmail(ctx, claims.Email)
	if err != nil {
		return nil, err
	}
	if userWithPw != nil {
		// Update the OIDC subject if not already set
		if claims.Sub != "" {
			if err := p.users.UpdateUserOIDCSubject(ctx, userWithPw.ID, claims.Sub); err != nil {
				return nil, err
			}
		}
		return &userWithPw.User, nil
	}

	// Create new user with viewer role
	name := claims.Name
	if name == "" {
		name = claims.Email
	}
	user, err := p.users.CreateUser(ctx, claims.Email, name, RoleViewer, "")
	if err != nil {
		return nil, err
	}

	// Set the OIDC subject
	if claims.Sub != "" {
		if err := p.users.UpdateUserOIDCSubject(ctx, user.ID, claims.Sub); err != nil {
			return nil, err
		}
	}

	return user, nil
}

// parseRSAPublicKey parses a JWK into an *rsa.PublicKey.
func parseRSAPublicKey(k jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64URLDecode(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode N: %w", err)
	}
	eBytes, err := base64URLDecode(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode E: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// verifyRSASignature verifies an RSA PKCS#1 v1.5 signature with SHA-256.
func verifyRSASignature(key *rsa.PublicKey, message, signature []byte) error {
	hash := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature)
}

// base64URLDecode decodes a base64url-encoded string (no padding).
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}
