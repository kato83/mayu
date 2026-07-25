package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Common errors returned by the local auth provider.
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrSessionExpired     = errors.New("session expired")
	ErrInvalidAPIKey      = errors.New("invalid api key")
	ErrAPIKeyExpired      = errors.New("api key expired")
)

// apiKeyPrefixLen is the number of characters used as the key prefix for lookup.
const apiKeyPrefixLen = 8

// LocalAuthProvider implements AuthProvider using local email/password
// authentication with bcrypt hashing and database-backed sessions.
type LocalAuthProvider struct {
	users    UserStore
	apiKeys  APIKeyStore
	sessions SessionStore
	maxAge   time.Duration
}

// NewLocalAuthProvider creates a new LocalAuthProvider.
// maxAge specifies the session lifetime; if zero, defaults to 24 hours.
func NewLocalAuthProvider(users UserStore, apiKeys APIKeyStore, sessions SessionStore, maxAge int) *LocalAuthProvider {
	duration := time.Duration(maxAge) * time.Second
	if duration <= 0 {
		duration = 24 * time.Hour
	}
	return &LocalAuthProvider{
		users:    users,
		apiKeys:  apiKeys,
		sessions: sessions,
		maxAge:   duration,
	}
}

// Authenticate verifies email and password credentials using bcrypt.
func (p *LocalAuthProvider) Authenticate(ctx context.Context, email, password string) (*User, error) {
	u, err := p.users.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("authenticate: %w", err)
	}
	if u == nil {
		return nil, ErrInvalidCredentials
	}
	if u.PasswordHash == "" {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return &u.User, nil
}

// ValidateSession checks whether a session ID is valid and not expired.
func (p *LocalAuthProvider) ValidateSession(ctx context.Context, sessionID string) (*User, error) {
	sess, err := p.sessions.GetSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("validate session: %w", err)
	}
	if sess == nil {
		return nil, ErrSessionExpired
	}
	if time.Now().After(sess.ExpiresAt) {
		// Clean up the expired session
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

// ValidateAPIKey validates a raw API key by extracting the prefix, looking up
// candidates, and comparing the SHA-256 hash using constant-time comparison.
func (p *LocalAuthProvider) ValidateAPIKey(ctx context.Context, rawKey string) (*User, error) {
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

	// Compute SHA-256 hash of the raw key
	hash := sha256.Sum256([]byte(rawKey))
	rawHash := hex.EncodeToString(hash[:])

	for _, candidate := range candidates {
		if subtle.ConstantTimeCompare([]byte(rawHash), []byte(candidate.KeyHash)) == 1 {
			// Check expiration
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
func (p *LocalAuthProvider) CreateSession(ctx context.Context, userID int64) (string, error) {
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
func (p *LocalAuthProvider) DeleteSession(ctx context.Context, sessionID string) error {
	return p.sessions.DeleteSession(ctx, sessionID)
}

// Mode returns "local".
func (p *LocalAuthProvider) Mode() string {
	return "local"
}

// HashPassword hashes a password using bcrypt with the default cost.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

// HashAPIKey computes the SHA-256 hash of a raw API key for storage.
func HashAPIKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}

// APIKeyPrefix returns the prefix portion of a raw API key.
func APIKeyPrefix(rawKey string) string {
	if len(rawKey) < apiKeyPrefixLen {
		return rawKey
	}
	return rawKey[:apiKeyPrefixLen]
}

// generateToken produces a cryptographically random hex string of the given byte length.
func generateToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
