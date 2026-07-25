// Package auth provides authentication and authorization for mayu.
// It supports multiple auth modes: local (email/password), OIDC, and none
// (development/backward-compatible mode where all requests are allowed).
package auth

import "context"

// Role constants define the supported authorization roles.
const (
	// RoleAdmin grants full access to all resources.
	RoleAdmin = "admin"
	// RoleViewer grants read-only access to resources.
	RoleViewer = "viewer"
)

// User represents an authenticated user.
type User struct {
	ID    int64
	Email string
	Name  string
	Role  string
}

// AuthProvider defines the interface for authentication providers.
// Implementations must be safe for concurrent use.
type AuthProvider interface {
	// Authenticate verifies email and password credentials.
	// Returns the authenticated user or an error if credentials are invalid.
	Authenticate(ctx context.Context, email, password string) (*User, error)

	// ValidateSession checks whether a session ID is valid and not expired.
	// Returns the user associated with the session.
	ValidateSession(ctx context.Context, sessionID string) (*User, error)

	// ValidateAPIKey checks whether a raw API key is valid.
	// Returns the user associated with the key.
	ValidateAPIKey(ctx context.Context, rawKey string) (*User, error)

	// CreateSession creates a new session for the given user.
	// Returns the session ID to be stored in a cookie or header.
	CreateSession(ctx context.Context, userID int64) (sessionID string, err error)

	// DeleteSession invalidates the given session.
	DeleteSession(ctx context.Context, sessionID string) error

	// Mode returns the authentication mode name (e.g., "local", "none", "oidc").
	Mode() string
}
