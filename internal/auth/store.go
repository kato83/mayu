package auth

import (
	"context"
	"time"
)

// UserStore defines the interface for user persistence operations.
type UserStore interface {
	// CreateUser creates a new user with the given attributes.
	// Returns the created user with its generated ID.
	CreateUser(ctx context.Context, email, name, role, passwordHash string) (*User, error)

	// GetUserByEmail retrieves a user by email address.
	// Returns nil, nil if not found.
	GetUserByEmail(ctx context.Context, email string) (*UserWithPassword, error)

	// GetUserByID retrieves a user by ID.
	// Returns nil, nil if not found.
	GetUserByID(ctx context.Context, id int64) (*User, error)

	// ListUsers returns all users ordered by ID.
	ListUsers(ctx context.Context) ([]*User, error)

	// UpdateUserRole updates the role for a user identified by email.
	// Returns the updated user, or an error if not found.
	UpdateUserRole(ctx context.Context, email, role string) (*User, error)

	// UpdateUserOIDCSubject sets the OIDC subject identifier for a user.
	UpdateUserOIDCSubject(ctx context.Context, userID int64, subject string) error

	// GetUserByOIDCSubject retrieves a user by OIDC subject identifier.
	// Returns nil, nil if not found.
	GetUserByOIDCSubject(ctx context.Context, subject string) (*User, error)
}

// APIKeyStore defines the interface for API key persistence operations.
type APIKeyStore interface {
	// CreateAPIKey creates a new API key record.
	// Returns the created key metadata (without the hash).
	CreateAPIKey(ctx context.Context, userID int64, name string, keyHash string, keyPrefix string, expiresAt *time.Time) (*APIKey, error)

	// ListAPIKeys returns all API keys for a user, ordered by creation time.
	ListAPIKeys(ctx context.Context, userID int64) ([]*APIKey, error)

	// DeleteAPIKey removes an API key by ID, scoped to a user.
	// Returns the number of rows affected (0 if not found).
	DeleteAPIKey(ctx context.Context, id int64, userID int64) (int64, error)

	// GetAPIKeyByPrefix retrieves all API key records matching the given prefix.
	// Returns the full records including the hash for verification.
	GetAPIKeyByPrefix(ctx context.Context, prefix string) ([]*APIKeyWithHash, error)
}

// SessionStore defines the interface for session persistence operations.
type SessionStore interface {
	// CreateSession stores a new session record.
	CreateSession(ctx context.Context, id string, userID int64, expiresAt time.Time) error

	// GetSession retrieves a session by ID.
	// Returns nil, nil if not found.
	GetSession(ctx context.Context, id string) (*Session, error)

	// DeleteSession removes a session by ID.
	DeleteSession(ctx context.Context, id string) error

	// DeleteExpiredSessions removes all sessions that have expired.
	DeleteExpiredSessions(ctx context.Context) error
}

// UserWithPassword extends User with the password hash for authentication.
type UserWithPassword struct {
	User
	PasswordHash string
}

// APIKey represents an API key record (without the sensitive hash).
type APIKey struct {
	ID        int64
	UserID    int64
	Name      string
	KeyPrefix string
	CreatedAt time.Time
	ExpiresAt *time.Time
}

// APIKeyWithHash extends APIKey with the hash for server-side verification.
type APIKeyWithHash struct {
	APIKey
	KeyHash string
}

// Session represents an active user session.
type Session struct {
	ID        string
	UserID    int64
	CreatedAt time.Time
	ExpiresAt time.Time
}
