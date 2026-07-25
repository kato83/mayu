package auth

import "context"

// NoAuthProvider implements AuthProvider for development and backward-compatible
// configurations where authentication is disabled. All validation methods
// return a synthetic admin user, effectively allowing unrestricted access.
type NoAuthProvider struct{}

// NewNoAuthProvider creates a new NoAuthProvider.
func NewNoAuthProvider() *NoAuthProvider {
	return &NoAuthProvider{}
}

// syntheticAdmin is the user returned for all unauthenticated requests.
var syntheticAdmin = &User{
	ID:    0,
	Email: "admin@localhost",
	Name:  "Admin",
	Role:  RoleAdmin,
}

// Authenticate always returns the synthetic admin user regardless of credentials.
func (p *NoAuthProvider) Authenticate(_ context.Context, _, _ string) (*User, error) {
	return syntheticAdmin, nil
}

// ValidateSession always returns the synthetic admin user.
func (p *NoAuthProvider) ValidateSession(_ context.Context, _ string) (*User, error) {
	return syntheticAdmin, nil
}

// ValidateAPIKey always returns the synthetic admin user.
func (p *NoAuthProvider) ValidateAPIKey(_ context.Context, _ string) (*User, error) {
	return syntheticAdmin, nil
}

// CreateSession returns a fixed session ID (no-op for no-auth mode).
func (p *NoAuthProvider) CreateSession(_ context.Context, _ int64) (string, error) {
	return "no-auth-session", nil
}

// DeleteSession is a no-op for no-auth mode.
func (p *NoAuthProvider) DeleteSession(_ context.Context, _ string) error {
	return nil
}

// Mode returns "none".
func (p *NoAuthProvider) Mode() string {
	return "none"
}
