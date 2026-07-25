package auth

import (
	"context"
	"net/http"
	"strings"
)

// contextKey is an unexported type for context keys in this package.
// This prevents collisions with keys defined in other packages.
type contextKey struct{}

// userContextKey is the context key for the authenticated user.
var userContextKey = contextKey{}

// UserFromContext extracts the authenticated user from the request context.
// Returns nil if no user is present.
func UserFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(userContextKey).(*User)
	return u
}

// withUser returns a new context that carries the given user.
func withUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}

// SessionMiddleware returns middleware that validates the session cookie.
// If the cookie is missing or invalid, it responds with 401 Unauthorized.
func SessionMiddleware(provider AuthProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("mayu_session")
			if err != nil || cookie.Value == "" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			user, err := provider.ValidateSession(r.Context(), cookie.Value)
			if err != nil || user == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			ctx := withUser(r.Context(), user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// APIKeyMiddleware returns middleware that validates a Bearer token in the
// Authorization header. If the header is missing or the token is invalid,
// it responds with 401 Unauthorized.
func APIKeyMiddleware(provider AuthProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == "" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			user, err := provider.ValidateAPIKey(r.Context(), token)
			if err != nil || user == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			ctx := withUser(r.Context(), user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CombinedAuthMiddleware returns middleware that tries API key authentication
// first (if an Authorization header is present), then falls back to session
// cookie authentication. Returns 401 if neither method succeeds.
func CombinedAuthMiddleware(provider AuthProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try API key first if Authorization header is present
			if authHeader := r.Header.Get("Authorization"); authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				if token != "" {
					user, err := provider.ValidateAPIKey(r.Context(), token)
					if err == nil && user != nil {
						ctx := withUser(r.Context(), user)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
			}

			// Fall back to session cookie
			cookie, err := r.Cookie("mayu_session")
			if err == nil && cookie.Value != "" {
				user, err := provider.ValidateSession(r.Context(), cookie.Value)
				if err == nil && user != nil {
					ctx := withUser(r.Context(), user)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		})
	}
}

// RequireRole returns middleware that checks whether the authenticated user
// has one of the allowed roles. Responds with 403 Forbidden if the user
// lacks the required role, or 401 Unauthorized if no user is in the context.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			for _, role := range roles {
				if user.Role == role {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		})
	}
}

// OptionalAuth returns middleware that attempts authentication via API key
// or session cookie but does not reject unauthenticated requests. If valid
// credentials are found, the user is stored in the context. Otherwise the
// request proceeds without a user in the context.
func OptionalAuth(provider AuthProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try API key first
			if authHeader := r.Header.Get("Authorization"); authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				if token != "" {
					user, err := provider.ValidateAPIKey(r.Context(), token)
					if err == nil && user != nil {
						ctx := withUser(r.Context(), user)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
			}

			// Try session cookie
			cookie, err := r.Cookie("mayu_session")
			if err == nil && cookie.Value != "" {
				user, err := provider.ValidateSession(r.Context(), cookie.Value)
				if err == nil && user != nil {
					ctx := withUser(r.Context(), user)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// No valid credentials, proceed without user
			next.ServeHTTP(w, r)
		})
	}
}

// NoAuthMiddleware returns middleware that always sets the synthetic admin
// user in the request context. Used when auth mode is "none".
func NoAuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := withUser(r.Context(), syntheticAdmin)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
