package auth

import (
	"encoding/json"
	"net/http"
	"time"
)

// loginRequest is the JSON request body for POST /auth/login.
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// loginResponse is the JSON response for a successful login.
type loginResponse struct {
	User userResponse `json:"user"`
}

// userResponse is the JSON representation of a user in API responses.
type userResponse struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

// authConfigResponse is the JSON response for GET /auth/config.
type authConfigResponse struct {
	Mode string `json:"mode"`
}

// CookieName is the name of the session cookie.
const CookieName = "mayu_session"

// HandleLogin returns an http.HandlerFunc that authenticates a user with
// email and password, creates a session, and sets an HttpOnly cookie.
func HandleLogin(provider AuthProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAuthError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAuthError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.Email == "" || req.Password == "" {
			writeAuthError(w, http.StatusBadRequest, "email and password are required")
			return
		}

		user, err := provider.Authenticate(r.Context(), req.Email, req.Password)
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		sessionID, err := provider.CreateSession(r.Context(), user.ID)
		if err != nil {
			writeAuthError(w, http.StatusInternalServerError, "failed to create session")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     CookieName,
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(24 * time.Hour / time.Second),
		})

		writeAuthJSON(w, http.StatusOK, loginResponse{
			User: userResponse{
				ID:    user.ID,
				Email: user.Email,
				Name:  user.Name,
				Role:  user.Role,
			},
		})
	}
}

// HandleLogout returns an http.HandlerFunc that deletes the current session
// and clears the session cookie.
func HandleLogout(provider AuthProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAuthError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		cookie, err := r.Cookie(CookieName)
		if err == nil && cookie.Value != "" {
			_ = provider.DeleteSession(r.Context(), cookie.Value)
		}

		// Clear the cookie
		http.SetCookie(w, &http.Cookie{
			Name:     CookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})

		writeAuthJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// HandleAuthConfig returns an http.HandlerFunc that exposes the current
// authentication mode. This endpoint is public (no auth required) so the
// UI can determine which login flow to present.
func HandleAuthConfig(mode string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeAuthJSON(w, http.StatusOK, authConfigResponse{Mode: mode})
	}
}

// HandleMe returns an http.HandlerFunc that returns the currently
// authenticated user from the request context.
func HandleMe() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			writeAuthError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		writeAuthJSON(w, http.StatusOK, userResponse{
			ID:    user.ID,
			Email: user.Email,
			Name:  user.Name,
			Role:  user.Role,
		})
	}
}

// writeAuthJSON marshals v to JSON and writes it with the given status code.
func writeAuthJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeAuthError writes a JSON error response.
func writeAuthError(w http.ResponseWriter, status int, message string) {
	writeAuthJSON(w, status, map[string]string{"error": message})
}
