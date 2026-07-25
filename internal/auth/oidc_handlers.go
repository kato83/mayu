package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"
)

// OIDCStateCookieName is the name of the short-lived cookie that stores
// the OIDC state parameter for CSRF protection.
const OIDCStateCookieName = "mayu_oidc_state"

// oidcStateCookieMaxAge is the lifetime of the state cookie (5 minutes).
const oidcStateCookieMaxAge = 300

// HandleOIDCLogin returns an http.HandlerFunc that initiates the OIDC
// authorization code flow. It generates a random state parameter, stores it
// in a short-lived cookie, and redirects the user to the OIDC provider's
// authorization endpoint.
func HandleOIDCLogin(provider *OIDCAuthProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generate random state for CSRF protection
		stateBytes := make([]byte, 16)
		if _, err := rand.Read(stateBytes); err != nil {
			writeAuthError(w, http.StatusInternalServerError, "failed to generate state")
			return
		}
		state := hex.EncodeToString(stateBytes)

		// Store state in a short-lived cookie
		http.SetCookie(w, &http.Cookie{
			Name:     OIDCStateCookieName,
			Value:    state,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   oidcStateCookieMaxAge,
		})

		// Build authorization URL and redirect
		authURL, err := provider.AuthorizationURL(state)
		if err != nil {
			writeAuthError(w, http.StatusInternalServerError, "failed to build authorization URL")
			return
		}

		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// HandleOIDCCallback returns an http.HandlerFunc that handles the OIDC
// callback after the user authenticates with the identity provider. It
// validates the state parameter, exchanges the authorization code for tokens,
// creates a session, and redirects to the application root.
func HandleOIDCCallback(provider *OIDCAuthProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Validate state parameter
		stateCookie, err := r.Cookie(OIDCStateCookieName)
		if err != nil || stateCookie.Value == "" {
			writeAuthError(w, http.StatusBadRequest, "missing state cookie")
			return
		}

		queryState := r.URL.Query().Get("state")
		if queryState == "" || queryState != stateCookie.Value {
			writeAuthError(w, http.StatusBadRequest, "invalid state parameter")
			return
		}

		// Clear the state cookie
		http.SetCookie(w, &http.Cookie{
			Name:     OIDCStateCookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})

		// Check for error from the OIDC provider
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			desc := r.URL.Query().Get("error_description")
			if desc == "" {
				desc = errParam
			}
			writeAuthError(w, http.StatusBadRequest, "OIDC error: "+desc)
			return
		}

		// Get authorization code
		code := r.URL.Query().Get("code")
		if code == "" {
			writeAuthError(w, http.StatusBadRequest, "missing authorization code")
			return
		}

		// Exchange code and get user
		user, err := provider.HandleCallback(r.Context(), code)
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized, "authentication failed")
			return
		}

		// Create session
		sessionID, err := provider.CreateSession(r.Context(), user.ID)
		if err != nil {
			writeAuthError(w, http.StatusInternalServerError, "failed to create session")
			return
		}

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     CookieName,
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(24 * time.Hour / time.Second),
		})

		// Redirect to application root
		http.Redirect(w, r, "/", http.StatusFound)
	}
}
