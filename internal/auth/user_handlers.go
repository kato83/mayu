package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// createAPIKeyRequest is the JSON request body for POST /api/v1/user/api-keys.
type createAPIKeyRequest struct {
	Name          string `json:"name"`
	ExpiresInDays *int   `json:"expires_in_days,omitempty"`
}

// createAPIKeyResponse is the JSON response for a successful API key creation.
type createAPIKeyResponse struct {
	Key    string         `json:"key"`
	APIKey apiKeyResponse `json:"api_key"`
}

// apiKeyResponse is the JSON representation of an API key in API responses.
type apiKeyResponse struct {
	ID        int64   `json:"id"`
	Name      string  `json:"name"`
	KeyPrefix string  `json:"key_prefix"`
	CreatedAt string  `json:"created_at"`
	ExpiresAt *string `json:"expires_at,omitempty"`
}

// HandleListAPIKeys returns an http.HandlerFunc that lists the current user's API keys.
func HandleListAPIKeys(apiKeys APIKeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			writeAuthError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		keys, err := apiKeys.ListAPIKeys(r.Context(), user.ID)
		if err != nil {
			writeAuthError(w, http.StatusInternalServerError, "failed to list API keys")
			return
		}

		resp := make([]apiKeyResponse, 0, len(keys))
		for _, k := range keys {
			item := apiKeyResponse{
				ID:        k.ID,
				Name:      k.Name,
				KeyPrefix: k.KeyPrefix,
				CreatedAt: k.CreatedAt.Format(time.RFC3339),
			}
			if k.ExpiresAt != nil {
				s := k.ExpiresAt.Format(time.RFC3339)
				item.ExpiresAt = &s
			}
			resp = append(resp, item)
		}

		writeAuthJSON(w, http.StatusOK, resp)
	}
}

// HandleCreateAPIKey returns an http.HandlerFunc that creates an API key for the current user.
func HandleCreateAPIKey(apiKeys APIKeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			writeAuthError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var req createAPIKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAuthError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Generate random 32-byte API key
		keyBytes := make([]byte, 32)
		if _, err := rand.Read(keyBytes); err != nil {
			writeAuthError(w, http.StatusInternalServerError, "failed to generate key")
			return
		}
		rawKey := "mayu_" + hex.EncodeToString(keyBytes)

		keyHash := HashAPIKey(rawKey)
		keyPrefix := APIKeyPrefix(rawKey)

		var expiresAt *time.Time
		if req.ExpiresInDays != nil && *req.ExpiresInDays > 0 {
			t := time.Now().Add(time.Duration(*req.ExpiresInDays) * 24 * time.Hour)
			expiresAt = &t
		}

		apiKey, err := apiKeys.CreateAPIKey(r.Context(), user.ID, req.Name, keyHash, keyPrefix, expiresAt)
		if err != nil {
			writeAuthError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create API key: %v", err))
			return
		}

		resp := createAPIKeyResponse{
			Key: rawKey,
			APIKey: apiKeyResponse{
				ID:        apiKey.ID,
				Name:      apiKey.Name,
				KeyPrefix: apiKey.KeyPrefix,
				CreatedAt: apiKey.CreatedAt.Format(time.RFC3339),
			},
		}
		if apiKey.ExpiresAt != nil {
			s := apiKey.ExpiresAt.Format(time.RFC3339)
			resp.APIKey.ExpiresAt = &s
		}

		writeAuthJSON(w, http.StatusCreated, resp)
	}
}

// HandleDeleteAPIKey returns an http.HandlerFunc that deletes an API key by ID for the current user.
func HandleDeleteAPIKey(apiKeys APIKeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			writeAuthError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		idStr := chi.URLParam(r, "id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeAuthError(w, http.StatusBadRequest, "invalid API key ID")
			return
		}

		if err := apiKeys.DeleteAPIKey(r.Context(), id, user.ID); err != nil {
			writeAuthError(w, http.StatusInternalServerError, "failed to delete API key")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
