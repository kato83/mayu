package team

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/kato83/mayu/internal/auth"
)

// HandleCreateTeam returns a handler for POST /api/v1/teams.
func HandleCreateTeam(store TeamStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var input CreateTeamInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if input.Name == "" {
			writeError(w, http.StatusBadRequest, "name is required")
			return
		}

		t := &Team{
			Name:        input.Name,
			Description: input.Description,
		}
		id, err := store.CreateTeam(r.Context(), t)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create team")
			return
		}

		// Add creator as owner
		if err := store.AddMember(r.Context(), id, user.ID, RoleOwner); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to add creator as owner")
			return
		}

		created, err := store.GetTeam(r.Context(), id)
		if err != nil || created == nil {
			writeError(w, http.StatusInternalServerError, "failed to retrieve created team")
			return
		}

		writeJSON(w, http.StatusCreated, created)
	}
}

// HandleListTeams returns a handler for GET /api/v1/teams.
func HandleListTeams(store TeamStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var teams []*Team
		var err error
		if user.Role == "admin" {
			teams, err = store.ListTeams(r.Context())
		} else {
			teams, err = store.ListTeamsByUser(r.Context(), user.ID)
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list teams")
			return
		}

		writeJSON(w, http.StatusOK, teams)
	}
}

// HandleGetTeam returns a handler for GET /api/v1/teams/{id}.
func HandleGetTeam(store TeamStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid team ID")
			return
		}

		t, err := store.GetTeam(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get team")
			return
		}
		if t == nil {
			writeError(w, http.StatusNotFound, "team not found")
			return
		}

		// Non-admin must be a member
		if user.Role != "admin" {
			isMember, err := store.IsTeamMember(r.Context(), id, user.ID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to check membership")
				return
			}
			if !isMember {
				writeError(w, http.StatusForbidden, "not a team member")
				return
			}
		}

		writeJSON(w, http.StatusOK, t)
	}
}

// HandleUpdateTeam returns a handler for PUT /api/v1/teams/{id}.
func HandleUpdateTeam(store TeamStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid team ID")
			return
		}

		// Check permission: must be admin or team owner
		if user.Role != "admin" {
			membership, err := store.GetMembership(r.Context(), id, user.ID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to check membership")
				return
			}
			if membership == nil || membership.Role != RoleOwner {
				writeError(w, http.StatusForbidden, "only team owners or admins can update teams")
				return
			}
		}

		t, err := store.GetTeam(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get team")
			return
		}
		if t == nil {
			writeError(w, http.StatusNotFound, "team not found")
			return
		}

		var input UpdateTeamInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if input.Name != nil {
			t.Name = *input.Name
		}
		if input.Description != nil {
			t.Description = *input.Description
		}

		if err := store.UpdateTeam(r.Context(), t); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update team")
			return
		}

		writeJSON(w, http.StatusOK, t)
	}
}

// HandleDeleteTeam returns a handler for DELETE /api/v1/teams/{id}.
func HandleDeleteTeam(store TeamStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid team ID")
			return
		}

		// Only admin or team owner can delete
		if user.Role != "admin" {
			membership, err := store.GetMembership(r.Context(), id, user.ID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to check membership")
				return
			}
			if membership == nil || membership.Role != RoleOwner {
				writeError(w, http.StatusForbidden, "only team owners or admins can delete teams")
				return
			}
		}

		if err := store.DeleteTeam(r.Context(), id); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to delete team")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// HandleAddMember returns a handler for POST /api/v1/teams/{id}/members.
func HandleAddMember(store TeamStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		teamID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid team ID")
			return
		}

		// Only admin or team owner can add members
		if user.Role != "admin" {
			membership, err := store.GetMembership(r.Context(), teamID, user.ID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to check membership")
				return
			}
			if membership == nil || membership.Role != RoleOwner {
				writeError(w, http.StatusForbidden, "only team owners or admins can add members")
				return
			}
		}

		var input AddMemberInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if input.UserID == 0 {
			writeError(w, http.StatusBadRequest, "user_id is required")
			return
		}
		if input.Role == "" {
			input.Role = RoleMember
		}
		if input.Role != RoleOwner && input.Role != RoleMember {
			writeError(w, http.StatusBadRequest, "role must be 'owner' or 'member'")
			return
		}

		if err := store.AddMember(r.Context(), teamID, input.UserID, input.Role); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to add member")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// HandleRemoveMember returns a handler for DELETE /api/v1/teams/{id}/members/{userId}.
func HandleRemoveMember(store TeamStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		teamID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid team ID")
			return
		}

		memberUserID, err := strconv.ParseInt(chi.URLParam(r, "userId"), 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid user ID")
			return
		}

		// Only admin or team owner can remove members
		if user.Role != "admin" {
			membership, err := store.GetMembership(r.Context(), teamID, user.ID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to check membership")
				return
			}
			if membership == nil || membership.Role != RoleOwner {
				writeError(w, http.StatusForbidden, "only team owners or admins can remove members")
				return
			}
		}

		if err := store.RemoveMember(r.Context(), teamID, memberUserID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to remove member")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// HandleListMembers returns a handler for GET /api/v1/teams/{id}/members.
func HandleListMembers(store TeamStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		teamID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid team ID")
			return
		}

		// Non-admin must be a member to list members
		if user.Role != "admin" {
			isMember, err := store.IsTeamMember(r.Context(), teamID, user.ID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to check membership")
				return
			}
			if !isMember {
				writeError(w, http.StatusForbidden, "not a team member")
				return
			}
		}

		members, err := store.ListMembers(r.Context(), teamID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list members")
			return
		}

		writeJSON(w, http.StatusOK, members)
	}
}

// HandleListUsers returns a handler for GET /api/v1/teams/users.
// Used by the UI for the member add autocomplete/datalist.
func HandleListUsers(store TeamStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		users, err := store.ListUsers(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list users")
			return
		}

		writeJSON(w, http.StatusOK, users)
	}
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
