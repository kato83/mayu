// Package team provides data models, store interface, and implementation
// for the team/group feature, which allows users to be organized into
// logical units (departments, squads, projects) for resource scoping.
package team

import "time"

// Role constants for team membership.
const (
	RoleOwner  = "owner"
	RoleMember = "member"
)

// Team represents a group/team for organizing users.
type Team struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TeamMember represents a user's membership in a team.
type TeamMember struct {
	ID     int64  `json:"id"`
	TeamID int64  `json:"team_id"`
	UserID int64  `json:"user_id"`
	Role   string `json:"role"` // "owner" or "member"
	Email  string `json:"email,omitempty"`
	Name   string `json:"name,omitempty"`
}

// CreateTeamInput holds the input for creating a new team.
type CreateTeamInput struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// UpdateTeamInput holds the input for updating a team.
type UpdateTeamInput struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

// AddMemberInput holds the input for adding a member to a team.
type AddMemberInput struct {
	UserID int64  `json:"user_id"`
	Role   string `json:"role"` // "owner" or "member"
}

// UserInfo is a minimal user representation for the team member picker.
type UserInfo struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}
