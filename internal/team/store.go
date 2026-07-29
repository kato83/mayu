package team

import "context"

// TeamStore defines the interface for team data persistence.
type TeamStore interface {
	// CreateTeam creates a new team and returns the generated ID.
	CreateTeam(ctx context.Context, t *Team) (int64, error)

	// GetTeam retrieves a team by ID. Returns nil, nil if not found.
	GetTeam(ctx context.Context, id int64) (*Team, error)

	// GetTeamByName retrieves a team by name. Returns nil, nil if not found.
	GetTeamByName(ctx context.Context, name string) (*Team, error)

	// ListTeams returns all teams, ordered by name.
	ListTeams(ctx context.Context) ([]*Team, error)

	// ListTeamsByUser returns teams that a user belongs to.
	ListTeamsByUser(ctx context.Context, userID int64) ([]*Team, error)

	// UpdateTeam updates an existing team.
	UpdateTeam(ctx context.Context, t *Team) error

	// DeleteTeam removes a team by ID.
	DeleteTeam(ctx context.Context, id int64) error

	// AddMember adds a user to a team with the specified role.
	AddMember(ctx context.Context, teamID, userID int64, role string) error

	// RemoveMember removes a user from a team.
	RemoveMember(ctx context.Context, teamID, userID int64) error

	// ListMembers returns all members of a team.
	ListMembers(ctx context.Context, teamID int64) ([]*TeamMember, error)

	// GetMembership returns the membership record for a user in a team.
	// Returns nil, nil if the user is not a member.
	GetMembership(ctx context.Context, teamID, userID int64) (*TeamMember, error)

	// IsTeamMember checks if a user belongs to a team (any role).
	IsTeamMember(ctx context.Context, teamID, userID int64) (bool, error)

	// GetUserTeamIDs returns all team IDs that a user belongs to.
	GetUserTeamIDs(ctx context.Context, userID int64) ([]int64, error)

	// ListUsers returns all users (for member picker UI).
	ListUsers(ctx context.Context) ([]*UserInfo, error)
}
