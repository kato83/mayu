package team

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// PostgresTeamStore implements TeamStore using database/sql with the pgx stdlib driver.
type PostgresTeamStore struct {
	db *sql.DB
}

// NewPostgresTeamStore creates a new PostgresTeamStore with the given database connection.
func NewPostgresTeamStore(db *sql.DB) *PostgresTeamStore {
	return &PostgresTeamStore{db: db}
}

func (s *PostgresTeamStore) CreateTeam(ctx context.Context, t *Team) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO teams (name, description) VALUES ($1, $2) RETURNING id`,
		t.Name, t.Description,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("create team: %w", err)
	}
	return id, nil
}

func (s *PostgresTeamStore) GetTeam(ctx context.Context, id int64) (*Team, error) {
	t := &Team{}
	var desc sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, description, created_at, updated_at FROM teams WHERE id = $1`,
		id,
	).Scan(&t.ID, &t.Name, &desc, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get team: %w", err)
	}
	if desc.Valid {
		t.Description = desc.String
	}
	return t, nil
}

func (s *PostgresTeamStore) GetTeamByName(ctx context.Context, name string) (*Team, error) {
	t := &Team{}
	var desc sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, description, created_at, updated_at FROM teams WHERE name = $1`,
		name,
	).Scan(&t.ID, &t.Name, &desc, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get team by name: %w", err)
	}
	if desc.Valid {
		t.Description = desc.String
	}
	return t, nil
}

func (s *PostgresTeamStore) ListTeams(ctx context.Context) ([]*Team, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, description, created_at, updated_at FROM teams ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("list teams: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var teams []*Team
	for rows.Next() {
		t := &Team{}
		var desc sql.NullString
		if err := rows.Scan(&t.ID, &t.Name, &desc, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan team: %w", err)
		}
		if desc.Valid {
			t.Description = desc.String
		}
		teams = append(teams, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate teams: %w", err)
	}
	if teams == nil {
		teams = []*Team{}
	}
	return teams, nil
}

func (s *PostgresTeamStore) ListTeamsByUser(ctx context.Context, userID int64) ([]*Team, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT t.id, t.name, t.description, t.created_at, t.updated_at
		 FROM teams t
		 JOIN team_members tm ON tm.team_id = t.id
		 WHERE tm.user_id = $1
		 ORDER BY t.name ASC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list teams by user: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var teams []*Team
	for rows.Next() {
		t := &Team{}
		var desc sql.NullString
		if err := rows.Scan(&t.ID, &t.Name, &desc, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan team: %w", err)
		}
		if desc.Valid {
			t.Description = desc.String
		}
		teams = append(teams, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate teams: %w", err)
	}
	if teams == nil {
		teams = []*Team{}
	}
	return teams, nil
}

func (s *PostgresTeamStore) UpdateTeam(ctx context.Context, t *Team) error {
	t.UpdatedAt = time.Now()
	_, err := s.db.ExecContext(ctx,
		`UPDATE teams SET name = $1, description = $2, updated_at = $3 WHERE id = $4`,
		t.Name, t.Description, t.UpdatedAt, t.ID,
	)
	if err != nil {
		return fmt.Errorf("update team: %w", err)
	}
	return nil
}

func (s *PostgresTeamStore) DeleteTeam(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM teams WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete team: %w", err)
	}
	return nil
}

func (s *PostgresTeamStore) AddMember(ctx context.Context, teamID, userID int64, role string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO team_members (team_id, user_id, role)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (team_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
		teamID, userID, role,
	)
	if err != nil {
		return fmt.Errorf("add team member: %w", err)
	}
	return nil
}

func (s *PostgresTeamStore) RemoveMember(ctx context.Context, teamID, userID int64) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM team_members WHERE team_id = $1 AND user_id = $2`,
		teamID, userID,
	)
	if err != nil {
		return fmt.Errorf("remove team member: %w", err)
	}
	return nil
}

func (s *PostgresTeamStore) ListMembers(ctx context.Context, teamID int64) ([]*TeamMember, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT tm.id, tm.team_id, tm.user_id, tm.role, u.email, COALESCE(u.name, '')
		 FROM team_members tm
		 JOIN users u ON u.id = tm.user_id
		 WHERE tm.team_id = $1
		 ORDER BY tm.role ASC, u.email ASC`, teamID)
	if err != nil {
		return nil, fmt.Errorf("list team members: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var members []*TeamMember
	for rows.Next() {
		m := &TeamMember{}
		if err := rows.Scan(&m.ID, &m.TeamID, &m.UserID, &m.Role, &m.Email, &m.Name); err != nil {
			return nil, fmt.Errorf("scan team member: %w", err)
		}
		members = append(members, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate team members: %w", err)
	}
	if members == nil {
		members = []*TeamMember{}
	}
	return members, nil
}

func (s *PostgresTeamStore) GetMembership(ctx context.Context, teamID, userID int64) (*TeamMember, error) {
	m := &TeamMember{}
	err := s.db.QueryRowContext(ctx,
		`SELECT tm.id, tm.team_id, tm.user_id, tm.role, u.email, COALESCE(u.name, '')
		 FROM team_members tm
		 JOIN users u ON u.id = tm.user_id
		 WHERE tm.team_id = $1 AND tm.user_id = $2`,
		teamID, userID,
	).Scan(&m.ID, &m.TeamID, &m.UserID, &m.Role, &m.Email, &m.Name)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get membership: %w", err)
	}
	return m, nil
}

func (s *PostgresTeamStore) IsTeamMember(ctx context.Context, teamID, userID int64) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)`,
		teamID, userID,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check team membership: %w", err)
	}
	return exists, nil
}

func (s *PostgresTeamStore) GetUserTeamIDs(ctx context.Context, userID int64) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT team_id FROM team_members WHERE user_id = $1`, userID)
	if err != nil {
		return nil, fmt.Errorf("get user team IDs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan team ID: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate team IDs: %w", err)
	}
	if ids == nil {
		ids = []int64{}
	}
	return ids, nil
}

// ListUsers returns all users as UserInfo (for member picker UI).
func (s *PostgresTeamStore) ListUsers(ctx context.Context) ([]*UserInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, email, COALESCE(name, '') FROM users ORDER BY email ASC`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []*UserInfo
	for rows.Next() {
		u := &UserInfo{}
		if err := rows.Scan(&u.ID, &u.Email, &u.Name); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	if users == nil {
		users = []*UserInfo{}
	}
	return users, nil
}
