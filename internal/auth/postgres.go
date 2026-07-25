package auth

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// PostgresAuthStore implements UserStore, APIKeyStore, and SessionStore
// using database/sql with the pgx stdlib driver.
type PostgresAuthStore struct {
	db *sql.DB
}

// NewPostgresAuthStore creates a new PostgresAuthStore with the given database connection.
func NewPostgresAuthStore(db *sql.DB) *PostgresAuthStore {
	return &PostgresAuthStore{db: db}
}

// --- UserStore implementation ---

// CreateUser creates a new user with the given attributes.
func (s *PostgresAuthStore) CreateUser(ctx context.Context, email, name, role, passwordHash string) (*User, error) {
	var user User
	var pwHash sql.NullString
	if passwordHash != "" {
		pwHash = sql.NullString{String: passwordHash, Valid: true}
	}

	err := s.db.QueryRowContext(ctx, `
		INSERT INTO users (email, name, role, password_hash)
		VALUES ($1, $2, $3, $4)
		RETURNING id, email, name, role`,
		email, name, role, pwHash,
	).Scan(&user.ID, &user.Email, &user.Name, &user.Role)
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}
	return &user, nil
}

// GetUserByEmail retrieves a user by email address.
func (s *PostgresAuthStore) GetUserByEmail(ctx context.Context, email string) (*UserWithPassword, error) {
	var u UserWithPassword
	var name sql.NullString
	var pwHash sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT id, email, name, role, password_hash
		FROM users
		WHERE email = $1`,
		email,
	).Scan(&u.ID, &u.Email, &name, &u.Role, &pwHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	if name.Valid {
		u.Name = name.String
	}
	if pwHash.Valid {
		u.PasswordHash = pwHash.String
	}
	return &u, nil
}

// GetUserByID retrieves a user by ID.
func (s *PostgresAuthStore) GetUserByID(ctx context.Context, id int64) (*User, error) {
	var user User
	var name sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT id, email, name, role
		FROM users
		WHERE id = $1`,
		id,
	).Scan(&user.ID, &user.Email, &name, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get user by id %d: %w", id, err)
	}
	if name.Valid {
		user.Name = name.String
	}
	return &user, nil
}

// ListUsers returns all users ordered by ID.
func (s *PostgresAuthStore) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, email, name, role
		FROM users
		ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []*User
	for rows.Next() {
		var user User
		var name sql.NullString
		if err := rows.Scan(&user.ID, &user.Email, &name, &user.Role); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		if name.Valid {
			user.Name = name.String
		}
		users = append(users, &user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	return users, nil
}

// UpdateUserOIDCSubject sets the OIDC subject identifier for a user.
func (s *PostgresAuthStore) UpdateUserOIDCSubject(ctx context.Context, userID int64, subject string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET oidc_subject = $2, updated_at = NOW()
		WHERE id = $1`,
		userID, subject,
	)
	if err != nil {
		return fmt.Errorf("update user oidc_subject %d: %w", userID, err)
	}
	return nil
}

// GetUserByOIDCSubject retrieves a user by OIDC subject identifier.
func (s *PostgresAuthStore) GetUserByOIDCSubject(ctx context.Context, subject string) (*User, error) {
	var user User
	var name sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT id, email, name, role
		FROM users
		WHERE oidc_subject = $1`,
		subject,
	).Scan(&user.ID, &user.Email, &name, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get user by oidc_subject: %w", err)
	}
	if name.Valid {
		user.Name = name.String
	}
	return &user, nil
}

// --- APIKeyStore implementation ---

// CreateAPIKey creates a new API key record.
func (s *PostgresAuthStore) CreateAPIKey(ctx context.Context, userID int64, name string, keyHash string, keyPrefix string, expiresAt *time.Time) (*APIKey, error) {
	var key APIKey
	var expires sql.NullTime
	if expiresAt != nil {
		expires = sql.NullTime{Time: *expiresAt, Valid: true}
	}

	var keyName sql.NullString
	if name != "" {
		keyName = sql.NullString{String: name, Valid: true}
	}

	err := s.db.QueryRowContext(ctx, `
		INSERT INTO api_keys (user_id, name, key_hash, key_prefix, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, user_id, name, key_prefix, created_at, expires_at`,
		userID, keyName, keyHash, keyPrefix, expires,
	).Scan(&key.ID, &key.UserID, &keyName, &key.KeyPrefix, &key.CreatedAt, &expires)
	if err != nil {
		return nil, fmt.Errorf("insert api_key: %w", err)
	}
	if keyName.Valid {
		key.Name = keyName.String
	}
	if expires.Valid {
		key.ExpiresAt = &expires.Time
	}
	return &key, nil
}

// ListAPIKeys returns all API keys for a user, ordered by creation time.
func (s *PostgresAuthStore) ListAPIKeys(ctx context.Context, userID int64) ([]*APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, name, key_prefix, created_at, expires_at
		FROM api_keys
		WHERE user_id = $1
		ORDER BY created_at`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list api_keys for user %d: %w", userID, err)
	}
	defer func() { _ = rows.Close() }()

	var keys []*APIKey
	for rows.Next() {
		var key APIKey
		var keyName sql.NullString
		var expires sql.NullTime
		if err := rows.Scan(&key.ID, &key.UserID, &keyName, &key.KeyPrefix, &key.CreatedAt, &expires); err != nil {
			return nil, fmt.Errorf("scan api_key: %w", err)
		}
		if keyName.Valid {
			key.Name = keyName.String
		}
		if expires.Valid {
			key.ExpiresAt = &expires.Time
		}
		keys = append(keys, &key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate api_keys: %w", err)
	}
	return keys, nil
}

// DeleteAPIKey removes an API key by ID, scoped to a user.
func (s *PostgresAuthStore) DeleteAPIKey(ctx context.Context, id int64, userID int64) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM api_keys
		WHERE id = $1 AND user_id = $2`,
		id, userID,
	)
	if err != nil {
		return fmt.Errorf("delete api_key %d: %w", id, err)
	}
	return nil
}

// GetAPIKeyByPrefix retrieves all API key records matching the given prefix.
func (s *PostgresAuthStore) GetAPIKeyByPrefix(ctx context.Context, prefix string) ([]*APIKeyWithHash, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT ak.id, ak.user_id, ak.name, ak.key_prefix, ak.key_hash,
		       ak.created_at, ak.expires_at
		FROM api_keys ak
		WHERE ak.key_prefix = $1`,
		prefix,
	)
	if err != nil {
		return nil, fmt.Errorf("get api_keys by prefix: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var keys []*APIKeyWithHash
	for rows.Next() {
		var key APIKeyWithHash
		var keyName sql.NullString
		var expires sql.NullTime
		if err := rows.Scan(&key.ID, &key.UserID, &keyName, &key.KeyPrefix, &key.KeyHash,
			&key.CreatedAt, &expires); err != nil {
			return nil, fmt.Errorf("scan api_key_with_hash: %w", err)
		}
		if keyName.Valid {
			key.Name = keyName.String
		}
		if expires.Valid {
			key.ExpiresAt = &expires.Time
		}
		keys = append(keys, &key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate api_keys by prefix: %w", err)
	}
	return keys, nil
}

// --- SessionStore implementation ---

// CreateSession stores a new session record.
func (s *PostgresAuthStore) CreateSession(ctx context.Context, id string, userID int64, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, expires_at)
		VALUES ($1, $2, $3)`,
		id, userID, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

// GetSession retrieves a session by ID.
func (s *PostgresAuthStore) GetSession(ctx context.Context, id string) (*Session, error) {
	var sess Session
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, created_at, expires_at
		FROM sessions
		WHERE id = $1`,
		id,
	).Scan(&sess.ID, &sess.UserID, &sess.CreatedAt, &sess.ExpiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get session %s: %w", id, err)
	}
	return &sess, nil
}

// DeleteSession removes a session by ID.
func (s *PostgresAuthStore) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM sessions WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("delete session %s: %w", id, err)
	}
	return nil
}

// DeleteExpiredSessions removes all sessions that have expired.
func (s *PostgresAuthStore) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM sessions WHERE expires_at < NOW()`)
	if err != nil {
		return fmt.Errorf("delete expired sessions: %w", err)
	}
	return nil
}
