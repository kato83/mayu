package watchlist

import "context"

// WatchlistStore defines the interface for watchlist persistence operations.
type WatchlistStore interface {
	// CreateWatchlist creates a new watchlist entry and returns the generated ID.
	CreateWatchlist(ctx context.Context, w *Watchlist) (int64, error)

	// GetWatchlist retrieves a watchlist by ID, scoped to a user.
	// Returns nil, nil if not found.
	GetWatchlist(ctx context.Context, id int64, userID int64) (*Watchlist, error)

	// ListWatchlists returns all watchlists for a user, ordered by creation time.
	ListWatchlists(ctx context.Context, userID int64) ([]*Watchlist, error)

	// UpdateWatchlist updates an existing watchlist entry.
	UpdateWatchlist(ctx context.Context, w *Watchlist) error

	// DeleteWatchlist removes a watchlist by ID, scoped to a user.
	DeleteWatchlist(ctx context.Context, id int64, userID int64) error

	// ListMatchesByWatchlist returns matches for a specific watchlist with pagination.
	ListMatchesByWatchlist(ctx context.Context, watchlistID int64, limit int, offset int) ([]*WatchlistMatch, error)

	// ListMatchesByUser returns all matches across a user's watchlists with pagination.
	ListMatchesByUser(ctx context.Context, userID int64, limit int, offset int) ([]*WatchlistMatch, error)

	// CountMatchesByUser returns the total number of matches across a user's watchlists.
	CountMatchesByUser(ctx context.Context, userID int64) (int64, error)

	// RecordMatches records one or more watchlist matches in a batch.
	// Conflicts on (watchlist_id, vulnerability_id) are ignored.
	RecordMatches(ctx context.Context, matches []WatchlistMatch) error

	// GetActiveWatchlists returns all enabled watchlists across all users.
	GetActiveWatchlists(ctx context.Context) ([]*Watchlist, error)
}
