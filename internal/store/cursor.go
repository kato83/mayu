package store

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// Cursor represents a pagination cursor encoding (published, id) for stable keyset ordering.
// Sort order: ORDER BY published DESC NULLS LAST, id DESC
type Cursor struct {
	// Published is the published timestamp of the last seen item.
	// Nil means the item has no published date (NULL in DB).
	Published *time.Time

	// ID is the vulnerability ID of the last seen item.
	ID string
}

// EncodeCursor creates an opaque cursor string from published time and id.
// Format: base64("v1|<published_rfc3339_nano>|<id>") or base64("v1||<id>") for null published.
func EncodeCursor(published *time.Time, id string) string {
	var pubStr string
	if published != nil {
		pubStr = published.UTC().Format(time.RFC3339Nano)
	}
	raw := fmt.Sprintf("v1|%s|%s", pubStr, id)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeCursor parses an opaque cursor string back into its components.
// Returns an error if the cursor is malformed.
func DecodeCursor(cursor string) (*Cursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor encoding: %w", err)
	}

	parts := strings.SplitN(string(data), "|", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid cursor format")
	}

	if parts[0] != "v1" {
		return nil, fmt.Errorf("unsupported cursor version: %s", parts[0])
	}

	c := &Cursor{
		ID: parts[2],
	}

	if parts[1] != "" {
		t, err := time.Parse(time.RFC3339Nano, parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid cursor timestamp: %w", err)
		}
		c.Published = &t
	}

	if c.ID == "" {
		return nil, fmt.Errorf("invalid cursor: empty id")
	}

	return c, nil
}
