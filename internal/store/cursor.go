package store

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// Cursor represents a pagination cursor encoding a sort key timestamp and id for stable keyset ordering.
type Cursor struct {
	// SortKey is the sort column name ("published" or "modified").
	SortKey string

	// SortDirection is the sort direction ("asc" or "desc").
	// Empty defaults to "desc" for backward compatibility.
	SortDirection string

	// Timestamp is the sort key timestamp of the last seen item.
	// Nil means the item has a NULL value for the sort key.
	Timestamp *time.Time

	// ID is the vulnerability ID of the last seen item.
	ID string
}

// EncodeCursor creates an opaque cursor string from a sort key, timestamp, and id.
// Format: base64("v2|<sort_key>|<timestamp_rfc3339_nano>|<id>")
// Also supports legacy format for backward compatibility.
func EncodeCursor(ts *time.Time, id string) string {
	return EncodeCursorWithSort("modified", "desc", ts, id)
}

// EncodeCursorWithSort creates an opaque cursor string with explicit sort key and direction.
// Format: base64("v3|<sort_key>|<sort_direction>|<timestamp_rfc3339_nano>|<id>")
func EncodeCursorWithSort(sortKey string, sortDirection string, ts *time.Time, id string) string {
	var tsStr string
	if ts != nil {
		tsStr = ts.UTC().Format(time.RFC3339Nano)
	}
	if sortDirection == "" {
		sortDirection = "desc"
	}
	raw := fmt.Sprintf("v3|%s|%s|%s|%s", sortKey, sortDirection, tsStr, id)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeCursor parses an opaque cursor string back into its components.
// Supports v1 (legacy, assumes published), v2 (sort key without direction), and v3 (sort key + direction) formats.
func DecodeCursor(cursor string) (*Cursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor encoding: %w", err)
	}

	str := string(data)

	// v3 format: "v3|<sort_key>|<sort_direction>|<timestamp>|<id>"
	if strings.HasPrefix(str, "v3|") {
		parts := strings.SplitN(str, "|", 5)
		if len(parts) != 5 {
			return nil, fmt.Errorf("invalid cursor format")
		}

		c := &Cursor{
			SortKey:       parts[1],
			SortDirection: parts[2],
			ID:            parts[4],
		}

		if parts[3] != "" {
			t, err := time.Parse(time.RFC3339Nano, parts[3])
			if err != nil {
				return nil, fmt.Errorf("invalid cursor timestamp: %w", err)
			}
			c.Timestamp = &t
		}

		if c.ID == "" {
			return nil, fmt.Errorf("invalid cursor: empty id")
		}
		return c, nil
	}

	// v2 format: "v2|<sort_key>|<timestamp>|<id>" — no direction, defaults to desc
	if strings.HasPrefix(str, "v2|") {
		parts := strings.SplitN(str, "|", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid cursor format")
		}

		c := &Cursor{
			SortKey:       parts[1],
			SortDirection: "desc",
			ID:            parts[3],
		}

		if parts[2] != "" {
			t, err := time.Parse(time.RFC3339Nano, parts[2])
			if err != nil {
				return nil, fmt.Errorf("invalid cursor timestamp: %w", err)
			}
			c.Timestamp = &t
		}

		if c.ID == "" {
			return nil, fmt.Errorf("invalid cursor: empty id")
		}
		return c, nil
	}

	// v1 format (legacy): "v1|<timestamp>|<id>" — assumes published sort key, desc direction
	parts := strings.SplitN(str, "|", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid cursor format")
	}

	if parts[0] != "v1" {
		return nil, fmt.Errorf("unsupported cursor version: %s", parts[0])
	}

	c := &Cursor{
		SortKey:       "published",
		SortDirection: "desc",
		ID:            parts[2],
	}

	if parts[1] != "" {
		t, err := time.Parse(time.RFC3339Nano, parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid cursor timestamp: %w", err)
		}
		c.Timestamp = &t
	}

	if c.ID == "" {
		return nil, fmt.Errorf("invalid cursor: empty id")
	}

	return c, nil
}
