package store

import (
	"testing"
	"time"
)

func TestEncodeDecode_WithPublished(t *testing.T) {
	published := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	id := "GO-2024-2687"

	encoded := EncodeCursor(&published, id)
	if encoded == "" {
		t.Fatal("expected non-empty cursor")
	}

	cursor, err := DecodeCursor(encoded)
	if err != nil {
		t.Fatalf("DecodeCursor failed: %v", err)
	}
	if cursor.ID != id {
		t.Errorf("expected ID %q, got %q", id, cursor.ID)
	}
	if cursor.Published == nil {
		t.Fatal("expected non-nil Published")
	}
	if !cursor.Published.Equal(published) {
		t.Errorf("expected Published %v, got %v", published, *cursor.Published)
	}
}

func TestEncodeDecode_NilPublished(t *testing.T) {
	id := "CVE-2024-1234"

	encoded := EncodeCursor(nil, id)
	if encoded == "" {
		t.Fatal("expected non-empty cursor")
	}

	cursor, err := DecodeCursor(encoded)
	if err != nil {
		t.Fatalf("DecodeCursor failed: %v", err)
	}
	if cursor.ID != id {
		t.Errorf("expected ID %q, got %q", id, cursor.ID)
	}
	if cursor.Published != nil {
		t.Errorf("expected nil Published, got %v", cursor.Published)
	}
}

func TestDecodeCursor_InvalidBase64(t *testing.T) {
	_, err := DecodeCursor("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestDecodeCursor_InvalidFormat(t *testing.T) {
	// Valid base64 but wrong format (no pipe separators)
	_, err := DecodeCursor("aGVsbG8") // "hello" in base64
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestDecodeCursor_UnsupportedVersion(t *testing.T) {
	// base64 of "v99|2024-06-01T00:00:00Z|GO-2024-2687"
	_, err := DecodeCursor("djk5fDIwMjQtMDYtMDFUMDA6MDA6MDBafEdPLTIwMjQtMjY4Nw")
	if err == nil {
		t.Error("expected error for unsupported version")
	}
}

func TestDecodeCursor_EmptyID(t *testing.T) {
	// base64 of "v1|2024-06-01T00:00:00Z|"
	_, err := DecodeCursor("djF8MjAyNC0wNi0wMVQwMDowMDowMFp8")
	if err == nil {
		t.Error("expected error for empty id")
	}
}

func TestDecodeCursor_InvalidTimestamp(t *testing.T) {
	// base64 of "v1|not-a-date|GO-2024-2687"
	_, err := DecodeCursor("djF8bm90LWEtZGF0ZXxHTy0yMDI0LTI2ODc")
	if err == nil {
		t.Error("expected error for invalid timestamp")
	}
}

func TestEncodeCursor_Deterministic(t *testing.T) {
	published := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	id := "TEST-001"

	c1 := EncodeCursor(&published, id)
	c2 := EncodeCursor(&published, id)
	if c1 != c2 {
		t.Errorf("expected deterministic encoding, got %q and %q", c1, c2)
	}
}

func TestEncodeCursor_DifferentTimezonesSameInstant(t *testing.T) {
	// Different timezone representations of the same instant should produce same cursor
	t1 := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2024, 6, 15, 19, 0, 0, 0, time.FixedZone("JST", 9*3600))

	c1 := EncodeCursor(&t1, "ID-1")
	c2 := EncodeCursor(&t2, "ID-1")
	if c1 != c2 {
		t.Errorf("expected same cursor for same instant in different timezones, got %q and %q", c1, c2)
	}
}
