package model

import "time"

// NVDSource represents a single source identifier entry from the NVD Source API.
// One organization may have multiple source identifiers (UUIDs and/or email addresses),
// so each identifier gets its own row with the same name.
type NVDSource struct {
	// Name is the organization name (e.g., "kernel.org", "MITRE Corporation").
	Name string

	// ContactEmail is the organization's contact email (may be empty).
	ContactEmail string

	// SourceIdentifier is the unique identifier for this source (UUID or email).
	// This is the primary key.
	SourceIdentifier string

	// AcceptanceLevel is the NVD acceptance level description (e.g., "Contributor").
	AcceptanceLevel string

	// LastModified is when this source entry was last modified in NVD.
	LastModified *time.Time

	// CreatedAt is when this source was created in NVD.
	CreatedAt *time.Time
}
