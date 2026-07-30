-- Add source_ecosystem column to osv_entries.
-- Records the GCS ecosystem folder name (e.g., "Go", "npm", "GIT", "NVD", "Debian")
-- used during ingest, enabling identification of the data origin.
ALTER TABLE osv_entries ADD COLUMN source_ecosystem TEXT;

CREATE INDEX idx_osv_entries_source_ecosystem ON osv_entries (source_ecosystem);
