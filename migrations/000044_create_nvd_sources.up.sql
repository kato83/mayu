CREATE TABLE nvd_sources (
    name TEXT NOT NULL,
    contact_email TEXT,
    source_identifier TEXT NOT NULL,
    acceptance_level TEXT,
    last_modified TIMESTAMPTZ,
    created_at TIMESTAMPTZ,
    PRIMARY KEY (source_identifier)
);

CREATE INDEX idx_nvd_sources_name ON nvd_sources(name);
