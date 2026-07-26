-- endoflife.date integration tables
-- Stores product lifecycle information from endoflife.date API v1.

-- eol_products: Stores product metadata from endoflife.date
CREATE TABLE IF NOT EXISTS eol_products (
    name TEXT PRIMARY KEY,                -- endoflife.date product name (e.g., "nodejs", "python")
    label TEXT NOT NULL,                  -- Human-readable label (e.g., "Node.js", "Python")
    category TEXT,                        -- Product category (e.g., "framework", "lang", "os")
    tags TEXT[],                          -- Product tags
    version_command TEXT,                 -- Command to check version (e.g., "node --version")
    last_modified_at TIMESTAMPTZ,         -- Last modification time from API
    last_synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- eol_releases: Stores release/cycle EOL information
CREATE TABLE IF NOT EXISTS eol_releases (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    product_name TEXT NOT NULL REFERENCES eol_products(name) ON DELETE CASCADE,
    release_name TEXT NOT NULL,           -- Release cycle name (e.g., "22", "3.12", "24.04")
    label TEXT,                           -- Human-readable label (e.g., "22 (LTS)")
    codename TEXT,                        -- Release codename (e.g., "Noble Numbat")
    release_date DATE,                    -- Release date
    is_lts BOOLEAN,                       -- Whether this is an LTS release
    lts_from DATE,                        -- Date when LTS status begins
    is_eoas BOOLEAN,                      -- Whether active support has ended
    eoas_from DATE,                       -- End of active support date
    is_eol BOOLEAN,                       -- Whether the release has reached end of life
    eol_from DATE,                        -- End of life date
    is_eoes BOOLEAN,                      -- Whether extended support has ended
    eoes_from DATE,                       -- End of extended support date
    is_maintained BOOLEAN,                -- Whether currently maintained
    latest_version TEXT,                  -- Latest version in this cycle
    latest_version_date DATE,             -- Date of latest version
    latest_version_link TEXT,             -- URL for latest version changelog
    UNIQUE(product_name, release_name)
);

-- eol_identifiers: Maps purl/cpe identifiers to endoflife.date products
CREATE TABLE IF NOT EXISTS eol_identifiers (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    product_name TEXT NOT NULL REFERENCES eol_products(name) ON DELETE CASCADE,
    identifier_type TEXT NOT NULL,        -- "purl" or "cpe"
    identifier TEXT NOT NULL,             -- e.g., "pkg:npm/node" or "cpe:2.3:a:nodejs:node.js"
    UNIQUE(identifier_type, identifier)
);

-- Indexes for common lookups
CREATE INDEX idx_eol_releases_product ON eol_releases(product_name);
CREATE INDEX idx_eol_releases_eol ON eol_releases(is_eol, product_name);
CREATE INDEX idx_eol_identifiers_product ON eol_identifiers(product_name);
CREATE INDEX idx_eol_identifiers_type_id ON eol_identifiers(identifier_type, identifier);
