CREATE TABLE watchlists (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    match_type TEXT NOT NULL,
    ecosystem TEXT,
    package_name TEXT,
    purl_pattern TEXT,
    cpe_pattern TEXT,
    severity_min SMALLINT,
    epss_threshold FLOAT8,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE watchlist_matches (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    watchlist_id BIGINT NOT NULL REFERENCES watchlists(id) ON DELETE CASCADE,
    vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    matched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notified BOOLEAN NOT NULL DEFAULT false,
    notified_at TIMESTAMPTZ,
    UNIQUE (watchlist_id, vulnerability_id)
);

CREATE INDEX idx_watchlists_user_id ON watchlists (user_id);
CREATE INDEX idx_watchlists_enabled ON watchlists (enabled) WHERE enabled = true;
CREATE INDEX idx_watchlist_matches_watchlist_id ON watchlist_matches (watchlist_id);
CREATE INDEX idx_watchlist_matches_vulnerability_id ON watchlist_matches (vulnerability_id);
