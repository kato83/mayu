-- Custom triage profiles: user-defined profiles persisted in the database.
-- Built-in profiles (default, internet-facing, internal-only, air-gapped) are NOT stored here;
-- they are defined in application code and cannot be deleted.
CREATE TABLE triage_profiles (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    base VARCHAR(255),
    weights JSONB NOT NULL,
    thresholds JSONB NOT NULL,
    ssvc_mapping JSONB,
    created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_triage_profiles_created_by ON triage_profiles(created_by);
