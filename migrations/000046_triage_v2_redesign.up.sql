-- Triage Engine v2: Add score_weight and act_floor to triage_profiles
ALTER TABLE triage_profiles
    ADD COLUMN score_weight DOUBLE PRECISION NOT NULL DEFAULT 0.60,
    ADD COLUMN act_floor VARCHAR(20) NOT NULL DEFAULT 'Critical';

ALTER TABLE triage_profiles
    ADD CONSTRAINT chk_triage_profiles_score_weight CHECK (score_weight >= 0.0 AND score_weight <= 1.0);

ALTER TABLE triage_profiles
    ADD CONSTRAINT chk_triage_profiles_act_floor CHECK (act_floor IN ('Critical', 'High', 'Medium', 'Low'));

-- Create project_environment_profiles (replaces triage_server_profile_bindings)
CREATE TABLE project_environment_profiles (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id BIGINT NOT NULL REFERENCES sbom_projects(id) ON DELETE CASCADE,
    environment VARCHAR(100) NOT NULL,
    profile_name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, environment)
);

CREATE INDEX idx_pep_project ON project_environment_profiles(project_id);
CREATE INDEX idx_pep_environment ON project_environment_profiles(environment);

-- Migrate existing bindings to new table
INSERT INTO project_environment_profiles (project_id, environment, profile_name, description, created_at, updated_at)
SELECT project_id, COALESCE(environment, server_label), profile_name, description, created_at, updated_at
FROM triage_server_profile_bindings
ON CONFLICT (project_id, environment) DO NOTHING;

-- Drop old table
DROP TABLE IF EXISTS triage_server_profile_bindings;
DROP INDEX IF EXISTS idx_triage_spb_project;
DROP INDEX IF EXISTS idx_triage_spb_server;

-- Add default_profile to sbom_projects
ALTER TABLE sbom_projects ADD COLUMN default_profile VARCHAR(255);
