-- Add team_id to sbom_projects (issue #65)
ALTER TABLE sbom_projects ADD COLUMN team_id BIGINT REFERENCES teams(id) ON DELETE SET NULL;
CREATE INDEX idx_sbom_projects_team_id ON sbom_projects(team_id);

-- Add team_id to watchlists (issue #66)
ALTER TABLE watchlists ADD COLUMN team_id BIGINT REFERENCES teams(id) ON DELETE SET NULL;
CREATE INDEX idx_watchlists_team_id ON watchlists(team_id);

-- Add team_id to webhooks (issue #67)
ALTER TABLE webhooks ADD COLUMN team_id BIGINT REFERENCES teams(id) ON DELETE SET NULL;
CREATE INDEX idx_webhooks_team_id ON webhooks(team_id);
