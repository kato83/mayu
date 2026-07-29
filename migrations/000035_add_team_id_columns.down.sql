DROP INDEX IF EXISTS idx_webhooks_team_id;
ALTER TABLE webhooks DROP COLUMN IF EXISTS team_id;

DROP INDEX IF EXISTS idx_watchlists_team_id;
ALTER TABLE watchlists DROP COLUMN IF EXISTS team_id;

DROP INDEX IF EXISTS idx_sbom_projects_team_id;
ALTER TABLE sbom_projects DROP COLUMN IF EXISTS team_id;
