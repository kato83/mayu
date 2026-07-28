UPDATE vulnerabilities SET modified = COALESCE(published, NOW()) WHERE modified IS NULL;
ALTER TABLE vulnerabilities ALTER COLUMN modified SET NOT NULL;
