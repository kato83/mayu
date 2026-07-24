ALTER TABLE sync_state ADD COLUMN source_type TEXT NOT NULL DEFAULT '';

-- Backfill existing rows with appropriate source types
UPDATE sync_state SET source_type = 'osv' WHERE source NOT IN ('NVD-native', 'MITRE', 'EPSS', 'KEV');
UPDATE sync_state SET source_type = 'nvd' WHERE source = 'NVD-native';
UPDATE sync_state SET source_type = 'mitre' WHERE source = 'MITRE';
UPDATE sync_state SET source_type = 'epss' WHERE source = 'EPSS';
UPDATE sync_state SET source_type = 'kev' WHERE source = 'KEV';
