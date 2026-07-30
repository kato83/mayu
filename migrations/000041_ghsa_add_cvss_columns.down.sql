ALTER TABLE ghsa_entries DROP COLUMN IF EXISTS cvss_v4_score;
ALTER TABLE ghsa_entries DROP COLUMN IF EXISTS cvss_v4_vector;
ALTER TABLE ghsa_entries DROP COLUMN IF EXISTS cvss_v3_score;
ALTER TABLE ghsa_entries DROP COLUMN IF EXISTS cvss_v3_vector;
