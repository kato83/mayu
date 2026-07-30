-- Add CVSS score columns to ghsa_entries for structured severity data.
-- GitHub API may provide cvss_severities.cvss_v3 and/or cvss_severities.cvss_v4.
ALTER TABLE ghsa_entries ADD COLUMN cvss_v3_vector TEXT;
ALTER TABLE ghsa_entries ADD COLUMN cvss_v3_score FLOAT8;
ALTER TABLE ghsa_entries ADD COLUMN cvss_v4_vector TEXT;
ALTER TABLE ghsa_entries ADD COLUMN cvss_v4_score FLOAT8;
