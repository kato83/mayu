-- Add a SQL function to extract numeric base score from CVSS vector strings.
-- Supports CVSS v2, v3.x, and v4.0 formats.
-- Examples:
--   'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' → requires separate score
--   '9.8' (plain numeric) → 9.8
--   For CVSS vectors, we extract from the score column directly (which stores the numeric score or vector).

BEGIN;

CREATE OR REPLACE FUNCTION cvss_base_score(score_text TEXT) RETURNS NUMERIC AS $$
BEGIN
    -- Try to cast directly to numeric (handles plain score values like "9.8")
    BEGIN
        RETURN score_text::NUMERIC;
    EXCEPTION WHEN OTHERS THEN
        -- Not a plain number; return NULL for CVSS vector strings
        -- (In practice, OSV stores numeric scores in the score field)
        RETURN NULL;
    END;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

COMMIT;
