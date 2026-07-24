-- Add text_pattern_ops index on product_identifiers.ecosystem for prefix LIKE queries.
-- The existing idx_pi_ecosystem_name uses default btree ops which don't support
-- LIKE with non-C locale (en_US.utf8). This index enables prefix matching
-- for versioned ecosystems (e.g., 'Ubuntu' matching 'Ubuntu:22.04:LTS').
CREATE INDEX idx_pi_ecosystem_pattern
    ON product_identifiers (ecosystem text_pattern_ops)
    WHERE ecosystem IS NOT NULL;
