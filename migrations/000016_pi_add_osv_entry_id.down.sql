-- Revert: remove osv_entry_id column from product_identifiers.

DROP INDEX IF EXISTS idx_pi_osv_entry_id;
ALTER TABLE product_identifiers DROP COLUMN IF EXISTS osv_entry_id;
