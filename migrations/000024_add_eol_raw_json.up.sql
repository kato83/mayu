-- Add raw_json column to eol_products for data reversibility
ALTER TABLE eol_products ADD COLUMN raw_json JSONB;
