DROP INDEX IF EXISTS idx_webhooks_user_id;

ALTER TABLE webhooks DROP COLUMN IF EXISTS user_id;
