ALTER TABLE webhooks ADD COLUMN user_id BIGINT REFERENCES users(id) ON DELETE CASCADE;

CREATE INDEX idx_webhooks_user_id ON webhooks (user_id);
