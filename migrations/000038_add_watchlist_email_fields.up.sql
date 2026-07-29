ALTER TABLE watchlists ADD COLUMN notify_email BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE watchlists ADD COLUMN notify_email_to TEXT;
