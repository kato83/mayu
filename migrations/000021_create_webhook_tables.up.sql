CREATE TABLE webhooks (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    events TEXT[] NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'application/json',
    body_template TEXT NOT NULL,
    secret TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE webhook_delivery_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    webhook_id BIGINT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event TEXT NOT NULL,
    payload TEXT,
    response_status INT,
    response_body TEXT,
    error_message TEXT,
    attempt INT NOT NULL DEFAULT 1,
    delivered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    duration_ms INT
);

CREATE INDEX idx_webhook_delivery_logs_webhook_id ON webhook_delivery_logs (webhook_id);
CREATE INDEX idx_webhook_delivery_logs_delivered_at ON webhook_delivery_logs (delivered_at);
