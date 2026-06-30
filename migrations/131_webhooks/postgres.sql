-- Outbound webhooks — HMAC-signed event delivery to external systems.
--
-- An endpoint subscribes to one or more event types (empty = all). When a
-- matching event is emitted, the core enqueues a `webhook.deliver` job (so
-- delivery inherits the durable queue's retries, backoff, and dead-lettering).
-- The job handler signs the JSON body with the endpoint's secret
-- (HMAC-SHA256) and POSTs it; each attempt is recorded in webhook_deliveries.
--
-- Per-tenant tables (endpoints belong to a tenant's data), parallel to
-- mail_servers / api_tokens.

CREATE TABLE webhook_endpoints (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name          VARCHAR(255) NOT NULL,
    url           TEXT NOT NULL,
    -- HMAC signing secret, AES-256-GCM encrypted at rest (same scheme as
    -- mail_servers.password_enc; master key from VORTEX_SECRET_KEY).
    secret_enc    BYTEA,
    -- Subscribed event types. Empty array => receive every event.
    event_types   TEXT[] NOT NULL DEFAULT '{}',
    active        BOOLEAN NOT NULL DEFAULT true,
    -- Denormalised last-delivery summary for the admin list.
    last_delivery_at TIMESTAMPTZ,
    last_status   VARCHAR(20),
    created_by    UUID,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_endpoints_active ON webhook_endpoints(active);

-- Append-only delivery log: one row per attempt, for observability in the UI.
CREATE TABLE webhook_deliveries (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    endpoint_id   UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_type    VARCHAR(100) NOT NULL,
    status        VARCHAR(20) NOT NULL,          -- success | failed
    status_code   INTEGER,                       -- HTTP status, null on transport error
    duration_ms   INTEGER,
    error         TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_deliveries_endpoint ON webhook_deliveries(endpoint_id, created_at DESC);
