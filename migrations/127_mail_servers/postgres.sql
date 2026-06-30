-- Core outbound-email configuration, scoped per tenant DB. One or more SMTP
-- servers can be configured (Gmail, Office 365, generic); one is the default.
-- Passwords are stored encrypted (AES-256-GCM via vortex_security::crypto) in
-- password_enc as nonce||ciphertext||tag — never in plaintext. Any module can
-- send through the default server via vortex_framework::mail.
CREATE TABLE IF NOT EXISTS mail_servers (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(100) NOT NULL,
    provider      VARCHAR(30)  NOT NULL DEFAULT 'generic',   -- generic|gmail|office365|...
    host          VARCHAR(255) NOT NULL,
    port          INTEGER      NOT NULL DEFAULT 587,
    security      VARCHAR(10)  NOT NULL DEFAULT 'starttls',  -- starttls|tls|none
    username      VARCHAR(255),
    password_enc  BYTEA,                                     -- AES-256-GCM blob
    from_address  VARCHAR(255) NOT NULL,
    from_name     VARCHAR(100),
    is_default    BOOLEAN      NOT NULL DEFAULT false,
    active        BOOLEAN      NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- At most one default server per tenant.
CREATE UNIQUE INDEX IF NOT EXISTS uq_mail_servers_default
    ON mail_servers(is_default) WHERE is_default;

-- Append-only record of send attempts (operational visibility, not WORM).
CREATE TABLE IF NOT EXISTS mail_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id   UUID REFERENCES mail_servers(id) ON DELETE SET NULL,
    to_address  VARCHAR(255) NOT NULL,
    subject     VARCHAR(500),
    status      VARCHAR(20)  NOT NULL DEFAULT 'sent',        -- sent|failed
    error       TEXT,
    context     VARCHAR(100),                                -- 'test'|'approval'|...
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mail_log_created ON mail_log(created_at DESC);
