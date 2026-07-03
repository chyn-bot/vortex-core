-- Mobile / programmatic auth tokens — access + refresh pairs issued by a
-- username+password login for first-party apps (e.g. the SESB field-technician
-- app). Distinct from `api_tokens` (admin-issued, long-lived service PATs) and
-- from `sessions` (browser cookie transport):
--
--   * a login mints a short-lived ACCESS token (sent as `Authorization:
--     Bearer` on every API call) and a long-lived REFRESH token (used only to
--     mint the next access token when connectivity returns — the property the
--     offline field flow needs);
--   * both rows share a `family_id` — one family == one device login;
--   * refresh tokens ROTATE: each refresh is single-use (`consumed_at`), and
--     presenting an already-consumed refresh is treated as theft — the whole
--     family is revoked (reuse detection);
--   * everything is opaque + DB-backed (only the SHA-256 hash is stored, the
--     `sessions`/`api_tokens` scheme), so a lost device is killed with one
--     UPDATE — no JWT blocklist. This is the zero-trust revocation property.
--
-- Per-tenant table: tokens reference `users`, which are per-database, so a
-- request must name its database (header `X-Vortex-Database`, defaulting to
-- the server's default DB) exactly as the login cookie and `api_tokens` do.

CREATE TABLE mobile_auth_token (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- One family == one device login. Rotation issues new rows in the same
    -- family; logout / device-revoke / reuse-detection revoke the family.
    family_id     UUID NOT NULL,
    -- 'access' (short-lived, presented on every call) or
    -- 'refresh' (long-lived, single-use, mints the next pair).
    kind          VARCHAR(8)  NOT NULL,
    -- SHA-256 hex of the presented secret. Unique so a duplicate/collision is
    -- rejected at the DB layer. The raw secret is returned once, never stored.
    token_hash    VARCHAR(64) NOT NULL UNIQUE,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Opaque client-generated device id + a human label for the "your
    -- devices" / lost-device revocation UI.
    device_id     VARCHAR(128),
    device_name   VARCHAR(255),
    -- Coarse capability grants carried onto the resolved user. Empty => the
    -- token can read; 'write' permits mutation. Policy (Cedar) still applies.
    scopes        TEXT[] NOT NULL DEFAULT '{}',
    -- Rotation lineage: an access row points at its issuing refresh; a rotated
    -- refresh points at the refresh it replaced. Purely for audit/forensics.
    parent_id     UUID REFERENCES mobile_auth_token(id) ON DELETE SET NULL,
    -- Set when a refresh token is spent (rotated). A second presentation of a
    -- row with consumed_at set == reuse == revoke the family.
    consumed_at   TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked       BOOLEAN NOT NULL DEFAULT false,
    revoked_at    TIMESTAMPTZ,
    revoked_reason VARCHAR(255),
    ip_address    INET,
    user_agent    TEXT,
    last_used_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_mobile_auth_kind CHECK (kind IN ('access', 'refresh'))
);

-- Hot path: resolve a presented secret. Partial index keeps only live tokens
-- in the lookup set.
CREATE INDEX idx_mobile_auth_hash   ON mobile_auth_token(token_hash) WHERE NOT revoked;
CREATE INDEX idx_mobile_auth_family ON mobile_auth_token(family_id);
CREATE INDEX idx_mobile_auth_user   ON mobile_auth_token(user_id);
-- "Your devices" listing: live refresh tokens per user/device.
CREATE INDEX idx_mobile_auth_device ON mobile_auth_token(user_id, device_id)
    WHERE kind = 'refresh' AND NOT revoked;

COMMENT ON TABLE mobile_auth_token IS
    'Access+refresh token pairs for first-party programmatic clients (mobile field app). Opaque, DB-backed, per-family rotation with reuse detection. Distinct from api_tokens (service PATs) and sessions (browser cookies).';
