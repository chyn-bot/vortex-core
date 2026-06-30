-- API tokens — bearer credentials for the public REST API (/api/v1).
--
-- A token authenticates as its owning user: API requests inherit that
-- user's roles and therefore the same Cedar policy gates as the UI. The
-- raw secret is shown once at creation and never stored; only its
-- SHA-256 hash is persisted (same scheme as `sessions.token_hash`).
--
-- Per-tenant table: tokens reference `users`, which are per-database, so
-- an API request must name its database (header `X-Vortex-Database`,
-- defaulting to the server's default DB) just as the login cookie does.

CREATE TABLE api_tokens (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name         VARCHAR(255) NOT NULL,
    -- Display-only leading slice of the secret (e.g. 'vtx_a1b2c3d4') so
    -- operators can recognise a token in the UI without it being usable.
    token_prefix VARCHAR(20)  NOT NULL,
    -- SHA-256 hex of the full secret. Unique so a hash collision or a
    -- duplicate insert is rejected at the DB layer.
    token_hash   VARCHAR(64)  NOT NULL UNIQUE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Coarse capability grants. Empty array => read-only. 'write' permits
    -- create/update/delete. Policy still applies on top of every call.
    scopes       TEXT[] NOT NULL DEFAULT '{}',
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    revoked      BOOLEAN NOT NULL DEFAULT false,
    revoked_at   TIMESTAMPTZ,
    created_by   UUID,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Hot path: resolve a presented secret. Partial index keeps only live
-- tokens in the lookup set.
CREATE INDEX idx_api_tokens_hash ON api_tokens(token_hash) WHERE NOT revoked;
CREATE INDEX idx_api_tokens_user ON api_tokens(user_id);
