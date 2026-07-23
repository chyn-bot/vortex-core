-- Identity federation (OIDC first; SAML/LDAP share the tables).
--
-- Vortex identity was local-only (argon2id + TOTP). These tables add
-- per-tenant federated login: an `identity_provider` row holds a tenant's IdP
-- configuration, and `user_federated_identity` maps an IdP subject to a local
-- user so an SSO login resolves to exactly one account (never by raw email,
-- which would be spoofable). Both are CORE tables — federation is a platform
-- concern every regulated vertical needs — living in one tenant DB each,
-- exactly like `users`/`system_settings`.

CREATE TABLE IF NOT EXISTS identity_provider (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id      UUID REFERENCES companies(id),
    -- 'oidc' today; 'saml' / 'ldap' reserved for the same table shape.
    provider_type   VARCHAR(20)  NOT NULL DEFAULT 'oidc',
    enabled         BOOLEAN      NOT NULL DEFAULT true,
    -- Shown on the login page button ("Sign in with {display_name}").
    display_name    VARCHAR(120) NOT NULL,
    -- OIDC issuer URL; discovery doc is issuer + /.well-known/openid-configuration.
    issuer          TEXT         NOT NULL,
    client_id       TEXT         NOT NULL,
    -- Client secret sealed with AES-256-GCM via the key provider (BYTEA blob),
    -- never stored in plaintext — same treatment as SMTP passwords.
    client_secret_enc BYTEA,
    -- Where the IdP redirects back; must match the app's /auth/oidc/callback.
    redirect_uri    TEXT         NOT NULL,
    -- Space-separated scopes; 'openid' is always requested.
    scopes          VARCHAR(255) NOT NULL DEFAULT 'openid email profile',
    -- Which ID-token claim carries the stable subject (default 'sub') and the
    -- email/username, so mapping is configurable per IdP.
    claim_mapping   JSONB        NOT NULL DEFAULT '{"subject":"sub","email":"email","name":"name"}'::jsonb,
    -- On first login, auto-create + link a local user (JIT) or require a
    -- pre-existing linked account.
    jit_provisioning BOOLEAN     NOT NULL DEFAULT true,
    -- Role granted to JIT-provisioned users (by role name).
    default_role    VARCHAR(100),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- One tenant, one enabled provider per type is the common case; not enforced
-- so staging/prod IdPs can coexist disabled.
CREATE INDEX IF NOT EXISTS idx_identity_provider_enabled
    ON identity_provider (enabled) WHERE enabled;

CREATE TABLE IF NOT EXISTS user_federated_identity (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id   UUID NOT NULL REFERENCES identity_provider(id) ON DELETE CASCADE,
    -- The IdP's stable subject identifier (OIDC `sub` / SAML NameID). This,
    -- not email, is the trust anchor for matching a login to a local user.
    subject       VARCHAR(255) NOT NULL,
    email         VARCHAR(255),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    -- An IdP subject maps to exactly one local user within a provider.
    UNIQUE (provider_id, subject)
);

CREATE INDEX IF NOT EXISTS idx_user_federated_identity_user
    ON user_federated_identity (user_id);

-- Least-privilege runtime role (migrations 114/166) needs DML on the new tables.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON identity_provider TO vortex_runtime';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON user_federated_identity TO vortex_runtime';
    END IF;
END$$;
