-- Portal invitations.
--
-- When a staff user invites a partner to the portal, the portal `users` row is
-- created inactive (password_hash is an unusable placeholder) and a one-time
-- invite token is issued here. The invitee follows the emailed link, sets a
-- password, and the account is activated — the token is single-use and expires.
--
-- Only the SHA-256 hash of the token is stored; the raw token lives only in the
-- emailed link (same discipline as sessions / api tokens).

CREATE TABLE IF NOT EXISTS portal_invite (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(64) NOT NULL UNIQUE,
    email       VARCHAR(255),
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_by  UUID        REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Look up a partner's outstanding invite quickly (for resend / status).
CREATE INDEX IF NOT EXISTS idx_portal_invite_user ON portal_invite(user_id);
