-- Portal users (external customer/vendor self-service).
--
-- A portal user is an ordinary `users` row with `is_portal = true` and a
-- `contact_id` bound to the partner (`contacts` row) it represents. Portal
-- logins are confined to the `/portal/*` surface: the internal auth middleware
-- rejects `is_portal` users, so they can never reach a back-office route.
-- Every portal document query scopes on `contact_id` derived from the session
-- (never a request parameter), so a portal user can only see their own
-- partner's data.
--
-- Internal staff keep `is_portal = false` and `contact_id = NULL` — the
-- discriminator didn't exist before, so all existing users are correctly
-- classified as internal by the defaults.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS is_portal  BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS contact_id UUID REFERENCES contacts(id) ON DELETE RESTRICT;

-- A portal user must be bound to a partner; an internal user must not be.
-- (RESTRICT on the FK keeps a partner with an active portal login from being
-- deleted out from under it.)
ALTER TABLE users
    ADD CONSTRAINT chk_users_portal_contact
    CHECK ( (is_portal = false AND contact_id IS NULL)
         OR (is_portal = true  AND contact_id IS NOT NULL) );

-- Fast "does this partner already have a portal login?" and portal-user lists.
CREATE INDEX IF NOT EXISTS idx_users_contact ON users(contact_id) WHERE contact_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_portal  ON users(is_portal)  WHERE is_portal = true;

-- Minimal system role for portal logins. It carries no back-office
-- permissions; the real access boundary is the /portal/* confinement plus the
-- session-derived contact scope, not this role's permission list.
INSERT INTO roles (id, company_id, name, description, permissions, is_system) VALUES
    ('00000000-0000-0000-0000-000000000005', NULL, 'Portal User',
     'External customer/vendor self-service access', '["portal.*"]', true)
ON CONFLICT (id) DO NOTHING;
