-- Approval-before-DDL for Vortex Blueprints (Phase 4b).
--
-- When a tenant turns on `require_approval`, a schema-changing Blueprint
-- operation (create / add_field / rename_field / remove_field / archive) is not
-- applied immediately. Instead the intended operation is captured — as its type
-- plus a serialized payload — in `blueprint_change_request` with status
-- 'pending'. An approver (who must not be the requester) reviews it and either
-- applies it (the real DDL runs then) or rejects it. This is "governed no-code":
-- production schema is never changed without an approved, audited plan.
--
-- Layout/metadata-only changes are NOT gated by approval — only the operations
-- that run DDL are.

CREATE TABLE IF NOT EXISTS blueprint_change_request (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    op            VARCHAR(32)  NOT NULL,            -- create|add_field|rename_field|remove_field|archive
    payload       JSONB        NOT NULL,            -- serialized BlueprintOp (the exact op to replay)
    model_name    VARCHAR(255),                     -- target model (NULL for a create until applied)
    target_label  VARCHAR(255) NOT NULL,            -- human summary for the inbox
    status        VARCHAR(16)  NOT NULL DEFAULT 'pending',  -- pending|approved|rejected
    requested_by  UUID NOT NULL REFERENCES users(id),
    requested_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    decided_by    UUID REFERENCES users(id),
    decided_at    TIMESTAMPTZ,
    reason        TEXT,
    CONSTRAINT chk_bcr_status CHECK (status IN ('pending', 'approved', 'rejected'))
);

CREATE INDEX IF NOT EXISTS idx_bcr_status ON blueprint_change_request (status, requested_at);

-- Single-row per-tenant governance switch. The boolean PK + CHECK pins it to
-- exactly one row (id = true), so reads never need a WHERE and writes upsert.
CREATE TABLE IF NOT EXISTS blueprint_governance (
    id               BOOLEAN PRIMARY KEY DEFAULT TRUE,
    require_approval BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT chk_bg_single_row CHECK (id)
);
INSERT INTO blueprint_governance (id, require_approval) VALUES (TRUE, FALSE)
ON CONFLICT (id) DO NOTHING;

-- Cedar is deny-by-default, so approving a change needs its own permit. Kept as
-- a separate rule from `admins_can_manage_blueprints` (146) so the approve
-- capability can later be granted to a distinct reviewer role without widening
-- the manage permit.
INSERT INTO policy_rules (name, description, policy_text, priority) VALUES
(
    'admins_can_approve_blueprints',
    'System administrators can approve or reject pending Blueprint schema changes.',
    $cedar$permit (
    principal in Role::"system_administrator",
    action == Action::"blueprint.approve",
    resource
);$cedar$,
    100
)
ON CONFLICT (name) DO NOTHING;
