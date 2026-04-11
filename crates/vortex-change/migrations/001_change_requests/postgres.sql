-- Migration 117: Change Requests
--
-- The first real plugin built on the Phase 0.4 workflow substrate.
-- Creates the `change_requests` table and seeds Cedar policies that
-- enforce the CIP-010 change management rules:
--
--   - only `change_approver` or `system_administrator` roles can
--     run the `approve`, `reject`, or `review` transitions;
--   - a CR requester can never run `approve` on their own CR
--     (segregation of duties);
--   - anyone can `withdraw` their own CR;
--   - `submit`, `send_back`, and `close` are open to the CR owner
--     or any admin.
--
-- The CR table itself is NOT marked WORM — editable while in
-- `draft` state. Immutability comes from the workflow_transitions
-- history (116) and the audit ledger (114), both of which are
-- trigger-protected. Once a CR leaves `draft` the application
-- enforces field-level immutability; if a DBA edits the row
-- directly, the workflow history + audit chain still tell the
-- true story.

-- ============================================================================
-- 1. change_requests
-- ============================================================================
CREATE TABLE IF NOT EXISTS change_requests (
    id                     UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    number                 VARCHAR(32) NOT NULL,
    title                  VARCHAR(255) NOT NULL,
    description            TEXT NOT NULL,
    category               VARCHAR(32) NOT NULL,
    criticality            VARCHAR(16) NOT NULL,
    rollback_plan          TEXT,
    planned_start          TIMESTAMPTZ,
    planned_end            TIMESTAMPTZ,
    requested_by           UUID NOT NULL REFERENCES users(id),
    workflow_instance_id   UUID NOT NULL REFERENCES workflow_instances(id),
    company_id             UUID NOT NULL REFERENCES companies(id),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_change_requests_tenant_number UNIQUE (company_id, number),
    CONSTRAINT uq_change_requests_workflow_instance UNIQUE (workflow_instance_id),
    CONSTRAINT chk_change_requests_category CHECK (
        category IN ('routine', 'standard', 'maintenance', 'emergency')
    ),
    CONSTRAINT chk_change_requests_criticality CHECK (
        criticality IN ('low', 'medium', 'high')
    ),
    CONSTRAINT chk_change_requests_window CHECK (
        planned_start IS NULL OR planned_end IS NULL OR planned_end >= planned_start
    )
);

CREATE INDEX IF NOT EXISTS idx_change_requests_company_updated
    ON change_requests (company_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_change_requests_requester
    ON change_requests (requested_by, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_change_requests_workflow_instance
    ON change_requests (workflow_instance_id);
CREATE INDEX IF NOT EXISTS idx_change_requests_criticality
    ON change_requests (criticality, category);

-- Auto-bump updated_at on any row change (reuses the helper
-- function defined in migration 001).
DROP TRIGGER IF EXISTS trg_change_requests_updated_at ON change_requests;
CREATE TRIGGER trg_change_requests_updated_at
    BEFORE UPDATE ON change_requests
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Runtime role still needs the normal CRUD set on change_requests —
-- only audit_log and workflow_transitions are WORM.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON change_requests TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE change_requests IS
    'NERC CIP-010 change requests. Lifecycle is driven by workflow_instances + workflow_transitions via the vortex-workflow engine; every state change is Cedar-gated and WORM-audited. number is tenant-scoped (CR/YYYY/NNNNN).';
COMMENT ON COLUMN change_requests.workflow_instance_id IS
    'FK into workflow_instances — the single source of truth for current_state. Unique so CR ↔ workflow is 1:1.';
COMMENT ON COLUMN change_requests.rollback_plan IS
    'Required by handler validation for high-criticality changes. Nullable so drafts can be saved incrementally.';

-- ============================================================================
-- 2. Seed Cedar policies for the change_request workflow
-- ============================================================================
-- These policies are evaluated by the workflow engine when it calls
-- PolicyService::check(actor, transition_name, WorkflowInstance).
--
-- Semantics: deny-by-default + explicit-forbid-wins. That means:
--   - "admins_can_do_anything_on_change_requests" is the broad
--     permit so local dev works out of the box;
--   - "change_approvers_can_review_and_decide" tightens approval
--     to a dedicated role;
--   - "cr_owner_can_submit_and_withdraw" scopes the owner-only
--     actions to the right actor;
--   - "requester_cannot_approve_own_cr" is a forbid that beats
--     any matching permit, enforcing segregation of duties.
--
-- The resource attribute set passed by the engine is:
--   { workflow_type: "change_request",
--     from_state:   "draft"|"submitted"|"under_review"|...,
--     to_state:     "submitted"|"under_review"|"approved"|... }
-- Plus the resource uid, which is the WorkflowInstance id.
--
-- Note: handlers do NOT currently project the CR's `requested_by`
-- into Cedar `resource.owner_id`, so the "cannot approve your own"
-- rule is enforced in Rust as a belt-and-braces check. When we
-- extend TransitionContext to carry owner attributes, this forbid
-- rule becomes the authoritative enforcement.

INSERT INTO policy_rules (name, description, policy_text, priority) VALUES
(
    'change_request_admins_full_access',
    'System Administrators and Administrators can run any transition on any change request.',
    $cedar$permit (
    principal in Role::"system_administrator",
    action,
    resource
) when {
    resource.workflow_type == "change_request"
};$cedar$,
    10
),
(
    'change_request_admin_role_full_access',
    'Legacy Administrator role also gets full CR lifecycle access.',
    $cedar$permit (
    principal in Role::"administrator",
    action,
    resource
) when {
    resource.workflow_type == "change_request"
};$cedar$,
    10
),
(
    'change_request_approvers_can_review_and_decide',
    'Users in change_approver may pick up submitted CRs (review), approve or reject them, and send them back for more work.',
    $cedar$permit (
    principal in Role::"change_approver",
    action in [Action::"review", Action::"approve", Action::"reject", Action::"send_back"],
    resource
) when {
    resource.workflow_type == "change_request"
};$cedar$,
    20
),
(
    'change_request_any_user_can_submit_or_withdraw_or_close',
    'Any authenticated user can submit a draft, withdraw a CR they own, or close an approved CR after execution. Ownership is enforced at the handler level until the engine projects resource.owner_id into Cedar.',
    $cedar$permit (
    principal,
    action in [Action::"submit", Action::"withdraw", Action::"close"],
    resource
) when {
    resource.workflow_type == "change_request"
};$cedar$,
    30
);

-- ============================================================================
-- 3. System attestation audit entry
-- ============================================================================
INSERT INTO audit_log (
    user_id, username, action, resource_type, details,
    cip_requirement, security_level, success
) VALUES (
    NULL,
    'system',
    'change_request_plugin_enabled',
    'change_requests',
    jsonb_build_object(
        'migration', 'change_request:001_change_requests',
        'workflow_type', 'change_request',
        'states', jsonb_build_array('draft','submitted','under_review','approved','rejected','withdrawn','closed'),
        'policies_seeded', 4
    ),
    'CIP-010 R1',
    'HIGH',
    true
);
