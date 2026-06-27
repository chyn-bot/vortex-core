-- Migration 115: Policy Engine (Cedar-based ABAC)
--
-- Creates the `policy_rules` table and seeds it with a minimal set of
-- baseline policies. The Rust service (`crates/vortex-policy/`) loads
-- active rows at startup, parses each as Cedar source, and evaluates
-- request decisions against the assembled policy set.
--
-- Relationship to existing RBAC:
--   - `model_access` / `record_rules` / `field_access` still enforce the
--     coarse layer ("can role X read table Y?").
--   - `policy_rules` layers above for fine-grained decisions that depend
--     on request context, record attributes, or relationships ("can
--     Alice approve WO-123 given she is the requester?").
--   - Handlers typically check both: RBAC gate first (cheap, set-based),
--     Cedar policy second (expressive, per-decision).
--
-- The table is NOT marked WORM — policies are operational configuration
-- that needs to be editable. History of policy changes will be recorded
-- in the audit_log via the PolicyChanged action variant in a future phase.

CREATE TABLE IF NOT EXISTS policy_rules (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name         VARCHAR(255) NOT NULL,
    description  TEXT,
    policy_text  TEXT NOT NULL,
    active       BOOLEAN NOT NULL DEFAULT true,
    priority     INTEGER NOT NULL DEFAULT 100,
    company_id   UUID REFERENCES companies(id),
    created_by   UUID REFERENCES users(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_policy_rules_name UNIQUE (name)
);

CREATE INDEX IF NOT EXISTS idx_policy_rules_active ON policy_rules(active, priority);
CREATE INDEX IF NOT EXISTS idx_policy_rules_company ON policy_rules(company_id, active);

COMMENT ON TABLE policy_rules IS
    'Cedar ABAC policies loaded by vortex-policy::PolicyService. See crates/vortex-policy/src/service.rs for evaluation semantics (deny-by-default, forbid beats permit).';
COMMENT ON COLUMN policy_rules.policy_text IS
    'Cedar policy source — one or more permit/forbid statements. Parsed at service load; rows with parse errors are skipped with a logged warning but do not block startup.';

-- Auto-update updated_at on any row change.
DROP TRIGGER IF EXISTS trg_policy_rules_updated_at ON policy_rules;
CREATE TRIGGER trg_policy_rules_updated_at
    BEFORE UPDATE ON policy_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Seed policies
-- ============================================================================
-- These are intentionally permissive — they mirror the current hard-coded
-- RBAC behaviour so the switch to Cedar is a no-op semantically. Tightening
-- happens in follow-up migrations as specific compliance requirements land.

INSERT INTO policy_rules (name, description, policy_text, priority) VALUES
(
    'admins_can_manage_users',
    'System administrators and Administrators can create, update, delete, lock, and unlock any user account.',
    $cedar$permit (
    principal in Role::"system_administrator",
    action in [Action::"create", Action::"update", Action::"delete", Action::"lock", Action::"unlock"],
    resource
);

permit (
    principal in Role::"administrator",
    action in [Action::"create", Action::"update", Action::"delete", Action::"lock", Action::"unlock"],
    resource
);$cedar$,
    10
),
(
    'self_service_profile_update',
    'Any user can update their own profile (email, full_name, password). Applies only when principal == resource.',
    $cedar$permit (
    principal,
    action == Action::"update",
    resource
) when {
    principal == resource
};$cedar$,
    20
),
(
    'forbid_delete_system_company',
    'The seeded system company (00000000-0000-0000-0000-000000000001) must never be deleted. Catches both accidental admin clicks and malicious scripts.',
    $cedar$forbid (
    principal,
    action == Action::"delete",
    resource == Company::"00000000-0000-0000-0000-000000000001"
);$cedar$,
    1
),
(
    'auditors_can_verify_chain',
    'Users with the auditor role can invoke `vortex audit verify` and read any audit_log row regardless of tenant. This unblocks compliance reviewers who need to check the ledger independently.',
    $cedar$permit (
    principal in Role::"auditor",
    action in [Action::"read", Action::"verify"],
    resource
);$cedar$,
    40
);

-- ============================================================================
-- Seed audit_log entry: a system-level marker recording when the policy
-- engine became active.
-- ============================================================================
INSERT INTO audit_log (
    user_id, username, action, resource_type, details,
    compliance_category, security_level, success
) VALUES (
    NULL,
    'system',
    'POLICY_ENGINE_ENABLED',
    'policy_rules',
    jsonb_build_object(
        'migration', '115_policy_engine',
        'engine', 'cedar-policy',
        'seed_policies', 4
    ),
    'authorization',
    'HIGH',
    true
);
