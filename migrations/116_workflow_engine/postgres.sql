-- Migration 116: Workflow Engine
--
-- Creates the two tables the vortex-workflow crate needs:
--
--   - workflow_instances: the living, mutable half of a workflow.
--     One row per running instance of any state machine registered
--     with the engine. Plugins define their own state machines at
--     compile time; this table stores the current state + state_data.
--
--   - workflow_transitions: append-only history of every state
--     change. WORM-enforced via BEFORE UPDATE/DELETE/TRUNCATE
--     triggers (same pattern as audit_log from migration 114).
--     Each row has a back-reference to the audit_log entry the
--     engine wrote for that transition, so auditors can walk from
--     a workflow history row back to its cryptographically-chained
--     audit record.
--
-- Scoping:
--   - Both tables are multi-tenant via company_id.
--   - Both reference users(id) and companies(id) for FK integrity.
--   - workflow_transitions.audit_entry_id references audit_log(id)
--     so a dangling transition (audit row missing) is a FK error.

-- ============================================================================
-- 1. workflow_instances — the mutable runtime state
-- ============================================================================
CREATE TABLE IF NOT EXISTS workflow_instances (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workflow_type   VARCHAR(100) NOT NULL,
    current_state   VARCHAR(100) NOT NULL,
    state_data      JSONB DEFAULT '{}'::jsonb,
    company_id      UUID NOT NULL REFERENCES companies(id),
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workflow_instances_type_state
    ON workflow_instances (workflow_type, current_state);
CREATE INDEX IF NOT EXISTS idx_workflow_instances_company
    ON workflow_instances (company_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_workflow_instances_created_by
    ON workflow_instances (created_by, created_at DESC);

-- updated_at auto-bump trigger (reuses the generic helper defined
-- in migration 001).
DROP TRIGGER IF EXISTS trg_workflow_instances_updated_at ON workflow_instances;
CREATE TRIGGER trg_workflow_instances_updated_at
    BEFORE UPDATE ON workflow_instances
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

COMMENT ON TABLE workflow_instances IS
    'Live state of running workflow instances. One row per instance; current_state/state_data mutate as transitions occur. Transition history lives in workflow_transitions (append-only).';
COMMENT ON COLUMN workflow_instances.state_data IS
    'Plugin-defined JSON blob scoped to this instance. Schema is a private contract between the plugin and its handlers; the engine treats this as opaque.';

-- ============================================================================
-- 2. workflow_transitions — append-only history
-- ============================================================================
CREATE TABLE IF NOT EXISTS workflow_transitions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    instance_id     UUID NOT NULL REFERENCES workflow_instances(id),
    transition_name VARCHAR(100) NOT NULL,
    from_state      VARCHAR(100) NOT NULL,
    to_state        VARCHAR(100) NOT NULL,
    actor_user_id   UUID REFERENCES users(id),
    context         JSONB DEFAULT '{}'::jsonb,
    audit_entry_id  UUID REFERENCES audit_log(id),
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workflow_transitions_instance
    ON workflow_transitions (instance_id, occurred_at ASC);
CREATE INDEX IF NOT EXISTS idx_workflow_transitions_actor
    ON workflow_transitions (actor_user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_workflow_transitions_audit
    ON workflow_transitions (audit_entry_id);

-- ============================================================================
-- 3. Append-only WORM enforcement for workflow_transitions
-- ============================================================================
-- The history table gets the same treatment as audit_log: BEFORE
-- UPDATE/DELETE/TRUNCATE triggers that RAISE EXCEPTION. Once a
-- transition is recorded, it cannot be rewritten or erased. This is
-- what makes workflow history defensible evidence for compliance
-- audits: "show me every state change on this Change Request" has
-- a single source of truth that no one — not even a DBA — can
-- quietly alter.

CREATE OR REPLACE FUNCTION workflow_transitions_block_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'workflow_transitions is append-only (WORM); TG_OP=% blocked by workflow policy', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_workflow_transitions_no_update ON workflow_transitions;
CREATE TRIGGER trg_workflow_transitions_no_update
    BEFORE UPDATE ON workflow_transitions
    FOR EACH ROW EXECUTE FUNCTION workflow_transitions_block_mutation();

DROP TRIGGER IF EXISTS trg_workflow_transitions_no_delete ON workflow_transitions;
CREATE TRIGGER trg_workflow_transitions_no_delete
    BEFORE DELETE ON workflow_transitions
    FOR EACH ROW EXECUTE FUNCTION workflow_transitions_block_mutation();

DROP TRIGGER IF EXISTS trg_workflow_transitions_no_truncate ON workflow_transitions;
CREATE TRIGGER trg_workflow_transitions_no_truncate
    BEFORE TRUNCATE ON workflow_transitions
    FOR EACH STATEMENT EXECUTE FUNCTION workflow_transitions_block_mutation();

-- Runtime role gets SELECT + INSERT only. UPDATE/DELETE/TRUNCATE
-- are explicitly revoked to back up the trigger enforcement.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON workflow_transitions FROM vortex_runtime';
    END IF;
END$$;

REVOKE UPDATE, DELETE, TRUNCATE ON workflow_transitions FROM PUBLIC;

COMMENT ON TABLE workflow_transitions IS
    'Append-only history of state machine transitions. Every row is a provable, immutable record linked back to an audit_log entry (audit_entry_id FK). BEFORE UPDATE/DELETE/TRUNCATE triggers enforce WORM semantics at the database level.';

-- ============================================================================
-- 4. System attestation audit entry
-- ============================================================================
INSERT INTO audit_log (
    user_id, username, action, resource_type, details,
    compliance_category, security_level, success
) VALUES (
    NULL,
    'system',
    'workflow_engine_enabled',
    'workflow_instances',
    jsonb_build_object(
        'migration', '116_workflow_engine',
        'worm_enforcement', true,
        'supports', jsonb_build_array('change_requests', 'purchase_orders', 'incidents', 'access_requests')
    ),
    'authentication',
    'HIGH',
    true
);
