-- ============================================================================
-- Migration 164 (core) — generic record-API authorization baseline.
-- ============================================================================
-- Seeds the Cedar policy the generic REST API (/api/v1/{model}) evaluates on
-- every read/create/update/delete. Depends on migration 115 (policy_rules +
-- Cedar engine).
--
-- The policy_text below MUST stay byte-for-byte identical to api_baseline.cedar
-- in this directory (a drift test in crates/vortex-policy/tests asserts it).
--
-- Idempotent: upsert on the unique policy name.
-- ============================================================================

INSERT INTO policy_rules (name, description, policy_text, priority, active) VALUES
(
    'api_record_authz_baseline',
    'Generic record API (/api/v1) authorization baseline: permits any authenticated principal, scoped to Record resources. The seam tenants tighten with forbid rules or role-scoped permits. Enforced when API_POLICY_ENFORCED is set.',
    $cedar$// Core — generic record API authorization baseline (migration 164).
//
// The generic REST API (`/api/v1/{model}`) evaluates this policy on every
// read/create/update/delete. This baseline PERMITS any authenticated principal
// (the bearer-token middleware has already established identity), so that
// turning on enforcement (API_POLICY_ENFORCED=1) does not break existing
// integrations. It is the seam a tenant tightens: add `forbid` rules — e.g.
// forbid `delete` on financial models for non-managers — or replace this
// permit with narrower role-scoped permits.
//
// `resource is Record` confines this permit to the generic record API; it does
// not affect workflow, work-order, blueprint or user-management authorization,
// which use their own resource types.
permit (
    principal,
    action,
    resource
) when {
    resource is Record
};
$cedar$,
    50,
    true
)
ON CONFLICT (name) DO UPDATE
    SET policy_text = EXCLUDED.policy_text,
        description = EXCLUDED.description,
        priority    = EXCLUDED.priority,
        active      = true,
        updated_at  = now();
