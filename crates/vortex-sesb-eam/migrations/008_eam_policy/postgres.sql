-- ============================================================================
-- Migration 008 (SESB EAM) — starter Cedar policy for work-order transitions.
-- ============================================================================
-- Seeds the authorization policy that `maintenance_action` enforces via
-- `guarded_transition`. Depends on core migration 115 (the `policy_rules`
-- table and the Cedar engine).
--
-- The `policy_text` below MUST stay byte-for-byte identical to
-- `work_order_transitions.cedar` in this directory — that file is the source
-- of truth the plugin and its tests `include_str!`, and a drift test
-- (tests/work_order_policy.rs) asserts this SQL still contains it.
--
-- Idempotent: upsert on the unique policy name so re-running the migration
-- refreshes the text without creating duplicates.
-- ============================================================================

INSERT INTO policy_rules (name, description, policy_text, priority, active) VALUES
(
    'eam_work_order_transitions',
    'SESB EAM: operational EAM roles (EAM User/Officer/Manager/Admin) and platform administrators may drive work-order execution transitions (accept/reject/start/hold/resume/complete) on WorkOrder resources. Asset Creator/Verifier excluded.',
    $cedar$// SESB EAM — work-order transition authorization (migration 008).
//
// Grants the operational EAM roles (and platform admins) the right to drive a
// work order through its execution lifecycle. Actions map 1:1 to the edges in
// `work_order_machine()`. `reject` is the assigned agent DECLINING a job — it
// returns the order to `scheduled` and clears the assignee — so it belongs to
// the same field-execution tier as `accept`, not a supervisor-only action.
//
// Role strings are the `roles.name` values that land in `AuthUser.roles`
// (display-cased). Cedar `make_uid` does NOT normalise, so they must match
// verbatim. "EAM Asset Creator" / "EAM Asset Verifier" are intentionally
// excluded — their governance definition grants no work-order access.
//
// The role set lives in the `when` clause because Cedar only accepts a single
// entity uid in the policy-head `principal in ...` position; set membership is
// expressed as a condition. `resource is WorkOrder` keeps this permit from
// leaking onto other resource types that reuse an action name (e.g. a change
// request's "reject"). Cedar is default-deny: anything not permitted here is
// denied once EAM_TRANSITION_POLICY=enforce is set; until then denials are
// logged only.
permit (
    principal,
    action in [
        Action::"accept",
        Action::"reject",
        Action::"start",
        Action::"hold",
        Action::"resume",
        Action::"complete"
    ],
    resource
) when {
    resource is WorkOrder &&
    principal in [
        Role::"EAM User",
        Role::"EAM Officer",
        Role::"EAM Manager",
        Role::"EAM Admin",
        Role::"System Administrator",
        Role::"Administrator"
    ]
};
$cedar$,
    30,
    true
)
ON CONFLICT (name) DO UPDATE
    SET policy_text = EXCLUDED.policy_text,
        description = EXCLUDED.description,
        priority    = EXCLUDED.priority,
        active      = true,
        updated_at  = now();
