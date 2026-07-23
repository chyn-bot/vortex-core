//! Integration tests for the work-order authorization seed (migration 008)
//! and the `guarded_transition` helper.
//!
//! These build a real `PolicyService` from the exact Cedar text that ships in
//! `work_order_transitions.cedar`, so they validate the shipped policy — not a
//! hand-written stand-in. No database is touched: a tiny in-test `PolicyStore`
//! feeds the policy to the engine.

use std::sync::Arc;

use vortex_plugin_sdk::async_trait::async_trait;
use vortex_plugin_sdk::policy::{
    Decision, PolicyPrincipal, PolicyRecord, PolicyResult, PolicyResource, PolicyService,
    PolicyStore,
};
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::uuid::Uuid;

use vortex_sesb_eam::workflow::{guarded_transition, work_order_machine, Guard, WORK_ORDER_POLICY};

/// In-test store returning a fixed set of policy records — the same abstraction
/// the Postgres store implements, so `PolicyService::load` works unchanged.
struct SeedStore(Vec<PolicyRecord>);

#[async_trait]
impl PolicyStore for SeedStore {
    async fn load_all(&self) -> PolicyResult<Vec<PolicyRecord>> {
        Ok(self.0.clone())
    }
}

/// Build a `PolicyService` loaded with only the shipped work-order policy.
async fn seed_service() -> PolicyService {
    let now = vortex_plugin_sdk::chrono::Utc::now();
    let rec = PolicyRecord {
        id: Uuid::new_v4(),
        name: "eam_work_order_transitions".into(),
        description: None,
        policy_text: WORK_ORDER_POLICY.to_string(),
        active: true,
        priority: 30,
        company_id: None,
        created_at: now,
        updated_at: now,
    };
    let svc = PolicyService::load(Arc::new(SeedStore(vec![rec])))
        .await
        .expect("policy service loads");
    // The shipped Cedar must parse cleanly.
    assert!(
        svc.parse_errors().await.is_empty(),
        "work_order_transitions.cedar failed to parse: {:?}",
        svc.parse_errors().await
    );
    svc
}

fn principal(roles: &[&str]) -> PolicyPrincipal {
    PolicyPrincipal {
        user_id: Uuid::new_v4(),
        username: "tester".into(),
        company_id: Uuid::new_v4(),
        roles: roles.iter().map(|s| s.to_string()).collect(),
    }
}

fn wo_resource(from: &str, action: &str) -> PolicyResource {
    PolicyResource {
        type_name: "WorkOrder".into(),
        id: Uuid::new_v4().to_string(),
        attributes: json!({ "from_state": from, "action": action }),
    }
}

// ── Cedar policy: allow/deny by role, directly against the engine ──────────

#[tokio::test]
async fn field_agent_role_is_allowed_to_complete() {
    let svc = seed_service().await;
    let d = svc
        .check(&principal(&["EAM User"]), "complete", &wo_resource("in_progress", "complete"))
        .await
        .unwrap();
    assert!(matches!(d, Decision::Allow { .. }), "EAM User should be allowed to complete");
}

#[tokio::test]
async fn platform_admin_is_allowed() {
    let svc = seed_service().await;
    let d = svc
        .check(&principal(&["System Administrator"]), "reject", &wo_resource("assigned", "reject"))
        .await
        .unwrap();
    assert!(matches!(d, Decision::Allow { .. }));
}

#[tokio::test]
async fn excluded_role_is_denied() {
    let svc = seed_service().await;
    // "EAM Asset Verifier" has no work-order access per its governance def.
    let d = svc
        .check(&principal(&["EAM Asset Verifier"]), "complete", &wo_resource("in_progress", "complete"))
        .await
        .unwrap();
    assert!(matches!(d, Decision::Deny { .. }), "Asset Verifier must be denied work-order actions");
}

#[tokio::test]
async fn unknown_role_is_denied_default() {
    let svc = seed_service().await;
    let d = svc
        .check(&principal(&["Warehouse Clerk"]), "start", &wo_resource("scheduled", "start"))
        .await
        .unwrap();
    assert!(matches!(d, Decision::Deny { .. }), "Cedar default-deny for unlisted roles");
}

#[tokio::test]
async fn policy_does_not_leak_to_other_resource_types() {
    let svc = seed_service().await;
    // Same role + action, but a non-WorkOrder resource: the `resource is
    // WorkOrder` guard must keep the permit from applying (e.g. a change
    // request that happens to reuse the "reject" action name).
    let other = PolicyResource {
        type_name: "WorkflowInstance".into(),
        id: Uuid::new_v4().to_string(),
        attributes: json!({ "workflow_type": "change_request" }),
    };
    let d = svc.check(&principal(&["EAM Manager"]), "reject", &other).await.unwrap();
    assert!(matches!(d, Decision::Deny { .. }), "WO permit must not apply to WorkflowInstance");
}

// ── guarded_transition: legality + policy + warn/enforce ───────────────────

#[tokio::test]
async fn guarded_allows_legal_authorized_transition() {
    let svc = seed_service().await;
    let g = guarded_transition(
        &svc, work_order_machine(), "in_progress", "complete",
        &principal(&["EAM User"]), wo_resource("in_progress", "complete"), true,
    )
    .await;
    assert!(matches!(g, Guard::Allow(ref s) if s == "completed"));
}

#[tokio::test]
async fn guarded_rejects_illegal_edge_before_policy() {
    let svc = seed_service().await;
    // Authorized role, but completing from `scheduled` is not a legal edge —
    // the machine rejects it regardless of policy.
    let g = guarded_transition(
        &svc, work_order_machine(), "scheduled", "complete",
        &principal(&["EAM Manager"]), wo_resource("scheduled", "complete"), true,
    )
    .await;
    assert!(matches!(g, Guard::Illegal));
}

#[tokio::test]
async fn guarded_denies_unauthorized_in_enforce_mode() {
    let svc = seed_service().await;
    let g = guarded_transition(
        &svc, work_order_machine(), "in_progress", "complete",
        &principal(&["EAM Asset Verifier"]), wo_resource("in_progress", "complete"), true,
    )
    .await;
    assert!(matches!(g, Guard::Denied));
}

#[tokio::test]
async fn guarded_allows_unauthorized_in_warn_mode() {
    let svc = seed_service().await;
    // Same denied principal, but warn mode (enforce = false) lets it through
    // after logging — the rollout-safety guarantee.
    let g = guarded_transition(
        &svc, work_order_machine(), "in_progress", "complete",
        &principal(&["EAM Asset Verifier"]), wo_resource("in_progress", "complete"), false,
    )
    .await;
    assert!(matches!(g, Guard::Allow(ref s) if s == "completed"));
}

// ── Drift guard: migration SQL must embed the exact Cedar source ───────────

#[test]
fn migration_sql_embeds_the_exact_cedar_source() {
    const MIG_008_SQL: &str = include_str!("../migrations/008_eam_policy/postgres.sql");
    assert!(
        MIG_008_SQL.contains(WORK_ORDER_POLICY.trim()),
        "migration 008 postgres.sql must embed work_order_transitions.cedar byte-for-byte"
    );
}
