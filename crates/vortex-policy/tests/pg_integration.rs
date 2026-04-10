//! Integration tests for `vortex-policy` against a real Postgres.
//!
//! Requires `DATABASE_URL` pointing at a database with migrations
//! 001..=115 applied. When `DATABASE_URL` is absent, tests skip with a
//! warning so `cargo test` stays green on hosts without Postgres.

use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
use vortex_policy::{Decision, PgPolicyStore, PolicyPrincipal, PolicyResource, PolicyService};

async fn setup() -> Option<sqlx::PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .ok()?;
    // Verify policy_rules exists and has seed rows.
    let has_seed: Option<i64> = sqlx::query_scalar("SELECT COUNT(*) FROM policy_rules")
        .fetch_one(&pool)
        .await
        .ok();
    if has_seed.unwrap_or(0) == 0 {
        eprintln!("policy_rules empty — migration 115 not applied; skipping");
        return None;
    }
    Some(pool)
}

fn admin_principal() -> PolicyPrincipal {
    PolicyPrincipal {
        user_id: Uuid::from_u128(0xA1),
        username: "admin".into(),
        company_id: Uuid::from_bytes([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]),
        roles: vec!["system_administrator".into()],
    }
}

fn viewer_principal(id: u128) -> PolicyPrincipal {
    PolicyPrincipal {
        user_id: Uuid::from_u128(id),
        username: format!("viewer_{id}"),
        company_id: Uuid::from_bytes([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]),
        roles: vec!["viewer".into()],
    }
}

fn user_resource(id: u128) -> PolicyResource {
    PolicyResource {
        type_name: "User".into(),
        id: Uuid::from_u128(id).to_string(),
        attributes: serde_json::Value::Null,
    }
}

#[tokio::test]
async fn admin_can_update_other_user() {
    let Some(pool) = setup().await else { return };
    let svc = PolicyService::load(Arc::new(PgPolicyStore::new(pool)))
        .await
        .unwrap();
    let decision = svc
        .check(&admin_principal(), "update", &user_resource(0xB2))
        .await
        .unwrap();
    assert!(decision.is_allow(), "admin update should be allowed: {decision:?}");
    if let Decision::Allow { determining_policies } = decision {
        assert!(
            determining_policies
                .iter()
                .any(|p| p == "admins_can_manage_users"),
            "expected admins_can_manage_users to be determining, got {determining_policies:?}"
        );
    }
}

#[tokio::test]
async fn viewer_cannot_update_other_user() {
    let Some(pool) = setup().await else { return };
    let svc = PolicyService::load(Arc::new(PgPolicyStore::new(pool)))
        .await
        .unwrap();
    let decision = svc
        .check(&viewer_principal(0xC1), "update", &user_resource(0xC2))
        .await
        .unwrap();
    assert!(decision.is_deny(), "viewer should be denied: {decision:?}");
}

#[tokio::test]
async fn self_service_update_is_allowed() {
    let Some(pool) = setup().await else { return };
    let svc = PolicyService::load(Arc::new(PgPolicyStore::new(pool)))
        .await
        .unwrap();
    // Same uuid for principal and resource.
    let target_id = 0xDEAD_u128;
    let decision = svc
        .check(&viewer_principal(target_id), "update", &user_resource(target_id))
        .await
        .unwrap();
    assert!(decision.is_allow(), "self update should be allowed: {decision:?}");
    if let Decision::Allow { determining_policies } = decision {
        assert!(
            determining_policies
                .iter()
                .any(|p| p == "self_service_profile_update"),
            "expected self_service_profile_update determining: {determining_policies:?}"
        );
    }
}

#[tokio::test]
async fn forbid_overrides_admin_permit() {
    let Some(pool) = setup().await else { return };
    let svc = PolicyService::load(Arc::new(PgPolicyStore::new(pool)))
        .await
        .unwrap();
    // Admin trying to delete the system company. The
    // admins_can_manage_users permit does NOT cover Company::delete, but
    // even if it did, forbid_delete_system_company is a forbid and would
    // beat any permit. This test documents forbid-beats-permit semantics.
    let resource = PolicyResource {
        type_name: "Company".into(),
        id: "00000000-0000-0000-0000-000000000001".into(),
        attributes: serde_json::Value::Null,
    };
    let decision = svc
        .check(&admin_principal(), "delete", &resource)
        .await
        .unwrap();
    assert!(decision.is_deny(), "system company delete must be denied: {decision:?}");
}

#[tokio::test]
async fn auditor_can_read_and_verify() {
    let Some(pool) = setup().await else { return };
    let svc = PolicyService::load(Arc::new(PgPolicyStore::new(pool)))
        .await
        .unwrap();
    let auditor = PolicyPrincipal {
        user_id: Uuid::from_u128(0xAA),
        username: "auditor".into(),
        company_id: Uuid::from_bytes([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]),
        roles: vec!["auditor".into()],
    };
    let resource = PolicyResource {
        type_name: "AuditLog".into(),
        id: "any".into(),
        attributes: serde_json::Value::Null,
    };
    let decision = svc.check(&auditor, "verify", &resource).await.unwrap();
    assert!(decision.is_allow(), "auditor verify should be allowed: {decision:?}");
}
