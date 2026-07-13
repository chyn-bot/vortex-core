//! Governance test for Vortex Blueprints — proves the seeded Cedar permit
//! (`admins_can_manage_blueprints`, migration 146) grants system administrators
//! exactly the three blueprint actions the governed service gates on, and denies
//! everyone else. A mismatch between the migration's `Action::"blueprint.*"`
//! names and the strings `blueprint::gate(...)` passes would silently break the
//! whole feature (Cedar is deny-by-default), so this test pins them together.
//!
//! Skips unless `BLUEPRINT_TEST_DATABASE_URL` points at a DB with migrations
//! through 146 applied, so CI without Postgres stays green.

use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
use vortex_policy::{Decision, PgPolicyStore, PolicyPrincipal, PolicyResource, PolicyService};

/// The exact action strings `vortex_framework::blueprint::gate` passes.
const BLUEPRINT_ACTIONS: &[&str] = &["blueprint.create", "blueprint.alter", "blueprint.delete"];

async fn service() -> Option<PolicyService> {
    let url = std::env::var("BLUEPRINT_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new().max_connections(4).connect(&url).await.ok()?;
    let seeded: Option<i64> =
        sqlx::query_scalar("SELECT COUNT(*) FROM policy_rules WHERE name = 'admins_can_manage_blueprints'")
            .fetch_one(&pool)
            .await
            .ok();
    if seeded.unwrap_or(0) == 0 {
        eprintln!("admins_can_manage_blueprints not seeded (migration 146) — skipping");
        return None;
    }
    PolicyService::load(Arc::new(PgPolicyStore::new(pool))).await.ok()
}

fn principal(roles: &[&str]) -> PolicyPrincipal {
    PolicyPrincipal {
        user_id: Uuid::from_u128(0xB1),
        username: "tester".into(),
        company_id: Uuid::nil(),
        roles: roles.iter().map(|r| r.to_string()).collect(),
    }
}

fn blueprint_resource() -> PolicyResource {
    PolicyResource {
        type_name: "Blueprint".into(),
        id: "x_widget".into(),
        attributes: serde_json::Value::Null,
    }
}

#[tokio::test]
async fn admin_is_allowed_every_blueprint_action() {
    let Some(svc) = service().await else { return };
    let admin = principal(&["system_administrator"]);
    for action in BLUEPRINT_ACTIONS {
        let decision = svc.check(&admin, action, &blueprint_resource()).await.unwrap();
        assert!(decision.is_allow(), "admin should be allowed {action}: {decision:?}");
        if let Decision::Allow { determining_policies } = decision {
            assert!(
                determining_policies.iter().any(|p| p == "admins_can_manage_blueprints"),
                "{action} should be granted by admins_can_manage_blueprints, got {determining_policies:?}"
            );
        }
    }
}

#[tokio::test]
async fn non_admin_is_denied_every_blueprint_action() {
    let Some(svc) = service().await else { return };
    let viewer = principal(&["viewer"]);
    for action in BLUEPRINT_ACTIONS {
        let decision = svc.check(&viewer, action, &blueprint_resource()).await.unwrap();
        assert!(decision.is_deny(), "viewer must be denied {action}: {decision:?}");
    }
}
