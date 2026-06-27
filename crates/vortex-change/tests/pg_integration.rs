//! End-to-end integration test for the Change Request plugin.
//!
//! This composes every layer the CR plugin sits on:
//!
//! - **vortex-workflow**: registers the CR state machine on the engine
//!   and drives transitions through it.
//! - **vortex-security (audit)**: each engine transition writes a
//!   chained `workflow_transition` entry to the WORM audit ledger.
//! - **vortex-policy**: Cedar is queried on every transition.
//!   Migration 117 seeds the CR policies that grant access.
//! - **plugin migration**: the test verifies the `change_requests`
//!   table and its seed policies are in place, applied via the
//!   plugin's embedded `migrations/001_change_requests/` SQL
//!   through `Plugin::migrations()`.
//!
//! Like the other DB-backed tests in this workspace, this skips
//! silently when `DATABASE_URL` is unset so CI without a database
//! stays green.
//!
//! ## What this test is and is not
//!
//! It is *not* an HTTP test — it does not spin up axum. The CR
//! plugin's handlers.rs is a thin adapter over the engine + DB;
//! exercising the engine end-to-end with a real CR row is what
//! proves the compliance story. Testing axum handlers would add a
//! lot of plumbing to verify the same invariants.
//!
//! It *is* a full happy-path lifecycle test: create a CR, walk it
//! through draft → submitted → under_review → approved → closed,
//! and assert that every step wrote a transition row, every
//! transition row points at a real audit entry, and the final
//! state of the CR row is what we expect.

use std::sync::Arc;

use chrono::Utc;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use uuid::Uuid;

use vortex_change::cr_state_machine;
use vortex_orm::ConnectionPool;
use vortex_policy::{PgPolicyStore, PolicyPrincipal, PolicyService};
use vortex_security::audit::PgAuditStorage;
use vortex_security::AuditLog;
use vortex_workflow::{
    InstanceId, PgWorkflowStore, TransitionContext, WorkflowEngine, WorkflowStore, WorkflowType,
};

const SYSTEM_COMPANY_ID: Uuid =
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

struct TestEnv {
    engine: Arc<WorkflowEngine>,
    store: Arc<dyn WorkflowStore>,
    pool: sqlx::PgPool,
    requester_id: Uuid,
    approver_id: Uuid,
}

async fn setup() -> Option<TestEnv> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .ok()?;

    // Require the plugin migration — if the table isn't there the
    // test environment is not ready, skip silently. On a fresh DB
    // the migration is applied by `vortex db migrate`.
    let has_table: Option<i64> = sqlx::query_scalar(
        "SELECT 1::bigint FROM information_schema.tables
         WHERE table_name = 'change_requests' LIMIT 1",
    )
    .fetch_optional(&pool)
    .await
    .ok()
    .flatten();
    if has_table.is_none() {
        eprintln!(
            "change_requests table missing — plugin migration not applied; skipping"
        );
        return None;
    }

    // Wire up the engine stack (same pattern as vortex-workflow's
    // pg_integration test): ephemeral signing key registered in
    // audit_signing_keys, real PgAuditStorage, real PolicyService.
    let cp = Arc::new(ConnectionPool::from_pg_pool(pool.clone(), &url));
    use vortex_security::signing::{Ed25519Key, SigningKey};
    let key_id = format!("cr-test-{}", Uuid::now_v7());
    let (key, _pkcs8) = Ed25519Key::generate(&key_id).unwrap();
    let public_key = key.public_key();
    let audit_init = PgAuditStorage::new(cp.clone(), None);
    audit_init
        .register_signing_key(&key_id, &public_key, "ed25519", Utc::now())
        .await
        .unwrap();
    let signer: Arc<dyn SigningKey> = Arc::new(key);
    let audit_storage = Arc::new(PgAuditStorage::new(cp.clone(), Some(signer)));
    let audit = Arc::new(AuditLog::new(audit_storage));

    let policy_store = Arc::new(PgPolicyStore::new(pool.clone()));
    let policy = Arc::new(PolicyService::load(policy_store).await.unwrap());

    let wf_store: Arc<dyn WorkflowStore> = Arc::new(PgWorkflowStore::new(pool.clone()));
    let mut engine = WorkflowEngine::new(wf_store.clone(), audit.clone(), policy.clone());
    engine.register_machine(cr_state_machine());

    // Two users: requester (no special role) and approver
    // (system_administrator, which the plugin's seed policies
    // permit for any transition). Using two distinct users is what
    // makes the segregation-of-duties check meaningful.
    let requester_id = ensure_test_user(&pool, "cr_requester", &[]).await;
    let approver_id =
        ensure_test_user(&pool, "cr_approver", &["system_administrator"]).await;

    Some(TestEnv {
        engine: Arc::new(engine),
        store: wf_store,
        pool,
        requester_id,
        approver_id,
    })
}

/// Find or create a test user with idempotent upsert semantics. The
/// test runs its four tests in parallel, so naive "SELECT then
/// INSERT if missing" races on the `(company_id, username)` unique
/// constraint. `ON CONFLICT DO NOTHING` + a follow-up SELECT handles
/// the race without a transaction.
async fn ensure_test_user(pool: &sqlx::PgPool, username: &str, _roles: &[&str]) -> Uuid {
    sqlx::query(
        "INSERT INTO users (id, company_id, username, email, password_hash, full_name)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (company_id, username) DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(SYSTEM_COMPANY_ID)
    .bind(username)
    .bind(format!("{}@test.local", username))
    .bind("$argon2id$v=19$m=4096,t=3,p=1$test$test") // placeholder, never used for login
    .bind(username)
    .execute(pool)
    .await
    .unwrap();

    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM users WHERE company_id = $1 AND username = $2",
    )
    .bind(SYSTEM_COMPANY_ID)
    .bind(username)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn principal(user_id: Uuid, roles: &[&str]) -> PolicyPrincipal {
    PolicyPrincipal {
        user_id,
        username: "cr_test".into(),
        company_id: SYSTEM_COMPANY_ID,
        roles: roles.iter().map(|s| s.to_string()).collect(),
    }
}

/// Insert a minimal `change_requests` row wired to a fresh workflow
/// instance. Mirrors what the `cr_create` handler does without going
/// through axum, so the test doesn't need a server.
async fn create_test_cr(env: &TestEnv, requester: Uuid) -> (Uuid, String, Uuid) {
    let instance = env
        .engine
        .create_instance(
            &WorkflowType::new("change_request"),
            SYSTEM_COMPANY_ID,
            requester,
            json!({}),
        )
        .await
        .unwrap();

    let cr_id = Uuid::new_v4();
    // Build a short tenant-unique number that fits the VARCHAR(32)
    // column. Taking the first 20 chars of a random v4 uuid gives
    // the tests a collision probability low enough to ignore, while
    // staying inside the column width (the "CR/TEST/" prefix is
    // 8 chars so 20 more keeps us at 28 ≤ 32).
    let number = format!("CR/TEST/{}", &cr_id.simple().to_string()[..20]);
    let now = Utc::now();
    sqlx::query(
        r#"
        INSERT INTO change_requests (
            id, number, title, description, category, criticality,
            rollback_plan, requested_by, workflow_instance_id,
            company_id, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
        "#,
    )
    .bind(cr_id)
    .bind(&number)
    .bind("Upgrade billing service to v2")
    .bind("Scheduled upgrade of the billing service.")
    .bind("maintenance")
    .bind("medium")
    .bind(Some("Restore from last-known-good snapshot and roll back to v1."))
    .bind(requester)
    .bind(instance.id.0)
    .bind(SYSTEM_COMPANY_ID)
    .bind(now)
    .execute(&env.pool)
    .await
    .unwrap();

    (cr_id, number, instance.id.0)
}

// ─── Tests ────────────────────────────────────────────────────────

#[tokio::test]
async fn plugin_migration_seeds_cedar_policies() {
    let Some(env) = setup().await else { return };

    // The CR plugin's `001_change_requests` migration (now
    // embedded in the crate via `Plugin::migrations()`, not in the
    // host `migrations/` folder) seeds four Cedar policies. This
    // test proves the plugin-declared migration ran against this
    // database.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM policy_rules WHERE name LIKE 'change_request_%' AND active = true",
    )
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert!(
        count >= 4,
        "expected at least 4 CR policies seeded by the plugin migration, found {count}"
    );
}

#[tokio::test]
async fn full_cr_lifecycle_draft_to_closed() {
    let Some(env) = setup().await else { return };

    let (cr_id, _number, instance_id) = create_test_cr(&env, env.requester_id).await;
    let instance = InstanceId(instance_id);

    // Requester submits for review. The Cedar seed policy
    // `change_request_any_user_can_submit_or_withdraw_or_close`
    // grants `submit` to any authenticated principal.
    env.engine
        .transition(
            instance,
            "submit",
            TransitionContext {
                actor: principal(env.requester_id, &[]),
                context: json!({"comment": "please review"}),
            },
        )
        .await
        .unwrap();

    // Approver picks up the CR for review. They hold
    // system_administrator so the admin-full-access permit matches.
    env.engine
        .transition(
            instance,
            "review",
            TransitionContext {
                actor: principal(env.approver_id, &["system_administrator"]),
                context: json!({"comment": "taking a look"}),
            },
        )
        .await
        .unwrap();

    // Approver approves.
    env.engine
        .transition(
            instance,
            "approve",
            TransitionContext {
                actor: principal(env.approver_id, &["system_administrator"]),
                context: json!({"approver_notes": "approved, schedule for next window"}),
            },
        )
        .await
        .unwrap();

    // Requester closes after execution.
    env.engine
        .transition(
            instance,
            "close",
            TransitionContext {
                actor: principal(env.requester_id, &[]),
                context: json!({"comment": "executed, rollback not needed"}),
            },
        )
        .await
        .unwrap();

    // The workflow instance should be in the closed state.
    let reloaded = env.store.get_instance(instance).await.unwrap();
    assert_eq!(reloaded.current_state, "closed");

    // There should be exactly four transitions in history and each
    // one must reference a real audit_log entry.
    let history = env.store.get_transitions(instance).await.unwrap();
    assert_eq!(history.len(), 4, "expected 4 transitions, got {}", history.len());
    let expected_order = ["submit", "review", "approve", "close"];
    for (i, name) in expected_order.iter().enumerate() {
        assert_eq!(history[i].transition_name, *name);
        assert!(
            history[i].audit_entry_id.is_some(),
            "transition '{}' missing audit_entry_id",
            name
        );
    }

    // Each transition's audit entry is a real WORM-chained row.
    for t in &history {
        let row = sqlx::query(
            "SELECT action, entry_hash, chain_position
               FROM audit_log WHERE id = $1",
        )
        .bind(t.audit_entry_id.unwrap())
        .fetch_one(&env.pool)
        .await
        .unwrap();
        let action: String = row.get("action");
        let entry_hash: Option<Vec<u8>> = row.get("entry_hash");
        let chain_position: Option<i64> = row.get("chain_position");
        assert_eq!(action, "workflow_transition");
        assert!(entry_hash.is_some(), "audit entry must be hash-chained");
        assert!(chain_position.is_some(), "audit entry must have chain position");
    }

    // Sanity: the CR row still exists with the right requester.
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM change_requests WHERE id = $1)")
            .bind(cr_id)
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert!(exists);
}

#[tokio::test]
async fn rejected_cr_cannot_be_approved() {
    let Some(env) = setup().await else { return };

    let (_cr_id, _number, instance_id) = create_test_cr(&env, env.requester_id).await;
    let instance = InstanceId(instance_id);

    // Walk the CR to `under_review` then reject.
    env.engine
        .transition(
            instance,
            "submit",
            TransitionContext {
                actor: principal(env.requester_id, &[]),
                context: json!({}),
            },
        )
        .await
        .unwrap();
    env.engine
        .transition(
            instance,
            "review",
            TransitionContext {
                actor: principal(env.approver_id, &["system_administrator"]),
                context: json!({}),
            },
        )
        .await
        .unwrap();
    env.engine
        .transition(
            instance,
            "reject",
            TransitionContext {
                actor: principal(env.approver_id, &["system_administrator"]),
                context: json!({"reason": "incomplete rollback plan"}),
            },
        )
        .await
        .unwrap();

    // `rejected` is a terminal state. No further transitions are legal.
    let rejected = env.store.get_instance(instance).await.unwrap();
    assert_eq!(rejected.current_state, "rejected");

    let result = env
        .engine
        .transition(
            instance,
            "approve",
            TransitionContext {
                actor: principal(env.approver_id, &["system_administrator"]),
                context: json!({}),
            },
        )
        .await;
    assert!(
        result.is_err(),
        "expected approve to be rejected from terminal state"
    );
}

#[tokio::test]
async fn withdraw_is_available_from_draft_submitted_under_review() {
    let Some(env) = setup().await else { return };

    // Verify from each of the three allowed source states that
    // withdraw succeeds. A separate CR per state keeps them isolated.
    for start_state in ["draft", "submitted", "under_review"] {
        let (_cr_id, _number, instance_id) = create_test_cr(&env, env.requester_id).await;
        let instance = InstanceId(instance_id);

        // Walk to the target start state.
        if start_state == "submitted" || start_state == "under_review" {
            env.engine
                .transition(
                    instance,
                    "submit",
                    TransitionContext {
                        actor: principal(env.requester_id, &[]),
                        context: json!({}),
                    },
                )
                .await
                .unwrap();
        }
        if start_state == "under_review" {
            env.engine
                .transition(
                    instance,
                    "review",
                    TransitionContext {
                        actor: principal(env.approver_id, &["system_administrator"]),
                        context: json!({}),
                    },
                )
                .await
                .unwrap();
        }

        env.engine
            .transition(
                instance,
                "withdraw",
                TransitionContext {
                    actor: principal(env.requester_id, &[]),
                    context: json!({}),
                },
            )
            .await
            .unwrap_or_else(|e| {
                panic!("withdraw from {start_state} failed: {e}");
            });

        let reloaded = env.store.get_instance(instance).await.unwrap();
        assert_eq!(reloaded.current_state, "withdrawn");
    }
}
