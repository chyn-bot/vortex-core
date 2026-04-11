//! End-to-end integration tests for `vortex-workflow` against a
//! real Postgres database.
//!
//! These tests compose the full stack: workflow engine, WORM audit
//! ledger, Cedar policy engine, and Postgres. They prove the
//! interaction between them works the way the design promises —
//! transitions are audited, policies are enforced, and history is
//! tamper-evident at the DB level.
//!
//! Like the other integration tests in this workspace, these skip
//! silently when `DATABASE_URL` is unset so `cargo test` stays
//! green on CI machines without a database.

use std::sync::Arc;

use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use uuid::Uuid;

use vortex_orm::ConnectionPool;
use vortex_policy::{PgPolicyStore, PolicyPrincipal, PolicyService};
use vortex_security::audit::PgAuditStorage;
use vortex_security::AuditLog;
use vortex_workflow::{
    InstanceId, PgWorkflowStore, StateMachine, TransitionContext, WorkflowEngine, WorkflowError,
    WorkflowStore,
};

const SYSTEM_COMPANY_ID: Uuid =
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

async fn setup() -> Option<(Arc<dyn WorkflowStore>, Arc<WorkflowEngine>, sqlx::PgPool, Uuid)> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .ok()?;

    // Verify migration 116 is applied.
    let has_table: Option<i64> = sqlx::query_scalar(
        "SELECT 1::bigint FROM information_schema.tables
         WHERE table_name = 'workflow_instances' LIMIT 1",
    )
    .fetch_optional(&pool)
    .await
    .ok()
    .flatten();
    if has_table.is_none() {
        eprintln!("workflow_instances table missing — migration 116 not applied; skipping");
        return None;
    }

    // Build the full engine: PgWorkflowStore + PgAuditStorage (signed
    // with an ephemeral Ed25519 key so chain writes succeed without
    // needing VORTEX_AUDIT_SIGNING_KEY in the env) + PgPolicyService.
    //
    // We register the public half of the ephemeral key into
    // audit_signing_keys so the verifier (vortex audit verify) can
    // validate the entries it signs — otherwise the test would leave
    // un-verifiable rows that break `vortex audit verify` on reruns.
    let cp = Arc::new(ConnectionPool::from_pg_pool(pool.clone(), &url));
    use vortex_security::signing::{Ed25519Key, SigningKey};
    let key_id = format!("workflow-test-{}", Uuid::now_v7());
    let (key, _pkcs8) = Ed25519Key::generate(&key_id).unwrap();
    let public_key = key.public_key();
    let audit_storage_init = PgAuditStorage::new(cp.clone(), None);
    audit_storage_init
        .register_signing_key(&key_id, &public_key, "ed25519", chrono::Utc::now())
        .await
        .unwrap();
    let signer: Arc<dyn SigningKey> = Arc::new(key);
    let audit_storage = Arc::new(PgAuditStorage::new(cp.clone(), Some(signer)));
    let audit = Arc::new(AuditLog::new(audit_storage));

    // Insert a test-specific Cedar policy that permits
    // system_administrator to perform any workflow transition.
    // Done via an upsert so the test is idempotent across reruns.
    sqlx::query(
        r#"
        INSERT INTO policy_rules (name, description, policy_text, priority)
        VALUES ('test_workflow_admin_permit',
                'Test-only: system_administrator can run any transition',
                'permit (principal in Role::"system_administrator", action, resource);',
                5)
        ON CONFLICT (name) DO NOTHING
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let policy_store = Arc::new(PgPolicyStore::new(pool.clone()));
    let policy = Arc::new(PolicyService::load(policy_store).await.unwrap());

    let wf_store: Arc<dyn WorkflowStore> = Arc::new(PgWorkflowStore::new(pool.clone()));
    let mut engine = WorkflowEngine::new(wf_store.clone(), audit.clone(), policy.clone());

    // Register the test CR state machine. Four states, a happy
    // path and a reject branch. This exercises both a normal
    // advance and an invalid-transition rejection.
    let cr = StateMachine::new("test_cr")
        .state("draft")
        .state("submitted")
        .state("approved")
        .state("rejected")
        .initial("draft")
        .terminal("approved")
        .terminal("rejected")
        .transition("submit", "draft", "submitted")
        .transition("approve", "submitted", "approved")
        .transition("reject", "submitted", "rejected")
        .build();
    engine.register_machine(cr);

    // Find a real user to act as the creator. If there is no user
    // in the DB, insert one so the foreign keys are satisfied.
    let user_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM users ORDER BY created_at ASC LIMIT 1",
    )
    .fetch_optional(&pool)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| {
        // Create a synthetic test user synchronously via a blocking
        // handle so setup stays simple.
        Uuid::new_v4()
    });

    // If we just made up a UUID, actually insert that user so FKs work.
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    if !exists {
        sqlx::query(
            "INSERT INTO users (id, company_id, username, email, password_hash, full_name)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(user_id)
        .bind(SYSTEM_COMPANY_ID)
        .bind(format!("wf_test_{}", &user_id.to_string()[..8]))
        .bind(format!("wf_test_{}@example.com", &user_id.to_string()[..8]))
        .bind("$argon2id$v=19$m=4096,t=3,p=1$test$test") // placeholder hash, never used for login
        .bind("Workflow Test User")
        .execute(&pool)
        .await
        .unwrap();
    }

    Some((wf_store, Arc::new(engine), pool, user_id))
}

fn test_principal(user_id: Uuid) -> PolicyPrincipal {
    PolicyPrincipal {
        user_id,
        username: "wf_test".into(),
        company_id: SYSTEM_COMPANY_ID,
        roles: vec!["system_administrator".into()],
    }
}

#[tokio::test]
async fn create_and_transition_through_happy_path() {
    let Some((store, engine, pool, user_id)) = setup().await else {
        return;
    };

    // Create a fresh instance in the initial state.
    let instance = engine
        .create_instance(
            &"test_cr".into(),
            SYSTEM_COMPANY_ID,
            user_id,
            json!({ "title": "Replace transformer TX-01-MAIN" }),
        )
        .await
        .unwrap();
    assert_eq!(instance.current_state, "draft");
    assert_eq!(instance.workflow_type.as_str(), "test_cr");

    let id = instance.id;

    // draft → submitted
    let outcome = engine
        .transition(
            id,
            "submit",
            TransitionContext {
                actor: test_principal(user_id),
                context: json!({"note": "ready for review"}),
            },
        )
        .await
        .unwrap();
    assert_eq!(outcome.from_state, "draft");
    assert_eq!(outcome.to_state, "submitted");
    assert_eq!(outcome.instance.current_state, "submitted");

    // submitted → approved
    let outcome = engine
        .transition(
            id,
            "approve",
            TransitionContext {
                actor: test_principal(user_id),
                context: json!({"approver_notes": "looks good"}),
            },
        )
        .await
        .unwrap();
    assert_eq!(outcome.from_state, "submitted");
    assert_eq!(outcome.to_state, "approved");

    // Persisted state reflects the final transition.
    let reloaded = store.get_instance(id).await.unwrap();
    assert_eq!(reloaded.current_state, "approved");

    // History has both transitions in order.
    let history = store.get_transitions(id).await.unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].transition_name, "submit");
    assert_eq!(history[0].from_state, "draft");
    assert_eq!(history[0].to_state, "submitted");
    assert_eq!(history[1].transition_name, "approve");
    assert_eq!(history[1].from_state, "submitted");
    assert_eq!(history[1].to_state, "approved");

    // Each history row references an audit_log entry. That's the
    // compliance guarantee: the workflow row links back to a
    // tamper-evident chained audit entry.
    for t in &history {
        assert!(t.audit_entry_id.is_some(), "every transition must write an audit entry");
        let audit_row = sqlx::query(
            "SELECT action, resource_type, resource_id FROM audit_log WHERE id = $1",
        )
        .bind(t.audit_entry_id.unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
        let action: String = audit_row.get("action");
        assert_eq!(action, "workflow_transition");
    }
}

#[tokio::test]
async fn invalid_transition_from_wrong_state_is_rejected() {
    let Some((_store, engine, _pool, user_id)) = setup().await else {
        return;
    };

    let instance = engine
        .create_instance(&"test_cr".into(), SYSTEM_COMPANY_ID, user_id, json!({}))
        .await
        .unwrap();

    // Try to approve directly from draft — not a legal edge
    // (approve is only valid from submitted).
    let result = engine
        .transition(
            instance.id,
            "approve",
            TransitionContext {
                actor: test_principal(user_id),
                context: json!({}),
            },
        )
        .await;
    match result {
        Err(WorkflowError::InvalidTransition {
            from_state, transition, ..
        }) => {
            assert_eq!(from_state, "draft");
            assert_eq!(transition, "approve");
        }
        other => panic!("expected InvalidTransition, got {other:?}"),
    }
}

#[tokio::test]
async fn unknown_transition_name_is_rejected() {
    let Some((_store, engine, _pool, user_id)) = setup().await else {
        return;
    };

    let instance = engine
        .create_instance(&"test_cr".into(), SYSTEM_COMPANY_ID, user_id, json!({}))
        .await
        .unwrap();

    let result = engine
        .transition(
            instance.id,
            "time_travel",
            TransitionContext {
                actor: test_principal(user_id),
                context: json!({}),
            },
        )
        .await;
    assert!(
        matches!(result, Err(WorkflowError::UnknownTransition { .. })),
        "expected UnknownTransition, got {result:?}"
    );
}

#[tokio::test]
async fn worm_triggers_block_history_mutation() {
    let Some((_store, engine, pool, user_id)) = setup().await else {
        return;
    };

    let instance = engine
        .create_instance(&"test_cr".into(), SYSTEM_COMPANY_ID, user_id, json!({}))
        .await
        .unwrap();

    engine
        .transition(
            instance.id,
            "submit",
            TransitionContext {
                actor: test_principal(user_id),
                context: json!({}),
            },
        )
        .await
        .unwrap();

    // Attempt to UPDATE a history row. Must be blocked by the WORM
    // trigger installed in migration 116.
    let err = sqlx::query(
        "UPDATE workflow_transitions SET to_state = 'tampered' WHERE instance_id = $1",
    )
    .bind(instance.id.0)
    .execute(&pool)
    .await
    .expect_err("UPDATE must be blocked by WORM trigger");
    let msg = err.to_string();
    assert!(
        msg.contains("WORM") || msg.contains("append-only"),
        "unexpected error: {msg}"
    );

    // Attempt to DELETE — same WORM block.
    let err = sqlx::query("DELETE FROM workflow_transitions WHERE instance_id = $1")
        .bind(instance.id.0)
        .execute(&pool)
        .await
        .expect_err("DELETE must be blocked by WORM trigger");
    let msg = err.to_string();
    assert!(
        msg.contains("WORM") || msg.contains("append-only"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn list_instances_filters_by_state() {
    let Some((store, engine, _pool, user_id)) = setup().await else {
        return;
    };

    // Create three instances; advance two through submit so they
    // end up in different states.
    let i1 = engine
        .create_instance(&"test_cr".into(), SYSTEM_COMPANY_ID, user_id, json!({}))
        .await
        .unwrap();
    let i2 = engine
        .create_instance(&"test_cr".into(), SYSTEM_COMPANY_ID, user_id, json!({}))
        .await
        .unwrap();
    let i3 = engine
        .create_instance(&"test_cr".into(), SYSTEM_COMPANY_ID, user_id, json!({}))
        .await
        .unwrap();

    engine
        .transition(i2.id, "submit", TransitionContext {
            actor: test_principal(user_id),
            context: json!({}),
        })
        .await
        .unwrap();
    engine
        .transition(i3.id, "submit", TransitionContext {
            actor: test_principal(user_id),
            context: json!({}),
        })
        .await
        .unwrap();

    // Now list all "draft" — expect i1 at least.
    let drafts = store
        .list_instances(Some(&"test_cr".into()), Some("draft"), None, 100)
        .await
        .unwrap();
    assert!(
        drafts.iter().any(|i| i.id == i1.id),
        "draft list should contain i1"
    );
    // And list "submitted" — expect i2 and i3.
    let submitted = store
        .list_instances(Some(&"test_cr".into()), Some("submitted"), None, 100)
        .await
        .unwrap();
    let ids: std::collections::HashSet<InstanceId> = submitted.iter().map(|i| i.id).collect();
    assert!(ids.contains(&i2.id) && ids.contains(&i3.id));
}
