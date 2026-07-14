//! End-to-end test of the Vortex Intake quarantine triage path
//! (`approve_submission` / `reject_submission`) against a live Postgres DB.
//!
//! The admin approve/reject HTTP handlers require an authenticated admin
//! session, which the harness can't forge, so this test drives the governed
//! service functions directly — the exact code those handlers call — proving
//! that approving a held submission replays its captured payload into a real
//! record (via the same catalog-typed write the public path uses) and settles
//! the ledger, while rejecting writes no record. Both emit a WORM audit entry,
//! so a real `AuditLog` (backed by the DB chain) is wired in.
//!
//! Skipped unless `INTAKE_TEST_DATABASE_URL` points at a DB with migrations
//! through 149 applied, so CI without Postgres stays green:
//!
//! ```sh
//! INTAKE_TEST_DATABASE_URL=postgres://vortex:vortex@localhost:5432/acc_dev \
//!     cargo test -p vortex-framework --test intake_triage
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;

use sqlx::{PgPool, Row};
use uuid::Uuid;
use vortex_orm::connection::{ConnectionPool, DatabaseConfig};
use vortex_security::audit::PgAuditStorage;
use vortex_security::AuditLog;

const TARGET_TABLE: &str = "intake_test_target";
const MODEL: &str = "x_intake_triage_test";
const SLUG: &str = "intake-triage-test";

struct Harness {
    pool: PgPool,
    audit: AuditLog,
    reviewer: Uuid,
}

async fn setup() -> Option<Harness> {
    let Ok(url) = std::env::var("INTAKE_TEST_DATABASE_URL") else {
        eprintln!("INTAKE_TEST_DATABASE_URL not set — skipping intake triage test");
        return None;
    };
    let pool = PgPool::connect(&url).await.expect("connect");

    // Clean any prior run (submissions cascade from web_form).
    sqlx::query("DELETE FROM web_form WHERE slug = $1").bind(SLUG).execute(&pool).await.ok();
    sqlx::query("DELETE FROM ir_attachment WHERE res_model = $1").bind(MODEL).execute(&pool).await.ok();
    sqlx::query("DELETE FROM ir_model WHERE name = $1").bind(MODEL).execute(&pool).await.ok();
    sqlx::query(&format!("DROP TABLE IF EXISTS {TARGET_TABLE}")).execute(&pool).await.ok();

    // A self-contained target model: a physical table + its ir_model row.
    sqlx::query(&format!(
        "CREATE TABLE {TARGET_TABLE} (
             id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
             company_id UUID,
             partner_id UUID,
             created_by UUID,
             name VARCHAR(255),
             active BOOLEAN NOT NULL DEFAULT true,
             created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
             updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
         )"
    ))
    .execute(&pool)
    .await
    .expect("create target table");
    sqlx::query(
        "INSERT INTO ir_model (name, display_name, table_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(MODEL)
    .bind("Intake Triage Test")
    .bind(TARGET_TABLE)
    .execute(&pool)
    .await
    .expect("insert ir_model");

    // A quarantine form exposing a single field.
    sqlx::query(
        "INSERT INTO web_form (slug, model, title, fields, settings, active)
         VALUES ($1, $2, $3, $4, $5, true)",
    )
    .bind(SLUG)
    .bind(MODEL)
    .bind("Triage Test")
    .bind(serde_json::json!([{"name":"name","label":"Name","required":true}]))
    // partner_field set so approval also exercises portal owner stamping.
    .bind(serde_json::json!({"quarantine": true, "partner_field": "partner_id"}))
    .execute(&pool)
    .await
    .expect("insert web_form");

    // A real user for the reviewer FK (reviewed_by / audit user_id).
    let reviewer: Uuid = sqlx::query_scalar("SELECT id FROM users ORDER BY created_at LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("need at least one user in the DB");

    // A real AuditLog backed by the DB WORM chain.
    let cfg = DatabaseConfig { url, max_connections: 3, ..Default::default() };
    let cpool = Arc::new(ConnectionPool::new(cfg).await.expect("connection pool"));
    let audit = AuditLog::new(Arc::new(PgAuditStorage::new(cpool, None)));

    Some(Harness { pool, audit, reviewer })
}

async fn form_id(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM web_form WHERE slug = $1")
        .bind(SLUG)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Insert a quarantined submission carrying `payload` + optional actor + held
/// attachments, return its id.
async fn quarantined(
    pool: &PgPool,
    name: &str,
    partner_id: Option<Uuid>,
    submitted_by: Option<Uuid>,
    attachments: &[vortex_framework::intake::StoredUpload],
) -> Uuid {
    let fid = form_id(pool).await;
    let mut payload = BTreeMap::new();
    payload.insert("name".to_string(), name.to_string());
    sqlx::query_scalar(
        "INSERT INTO web_form_submission (form_id, status, payload, partner_id, submitted_by, attachments)
         VALUES ($1, 'quarantined', $2, $3, $4, $5) RETURNING id",
    )
    .bind(fid)
    .bind(serde_json::to_value(&payload).unwrap())
    .bind(partner_id)
    .bind(submitted_by)
    .bind(serde_json::to_value(attachments).unwrap())
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn approve_writes_the_held_record_and_settles_the_ledger() {
    let Some(h) = setup().await else { return };
    // A portal-origin held submission: it carries the partner + submitter, which
    // approval must stamp onto the replayed record (owner stamping).
    let partner = Uuid::from_u128(0xA0);
    // A held attachment that approval must link to the new record.
    let held = vortex_framework::intake::StoredUpload {
        key: "intake/held-blob.pdf".into(),
        name: "held.pdf".into(),
        size: 42,
        mime: "application/pdf".into(),
        checksum: "deadbeef".into(),
    };
    let sub = quarantined(&h.pool, "Approved Row", Some(partner), Some(h.reviewer), &[held]).await;

    let rec = vortex_framework::intake::approve_submission(
        &h.audit, &h.pool, "intake_test", sub, h.reviewer, "tester",
    )
    .await
    .expect("approve should succeed");

    // The held blob is now linked as an ir_attachment on the new record.
    let attach = sqlx::query(
        "SELECT name, store_fname, file_size, created_by FROM ir_attachment
         WHERE res_model = $1 AND res_id = $2",
    )
    .bind(MODEL)
    .bind(rec)
    .fetch_one(&h.pool)
    .await
    .expect("attachment linked on approval");
    assert_eq!(attach.get::<String, _>("name"), "held.pdf");
    assert_eq!(attach.get::<String, _>("store_fname"), "intake/held-blob.pdf");
    assert_eq!(attach.get::<Option<Uuid>, _>("created_by"), Some(h.reviewer));

    // The record now exists in the target table with the captured value AND the
    // owner stamps replayed from the held submission.
    let rrow = sqlx::query(&format!(
        "SELECT name, partner_id, created_by FROM {TARGET_TABLE} WHERE id = $1"
    ))
    .bind(rec)
    .fetch_one(&h.pool)
    .await
    .expect("record written");
    assert_eq!(rrow.get::<String, _>("name"), "Approved Row");
    assert_eq!(rrow.get::<Option<Uuid>, _>("partner_id"), Some(partner), "partner_field stamped");
    assert_eq!(rrow.get::<Option<Uuid>, _>("created_by"), Some(h.reviewer), "created_by stamped");

    // The ledger row is settled: accepted, record linked, reviewer stamped.
    let row = sqlx::query(
        "SELECT status, record_id, reviewed_by, reviewed_at FROM web_form_submission WHERE id = $1",
    )
    .bind(sub)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("status"), "accepted");
    assert_eq!(row.get::<Option<Uuid>, _>("record_id"), Some(rec));
    assert_eq!(row.get::<Option<Uuid>, _>("reviewed_by"), Some(h.reviewer));
    assert!(row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("reviewed_at").is_some());

    // Re-approving a settled submission is refused.
    let again = vortex_framework::intake::approve_submission(
        &h.audit, &h.pool, "intake_test", sub, h.reviewer, "tester",
    )
    .await;
    assert!(again.is_err(), "second approve must be rejected");
}

#[tokio::test]
async fn reject_writes_no_record() {
    let Some(h) = setup().await else { return };
    let sub = quarantined(&h.pool, "Rejected Row", None, None, &[]).await;

    let before: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {TARGET_TABLE}"))
        .fetch_one(&h.pool)
        .await
        .unwrap();

    vortex_framework::intake::reject_submission(
        &h.audit, &h.pool, "intake_test", sub, h.reviewer, "tester",
    )
    .await
    .expect("reject should succeed");

    let after: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {TARGET_TABLE}"))
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(before, after, "reject must write no record");

    let status: String = sqlx::query_scalar("SELECT status FROM web_form_submission WHERE id = $1")
        .bind(sub)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(status, "rejected");

    // Rejecting a non-quarantined row is refused.
    let again = vortex_framework::intake::reject_submission(
        &h.audit, &h.pool, "intake_test", sub, h.reviewer, "tester",
    )
    .await;
    assert!(again.is_err(), "second reject must be refused");
}
