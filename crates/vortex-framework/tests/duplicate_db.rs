//! End-to-end test of the record-duplication primitive against a live
//! Postgres database.
//!
//! Skipped unless `DUP_TEST_DATABASE_URL` is set. The test creates and
//! drops its own scratch tables, so any database the role can write to
//! works:
//!
//! ```sh
//! DUP_TEST_DATABASE_URL=postgres://vortex:…@localhost/vortex \
//!     cargo test -p vortex-framework --test duplicate_db
//! ```
//!
//! Covers: parent copy with skip/set/copy_suffix and created_by
//! stamping, child-line cloning with FK re-pointing and counter resets,
//! the missing-source error, and transactional atomicity (a failing
//! child clone must roll the parent back).

use serde_json::json;
use sqlx::{PgPool, Row};
use uuid::Uuid;
use vortex_framework::{ChildCopy, DuplicateSpec};

async fn setup() -> Option<PgPool> {
    let Ok(url) = std::env::var("DUP_TEST_DATABASE_URL") else {
        eprintln!("DUP_TEST_DATABASE_URL not set — skipping duplicate primitive test");
        return None;
    };
    let db = PgPool::connect(&url).await.expect("connect");
    sqlx::query("DROP TABLE IF EXISTS dup_test_line, dup_test_doc")
        .execute(&db)
        .await
        .expect("drop scratch tables");
    sqlx::query(
        "CREATE TABLE dup_test_doc (
             id UUID PRIMARY KEY,
             name TEXT NOT NULL,
             number VARCHAR(32) UNIQUE,
             state VARCHAR(16) NOT NULL DEFAULT 'draft',
             total NUMERIC(14,2) NOT NULL DEFAULT 0,
             created_by UUID,
             created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
             updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
         )",
    )
    .execute(&db)
    .await
    .expect("create parent");
    sqlx::query(
        "CREATE TABLE dup_test_line (
             id UUID PRIMARY KEY,
             doc_id UUID NOT NULL REFERENCES dup_test_doc(id),
             qty NUMERIC(12,3) NOT NULL,
             delivered NUMERIC(12,3) NOT NULL DEFAULT 0
         )",
    )
    .execute(&db)
    .await
    .expect("create child");
    Some(db)
}

async fn teardown(db: &PgPool) {
    let _ = sqlx::query("DROP TABLE IF EXISTS dup_test_line, dup_test_doc")
        .execute(db)
        .await;
}

#[tokio::test]
async fn duplicate_lifecycle() {
    let Some(db) = setup().await else { return };

    let src = Uuid::now_v7();
    let author = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dup_test_doc (id, name, number, state, total, created_by)
         VALUES ($1, 'Widget order', 'DOC/001', 'done', 99.50, $2)",
    )
    .bind(src)
    .bind(author)
    .execute(&db)
    .await
    .unwrap();
    for qty in [2, 5] {
        sqlx::query(
            "INSERT INTO dup_test_line (id, doc_id, qty, delivered) VALUES ($1, $2, $3, $3)",
        )
        .bind(Uuid::now_v7())
        .bind(src)
        .bind(qty)
        .execute(&db)
        .await
        .unwrap();
    }

    // ── The canonical document duplicate ──────────────────────────────
    let duplicator = Uuid::now_v7();
    let new_id = DuplicateSpec::new("dup_test_doc")
        .set("number", json!("DOC/002"))
        .skip("state") // back to DB default 'draft'
        .skip("total") // recomputed by the adopting module
        .copy_suffix("name")
        .child(ChildCopy::new("dup_test_line", "doc_id").set("delivered", json!(0)))
        .execute(&db, src, Some(duplicator))
        .await
        .expect("duplicate should succeed");
    assert_ne!(new_id, src);

    let copy = sqlx::query(
        "SELECT name, number, state, total::text AS total, created_by
         FROM dup_test_doc WHERE id = $1",
    )
    .bind(new_id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(copy.get::<String, _>("name"), "Widget order (copy)");
    assert_eq!(copy.get::<Option<String>, _>("number").as_deref(), Some("DOC/002"));
    assert_eq!(copy.get::<String, _>("state"), "draft");
    assert_eq!(copy.get::<String, _>("total"), "0.00");
    assert_eq!(copy.get::<Option<Uuid>, _>("created_by"), Some(duplicator));

    let lines: Vec<(String, String)> = sqlx::query(
        "SELECT qty::text AS qty, delivered::text AS delivered
         FROM dup_test_line WHERE doc_id = $1 ORDER BY qty",
    )
    .bind(new_id)
    .fetch_all(&db)
    .await
    .unwrap()
    .iter()
    .map(|r| (r.get("qty"), r.get("delivered")))
    .collect();
    assert_eq!(
        lines,
        vec![
            ("2.000".to_string(), "0.000".to_string()),
            ("5.000".to_string(), "0.000".to_string()),
        ],
        "lines must clone with fulfilment counters reset"
    );
    // Source untouched.
    let src_lines: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dup_test_line WHERE doc_id = $1")
            .bind(src)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(src_lines, 2);

    // ── Missing source is a clean error ───────────────────────────────
    let err = DuplicateSpec::new("dup_test_doc")
        .execute(&db, Uuid::now_v7(), None)
        .await
        .unwrap_err();
    assert_eq!(err, "source record not found");

    // ── Unique collision rolls back atomically (verbatim number copy) ─
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dup_test_doc")
        .fetch_one(&db)
        .await
        .unwrap();
    DuplicateSpec::new("dup_test_doc")
        .child(ChildCopy::new("dup_test_line", "doc_id"))
        .execute(&db, src, None)
        .await
        .expect_err("copying a UNIQUE number verbatim must fail");
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dup_test_doc")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(before, after, "failed duplicate must leave no partial rows");

    teardown(&db).await;
}
