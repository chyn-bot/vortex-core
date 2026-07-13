//! Blueprint DDL mechanics — integration test.
//!
//! Exercises the real runtime-DDL path (`vortex_orm::blueprint`) against a
//! Postgres DB with migrations through `145_blueprints` applied. Everything
//! runs inside one transaction that is rolled back at the end, so the test
//! leaves no residue (Postgres DDL is transactional).
//!
//! Skips silently unless `BLUEPRINT_TEST_DATABASE_URL` is set, so `cargo test`
//! and CI stay green without a database. Run it with e.g.:
//!
//!   BLUEPRINT_TEST_DATABASE_URL=postgres://vortex:vortex@localhost/acc_dev \
//!     cargo test -p vortex-orm --test blueprint_ddl -- --nocapture

use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;
use vortex_orm::blueprint;

async fn pool() -> Option<PgPool> {
    let url = std::env::var("BLUEPRINT_TEST_DATABASE_URL").ok()?;
    PgPool::connect(&url).await.ok()
}

#[tokio::test]
async fn ddl_lifecycle_creates_alters_and_logs() {
    let Some(db) = pool().await else {
        eprintln!("BLUEPRINT_TEST_DATABASE_URL not set — skipping blueprint DDL test");
        return;
    };
    let mut tx = db.begin().await.expect("begin tx");

    let table = "x_bp_ddl_test";

    // Seed an ir_model + blueprint row so the blueprint_ddl_log FK is satisfiable.
    let model_id: Uuid = sqlx::query_scalar(
        "INSERT INTO ir_model (name, display_name, table_name, module, source, is_virtual)
         VALUES ($1, $2, $1, 'blueprint', 'blueprint', true)
         ON CONFLICT (name) DO UPDATE SET display_name = EXCLUDED.display_name
         RETURNING id",
    )
    .bind(table)
    .bind("BP DDL Test")
    .fetch_one(&mut *tx)
    .await
    .expect("seed ir_model");

    let blueprint_id: Uuid = sqlx::query_scalar(
        "INSERT INTO blueprint (model_id, status) VALUES ($1, 'draft') RETURNING id",
    )
    .bind(model_id)
    .fetch_one(&mut *tx)
    .await
    .expect("seed blueprint");

    // Create the generated table + two typed columns.
    blueprint::create_model_table(&mut tx, table, blueprint_id)
        .await
        .expect("create table");
    blueprint::add_column(&mut tx, table, "customer_name", "string", blueprint_id)
        .await
        .expect("add string column");
    blueprint::add_column(&mut tx, table, "amount", "decimal", blueprint_id)
        .await
        .expect("add decimal column");

    // Insert a real row through the generated columns — proves they're first-class.
    sqlx::query(&format!(
        "INSERT INTO {table} (customer_name, amount) VALUES ($1, $2)"
    ))
    .bind("Acme")
    .bind(Decimal::new(199, 2)) // 1.99
    .execute(&mut *tx)
    .await
    .expect("insert data row");

    let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(&mut *tx)
        .await
        .expect("count rows");
    assert_eq!(count, 1, "the generated table stores real rows");

    // A protected system column can never be added or dropped.
    assert!(
        blueprint::add_column(&mut tx, table, "id", "uuid", blueprint_id)
            .await
            .is_err(),
        "system column must be rejected"
    );

    // Rename + drop a user column.
    blueprint::rename_column(&mut tx, table, "customer_name", "client_name", blueprint_id)
        .await
        .expect("rename column");
    blueprint::drop_column(&mut tx, table, "amount", blueprint_id)
        .await
        .expect("drop column");

    // The DDL ledger captured: create + 2 adds + rename + drop = 5 statements.
    let logged: i64 =
        sqlx::query_scalar("SELECT count(*) FROM blueprint_ddl_log WHERE blueprint_id = $1")
            .bind(blueprint_id)
            .fetch_one(&mut *tx)
            .await
            .expect("count ddl log");
    assert_eq!(logged, 5, "every executed DDL statement is logged");

    blueprint::drop_model_table(&mut tx, table, blueprint_id)
        .await
        .expect("drop table");

    // Leave no residue.
    tx.rollback().await.expect("rollback");
}
