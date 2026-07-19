//! Keyset (cursor) pagination — integration test.
//!
//! Proves the keyset path returns the *exact same sequence* as OFFSET over real
//! data — no skipped or duplicated rows — including across duplicate sort values
//! (which exercises the `id` tiebreaker), and that backward (`before`) nav
//! round-trips. Runs the real `execute_list` against Postgres.
//!
//! Skipped unless `LIST_TEST_DATABASE_URL` (or `CACHE_TEST_DATABASE_URL`) is
//! set, so `cargo test` and CI stay green without a database. Run with:
//!
//!   CACHE_TEST_DATABASE_URL=postgres://remicle:remicle_dev_2026@localhost/remicle \
//!     cargo test -p vortex-framework --test list_keyset -- --nocapture

use sqlx::{PgPool, Row};
use uuid::Uuid;

use vortex_framework::list::{execute_list, ListColumn, ListConfig, ListParams};

const TABLE: &str = "x_keyset_test";
const N: i64 = 1000;
const PAGE: u64 = 10;

fn base_config() -> ListConfig {
    ListConfig::new("Keyset", TABLE)
        .column(ListColumn::new("name", "Name").sortable().searchable())
        .default_sort("name")
}

async fn setup() -> Option<PgPool> {
    let url = std::env::var("LIST_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("CACHE_TEST_DATABASE_URL"))
        .ok()?;
    let db = PgPool::connect(&url).await.ok()?;
    sqlx::query(&format!("DROP TABLE IF EXISTS {TABLE}")).execute(&db).await.ok()?;
    sqlx::query(&format!(
        "CREATE TABLE {TABLE} (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL)"
    ))
    .execute(&db)
    .await
    .ok()?;
    // Deliberately duplicate names (50 distinct values over 1000 rows) so many
    // rows share a sort key — the case where a missing id tiebreaker would make
    // keyset skip or repeat rows at page boundaries.
    sqlx::query(&format!(
        "INSERT INTO {TABLE} (name) SELECT 'n' || (g % 50) FROM generate_series(1, {N}) g"
    ))
    .execute(&db)
    .await
    .ok()?;
    Some(db)
}

async fn ids_via_offset(db: &PgPool) -> Vec<Uuid> {
    let config = base_config(); // no keyset → OFFSET path
    let mut ids = Vec::new();
    let mut page = 1u64;
    loop {
        let params = ListParams { page, page_size: PAGE, ..ListParams::default() };
        let res = execute_list(db, &config, &params).await.expect("offset page");
        if res.rows.is_empty() {
            break;
        }
        for row in &res.rows {
            ids.push(row.try_get::<Uuid, _>("id").unwrap());
        }
        page += 1;
        if page > (N as u64 / PAGE) + 2 {
            break; // safety
        }
    }
    ids
}

async fn ids_via_keyset_forward(db: &PgPool) -> Vec<Uuid> {
    let config = base_config().keyset();
    let mut ids = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..(N as usize / PAGE as usize + 4) {
        let params = ListParams { page_size: PAGE, after: after.clone(), ..ListParams::default() };
        let res = execute_list(db, &config, &params).await.expect("keyset page");
        assert!(res.is_keyset(), "config opted into keyset");
        for row in &res.rows {
            ids.push(row.try_get::<Uuid, _>("id").unwrap());
        }
        match res.next_cursor {
            Some(c) => after = Some(c),
            None => break,
        }
    }
    ids
}

#[tokio::test]
async fn keyset_matches_offset_and_navigates_back() {
    let Some(db) = setup().await else {
        eprintln!("no *_TEST_DATABASE_URL — skipping keyset test");
        return;
    };

    let offset_ids = ids_via_offset(&db).await;
    let keyset_ids = ids_via_keyset_forward(&db).await;

    assert_eq!(offset_ids.len(), N as usize, "offset should visit every row once");
    assert_eq!(
        keyset_ids, offset_ids,
        "keyset must yield the identical sequence to OFFSET (order, no gaps, no dupes)"
    );
    // No duplicates anywhere in the keyset traversal.
    let unique: std::collections::HashSet<_> = keyset_ids.iter().collect();
    assert_eq!(unique.len(), keyset_ids.len(), "keyset repeated a row");

    // ── Backward navigation round-trips ──
    // Page forward twice to land on page 3, capture it, then use its prev_cursor
    // to walk back to page 2 and confirm it equals the forward page 2.
    let config = base_config().keyset();

    let p1 = execute_list(&db, &config, &ListParams { page_size: PAGE, ..ListParams::default() })
        .await
        .unwrap();
    let p2 = execute_list(
        &db,
        &config,
        &ListParams { page_size: PAGE, after: p1.next_cursor.clone(), ..ListParams::default() },
    )
    .await
    .unwrap();
    let p2_ids: Vec<Uuid> = p2.rows.iter().map(|r| r.try_get::<Uuid, _>("id").unwrap()).collect();
    let p3 = execute_list(
        &db,
        &config,
        &ListParams { page_size: PAGE, after: p2.next_cursor.clone(), ..ListParams::default() },
    )
    .await
    .unwrap();

    // Walk back from page 3 using its prev cursor.
    let back = execute_list(
        &db,
        &config,
        &ListParams { page_size: PAGE, before: p3.prev_cursor.clone(), ..ListParams::default() },
    )
    .await
    .unwrap();
    let back_ids: Vec<Uuid> = back.rows.iter().map(|r| r.try_get::<Uuid, _>("id").unwrap()).collect();
    assert_eq!(back_ids, p2_ids, "before-cursor from page 3 must reproduce page 2 in order");
    assert!(back.next_cursor.is_some(), "page 2 reached via 'before' still has a Next");

    sqlx::query(&format!("DROP TABLE IF EXISTS {TABLE}")).execute(&db).await.ok();
}
