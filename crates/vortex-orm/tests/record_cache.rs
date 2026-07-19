//! Record cache (Grid) read-through + invalidation — integration test.
//!
//! Proves the ORM read/write path actually consults the process-local
//! `RecordCache`: a `find` populates it, a second `find` is served hot, and a
//! `save`/`delete` invalidates it so no stale copy outlives the write. Runs the
//! real `ModelExt::{find,save,delete}` against Postgres.
//!
//! Skips silently unless `CACHE_TEST_DATABASE_URL` is set, so `cargo test` and
//! CI stay green without a database. Run it with e.g.:
//!
//!   CACHE_TEST_DATABASE_URL=postgres://remicle:remicle_dev_2026@localhost/remicle \
//!     cargo test -p vortex-orm --test record_cache -- --nocapture

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_common::{CompanyId, Context, FieldValue, VortexResult};
use vortex_orm::cache::{CacheConfig, RecordCache};
use vortex_orm::connection::ConnectionPool;
use vortex_orm::field::{FieldDef, FieldType};
use vortex_orm::model::{Model, ModelExt, ModelMeta};

const TABLE: &str = "x_cache_rec_test";
const MODEL: &str = "CacheRec";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheRec {
    id: Uuid,
    name: String,
}

fn meta_cell() -> &'static ModelMeta {
    static META: OnceLock<ModelMeta> = OnceLock::new();
    META.get_or_init(|| {
        // Plain (non-tenant, non-soft-delete, non-audited) so the table is just
        // (id, name) and the SELECT/INSERT the ORM builds matches it exactly.
        let mut m = ModelMeta::new(MODEL, TABLE);
        m.multi_tenant = false;
        m.soft_delete = false;
        m.audited = false;
        m.primary_key = "id".to_string();
        m.add_field(FieldDef::new("id", FieldType::Uuid).primary_key());
        m.add_field(FieldDef::new("name", FieldType::Text).required());
        m
    })
}

#[async_trait::async_trait]
impl Model for CacheRec {
    fn meta() -> &'static ModelMeta {
        meta_cell()
    }
    fn pk(&self) -> FieldValue {
        FieldValue::Uuid(self.id)
    }
    fn company_id(&self) -> Option<CompanyId> {
        None
    }
    fn to_values(&self) -> HashMap<String, FieldValue> {
        let mut v = HashMap::new();
        v.insert("id".to_string(), FieldValue::Uuid(self.id));
        v.insert("name".to_string(), FieldValue::String(self.name.clone()));
        v
    }
    fn from_values(values: HashMap<String, FieldValue>) -> VortexResult<Self> {
        let id = match values.get("id") {
            Some(FieldValue::Uuid(u)) => *u,
            Some(FieldValue::String(s)) => Uuid::parse_str(s).unwrap_or_default(),
            _ => Uuid::nil(),
        };
        let name = match values.get("name") {
            Some(FieldValue::String(s)) => s.clone(),
            _ => String::new(),
        };
        Ok(CacheRec { id, name })
    }
}

async fn ensure_table(pg: &sqlx::PgPool) {
    // Shared, idempotent table so the two integration tests can run in parallel
    // (each owns a distinct row id) without racing a DROP/CREATE. Serialize the
    // DDL through a process-local lock — concurrent `CREATE TABLE IF NOT EXISTS`
    // can still collide on the Postgres system catalog.
    static DDL_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    let _guard = DDL_LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS {TABLE} (id uuid PRIMARY KEY, name text NOT NULL)"
    ))
    .execute(pg)
    .await
    .expect("ensure table");
}

async fn setup() -> Option<(ConnectionPool, Arc<RecordCache>)> {
    let url = std::env::var("CACHE_TEST_DATABASE_URL").ok()?;
    let pg = sqlx::PgPool::connect(&url).await.ok()?;
    ensure_table(&pg).await;

    let mut cfg = CacheConfig::default();
    cfg.models = [MODEL.to_string()].into_iter().collect();
    let cache = Arc::new(RecordCache::new(cfg));
    let pool = ConnectionPool::from_pg_pool(pg, &url).with_cache(cache.clone());
    Some((pool, cache))
}

#[tokio::test]
async fn read_through_populates_and_writes_invalidate() {
    let Some((pool, cache)) = setup().await else {
        eprintln!("CACHE_TEST_DATABASE_URL not set — skipping record cache test");
        return;
    };
    let ctx = Context::system();
    let id = Uuid::from_u128(0x1234_5678);

    // Seed a row directly (bypass the cache). Clear any residue from a prior run.
    sqlx::query(&format!("DELETE FROM {TABLE} WHERE id = $1"))
        .bind(id)
        .execute(pool.pool())
        .await
        .ok();
    sqlx::query(&format!("INSERT INTO {TABLE} (id, name) VALUES ($1, 'v1')"))
        .bind(id)
        .execute(pool.pool())
        .await
        .expect("seed row");

    // find #1 — cold: cache miss, hits the DB, populates.
    let r1 = CacheRec::find(&pool, &ctx, FieldValue::Uuid(id))
        .await
        .expect("find1")
        .expect("row exists");
    assert_eq!(r1.name, "v1");

    // find #2 — hot: served from cache (hit count increments).
    let r2 = CacheRec::find(&pool, &ctx, FieldValue::Uuid(id))
        .await
        .expect("find2")
        .expect("row exists");
    assert_eq!(r2.name, "v1");
    assert_eq!(cache.stats().await.hits, 1, "second find must be a cache hit");

    // Mutate the row *underneath* the cache (raw SQL). The cache still serves
    // the old value — proving reads really come from the cache.
    sqlx::query(&format!("UPDATE {TABLE} SET name = 'v2-raw' WHERE id = $1"))
        .bind(id)
        .execute(pool.pool())
        .await
        .expect("raw update");
    let r3 = CacheRec::find(&pool, &ctx, FieldValue::Uuid(id))
        .await
        .expect("find3")
        .expect("row exists");
    assert_eq!(r3.name, "v1", "cache should still serve the pre-update value");

    // A save() through the ORM must invalidate, so the next read is fresh.
    let mut rec = CacheRec { id, name: "v3".to_string() };
    rec.save(&pool, &ctx).await.expect("save");
    let r4 = CacheRec::find(&pool, &ctx, FieldValue::Uuid(id))
        .await
        .expect("find4")
        .expect("row exists");
    assert_eq!(r4.name, "v3", "save must invalidate — next read reflects the write");

    // delete() must invalidate too — the record is gone from cache and DB.
    rec.delete(&pool, &ctx).await.expect("delete");
    let r5 = CacheRec::find(&pool, &ctx, FieldValue::Uuid(id))
        .await
        .expect("find5");
    assert!(r5.is_none(), "deleted record must not be served from cache");
    // The row was removed by delete(); leave the shared table in place for the
    // sibling test (they own disjoint row ids).
}

/// Two `ConnectionPool`s on the same database stand in for two app instances.
/// A write through instance A must invalidate instance B's cache via the
/// Postgres `LISTEN/NOTIFY` broadcast — otherwise B would serve a stale row.
#[tokio::test]
async fn write_on_one_instance_invalidates_another() {
    let Some(url) = std::env::var("CACHE_TEST_DATABASE_URL").ok() else {
        eprintln!("CACHE_TEST_DATABASE_URL not set — skipping cross-process cache test");
        return;
    };
    let admin = sqlx::PgPool::connect(&url).await.expect("connect");
    ensure_table(&admin).await;

    let make_instance = || async {
        let pg = sqlx::PgPool::connect(&url).await.expect("connect");
        let mut cfg = CacheConfig::default();
        cfg.models = [MODEL.to_string()].into_iter().collect();
        let cache = Arc::new(RecordCache::new(cfg));
        let pool = ConnectionPool::from_pg_pool(pg, &url).with_cache(cache.clone());
        pool.spawn_cache_listener();
        (pool, cache)
    };
    let (pool_a, _cache_a) = make_instance().await;
    let (pool_b, cache_b) = make_instance().await;

    // Give both listeners a moment to establish their LISTEN.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let ctx = Context::system();
    let id = Uuid::from_u128(0xABCD_EF01);

    // Seed + prime instance B's cache with "v1" (clear residue first).
    sqlx::query(&format!("DELETE FROM {TABLE} WHERE id = $1"))
        .bind(id)
        .execute(&admin)
        .await
        .ok();
    sqlx::query(&format!("INSERT INTO {TABLE} (id, name) VALUES ($1, 'v1')"))
        .bind(id)
        .execute(pool_b.pool())
        .await
        .expect("seed");
    let b1 = CacheRec::find(&pool_b, &ctx, FieldValue::Uuid(id))
        .await
        .expect("b find1")
        .expect("exists");
    assert_eq!(b1.name, "v1");
    assert_eq!(cache_b.size().await, 1, "B should have cached the row");

    // Instance A writes "v2" — this invalidates A locally and broadcasts.
    let mut rec = CacheRec { id, name: "v2".to_string() };
    rec.save(&pool_a, &ctx).await.expect("a save");

    // Instance B must observe the write after its listener applies the
    // broadcast invalidation. Poll B's find until it reflects "v2".
    let mut observed = String::new();
    for _ in 0..50 {
        let b = CacheRec::find(&pool_b, &ctx, FieldValue::Uuid(id))
            .await
            .expect("b find")
            .expect("exists");
        observed = b.name.clone();
        if observed == "v2" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        observed, "v2",
        "instance B must see instance A's write via cross-process invalidation"
    );

    // Clean up just our row; leave the shared table for the sibling test.
    sqlx::query(&format!("DELETE FROM {TABLE} WHERE id = $1"))
        .bind(id)
        .execute(&admin)
        .await
        .ok();
}
