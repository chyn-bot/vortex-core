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

async fn setup() -> Option<(ConnectionPool, Arc<RecordCache>)> {
    let url = std::env::var("CACHE_TEST_DATABASE_URL").ok()?;
    let pg = sqlx::PgPool::connect(&url).await.ok()?;
    sqlx::query(&format!("DROP TABLE IF EXISTS {TABLE}"))
        .execute(&pg)
        .await
        .ok()?;
    sqlx::query(&format!(
        "CREATE TABLE {TABLE} (id uuid PRIMARY KEY, name text NOT NULL)"
    ))
    .execute(&pg)
    .await
    .ok()?;

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

    // Seed a row directly (bypass the cache).
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

    // Clean up.
    sqlx::query(&format!("DROP TABLE IF EXISTS {TABLE}"))
        .execute(pool.pool())
        .await
        .ok();
}
