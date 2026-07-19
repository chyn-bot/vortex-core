//! Deterministic snapshot / freeze primitive.
//!
//! *"Freeze every input a computation needs into a versioned snapshot at the
//! start, and read only from the snapshot — never live master data mid-run."*
//! That single discipline is what makes a batch result reproducible and
//! defensible: the same snapshot version plus the same logic always produces the
//! same output, so a bill (or a valuation, or a payroll line) can be recomputed
//! identically months later and reconciled against what actually shipped.
//!
//! It is **core**, not billing. Any computation that must be reproducible wants
//! to read from a freeze rather than from data that moves under it.
//!
//! # Model
//!
//! - A [`SnapshotSet`] is one freeze: a caller `label` plus an auto-assigned,
//!   monotonic `version` (the "snapshot_version" downstream records reference).
//! - Records are frozen into the set with [`freeze`] while it is `open`.
//! - [`seal`] closes it. A sealed set is immutable — there is deliberately no
//!   update or delete path for its records — so it reproduces exactly.
//! - Calculation reads one record with [`get_record`], keyed on the entity.
//!
//! # Composing with the batch engine
//!
//! The two primitives are designed to pair: take a snapshot at run start, put
//! its `set_id`/`version` in the batch run's `params`, and have the
//! [`crate::batch::BatchProcessor`] read each item's inputs from
//! `get_record(set_id, item_key)`. The processor then touches no live data, so
//! the run is deterministic and idempotent by construction.

use serde_json::Value;
use sqlx::postgres::PgPool;
use sqlx::Row;
use uuid::Uuid;

use crate::batch::NewItem; // reuse the same "key + payload" shape for ergonomics

/// A freeze: a labelled, versioned set of frozen records.
#[derive(Debug, Clone)]
pub struct SnapshotSet {
    pub id: Uuid,
    pub label: String,
    pub version: i32,
    pub status: String,
}

impl SnapshotSet {
    /// True once the set is sealed and safe to read deterministically.
    pub fn is_sealed(&self) -> bool {
        self.status == "sealed"
    }
}

/// One record to freeze: the entity it describes and its frozen inputs.
#[derive(Debug, Clone)]
pub struct FrozenRecord {
    pub entity_key: String,
    pub data: Value,
}

impl FrozenRecord {
    pub fn new(entity_key: impl Into<String>, data: Value) -> Self {
        Self {
            entity_key: entity_key.into(),
            data,
        }
    }
}

impl From<NewItem> for FrozenRecord {
    fn from(i: NewItem) -> Self {
        FrozenRecord {
            entity_key: i.item_key,
            data: i.payload,
        }
    }
}

/// Create a new, `open` snapshot set for `label`, assigning the next version in
/// that label's line (1 for the first). Returns the created set.
pub async fn create_set(pool: &PgPool, label: &str) -> Result<SnapshotSet, String> {
    // Next version for this label. A UNIQUE(label, version) constraint is the
    // backstop against a concurrent double-create racing to the same number.
    let row = sqlx::query(
        "INSERT INTO snapshot_set (label, version) \
         VALUES ($1, COALESCE((SELECT MAX(version) FROM snapshot_set WHERE label = $1), 0) + 1) \
         RETURNING id, label, version, status",
    )
    .bind(label)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("create_set failed: {e}"))?;
    Ok(SnapshotSet {
        id: row.get("id"),
        label: row.get("label"),
        version: row.get("version"),
        status: row.get("status"),
    })
}

/// Rows per multi-value INSERT when freezing (3 params/row, under the 65535
/// bound-parameter ceiling).
const FREEZE_BATCH: usize = 1000;

/// Freeze records into an `open` set, idempotently. Re-freezing the same
/// `(set_id, entity_key)` is skipped via `ON CONFLICT DO NOTHING`, so a retried
/// freeze never duplicates or mutates an already-frozen record. Returns the
/// number of newly frozen records.
///
/// Rejects if the set is already sealed — a sealed freeze is immutable by
/// contract.
pub async fn freeze(
    pool: &PgPool,
    set_id: Uuid,
    records: &[FrozenRecord],
) -> Result<usize, String> {
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM snapshot_set WHERE id = $1")
            .bind(set_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| format!("freeze: load set failed: {e}"))?;
    match status.as_deref() {
        None => return Err(format!("freeze: snapshot set {set_id} not found")),
        Some("sealed") => {
            return Err(format!("freeze: snapshot set {set_id} is sealed and immutable"))
        }
        _ => {}
    }
    if records.is_empty() {
        return Ok(0);
    }

    let mut inserted = 0usize;
    for batch in records.chunks(FREEZE_BATCH) {
        let mut sql =
            String::from("INSERT INTO snapshot_record (set_id, entity_key, data) VALUES ");
        let mut params = 0;
        for i in 0..batch.len() {
            if i > 0 {
                sql.push(',');
            }
            sql.push_str(&format!("(${},${},${})", params + 1, params + 2, params + 3));
            params += 3;
        }
        sql.push_str(" ON CONFLICT (set_id, entity_key) DO NOTHING");

        let mut q = sqlx::query(&sql);
        for r in batch {
            q = q.bind(set_id).bind(&r.entity_key).bind(&r.data);
        }
        let res = q
            .execute(pool)
            .await
            .map_err(|e| format!("freeze insert failed: {e}"))?;
        inserted += res.rows_affected() as usize;
    }
    Ok(inserted)
}

/// Seal a set: mark it immutable and safe to read. Idempotent — sealing an
/// already-sealed set is a no-op.
pub async fn seal(pool: &PgPool, set_id: Uuid) -> Result<(), String> {
    let res = sqlx::query(
        "UPDATE snapshot_set SET status='sealed', sealed_at=NOW() \
         WHERE id=$1 AND status='open'",
    )
    .bind(set_id)
    .execute(pool)
    .await
    .map_err(|e| format!("seal failed: {e}"))?;
    if res.rows_affected() == 0 {
        // Either already sealed (fine) or missing (error).
        let exists: Option<(i32,)> =
            sqlx::query_as("SELECT 1 FROM snapshot_set WHERE id = $1")
                .bind(set_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| format!("seal: existence check failed: {e}"))?;
        if exists.is_none() {
            return Err(format!("seal: snapshot set {set_id} not found"));
        }
    }
    Ok(())
}

/// Like [`seal`], but also writes a WORM audit event attributing the seal to
/// `user`. Sealing freezes the inputs a computation reads, so it is a
/// defensibility checkpoint worth attributing in the ledger.
pub async fn seal_audited(
    state: &crate::state::AppState,
    user: &crate::auth::AuthUser,
    pool: &PgPool,
    set_id: Uuid,
) -> Result<(), String> {
    seal(pool, set_id).await?;
    let set = get_set(pool, set_id).await.ok().flatten();
    let count = record_count(pool, set_id).await.unwrap_or(0);
    let (label, version) = set
        .map(|s| (s.label, s.version))
        .unwrap_or_default();
    crate::audit_events::emit(
        state,
        user,
        "snapshot.sealed",
        "snapshot_set",
        set_id.to_string(),
        serde_json::json!({ "label": label, "version": version, "records": count }),
    )
    .await;
    Ok(())
}

/// Read one frozen record's data by entity key. This is the only thing a
/// deterministic calculation should read.
pub async fn get_record(
    pool: &PgPool,
    set_id: Uuid,
    entity_key: &str,
) -> Result<Option<Value>, String> {
    let row: Option<(Value,)> = sqlx::query_as(
        "SELECT data FROM snapshot_record WHERE set_id = $1 AND entity_key = $2",
    )
    .bind(set_id)
    .bind(entity_key)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("get_record failed: {e}"))?;
    Ok(row.map(|(d,)| d))
}

/// Load a set by id.
pub async fn get_set(pool: &PgPool, set_id: Uuid) -> Result<Option<SnapshotSet>, String> {
    let row = sqlx::query("SELECT id, label, version, status FROM snapshot_set WHERE id = $1")
        .bind(set_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("get_set failed: {e}"))?;
    Ok(row.map(|r| SnapshotSet {
        id: r.get("id"),
        label: r.get("label"),
        version: r.get("version"),
        status: r.get("status"),
    }))
}

/// The most recent set for a label (highest version), sealed or not.
pub async fn latest(pool: &PgPool, label: &str) -> Result<Option<SnapshotSet>, String> {
    let row = sqlx::query(
        "SELECT id, label, version, status FROM snapshot_set \
         WHERE label = $1 ORDER BY version DESC LIMIT 1",
    )
    .bind(label)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("latest failed: {e}"))?;
    Ok(row.map(|r| SnapshotSet {
        id: r.get("id"),
        label: r.get("label"),
        version: r.get("version"),
        status: r.get("status"),
    }))
}

/// Count the frozen records in a set.
pub async fn record_count(pool: &PgPool, set_id: Uuid) -> Result<i64, String> {
    sqlx::query_scalar("SELECT COUNT(*) FROM snapshot_record WHERE set_id = $1")
        .bind(set_id)
        .fetch_one(pool)
        .await
        .map_err(|e| format!("record_count failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sealed_flag() {
        let mut s = SnapshotSet {
            id: Uuid::nil(),
            label: "billing.cycle".into(),
            version: 1,
            status: "open".into(),
        };
        assert!(!s.is_sealed());
        s.status = "sealed".into();
        assert!(s.is_sealed());
    }

    #[test]
    fn frozen_record_from_new_item() {
        let fr: FrozenRecord = NewItem::new("acct-1", json!({"reading": 42})).into();
        assert_eq!(fr.entity_key, "acct-1");
        assert_eq!(fr.data, json!({"reading": 42}));
    }
}
