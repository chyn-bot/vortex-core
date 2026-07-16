//! Generic batch run engine — partitioned mass processing on the job queue.
//!
//! A **run** takes a selected set of **items** and pushes each through a
//! domain **processor**, in chunks dispatched over the durable job queue
//! ([`crate::jobs`]). It is deliberately industry-neutral: a billing cycle, a
//! mass-mailing, a bulk import, an overnight recompute are all "run a processor
//! over N items". The engine owns everything generic — run lifecycle,
//! progress/exception counting, fail-item isolation, idempotent restart, and
//! trial-vs-live propagation — and the vertical owns only the per-item logic,
//! registered in code against a `run_kind`.
//!
//! # Why this is core, not billing
//!
//! The IWK billing scope names five "bill types" that are all entry points into
//! one `select → process → record` pipeline, and demands fail-account
//! isolation, idempotent restart, and trial/live parity. None of those are
//! water-, sewerage-, or even billing-specific — they are the generic shape of
//! *any* large batch. So the shape lives here in core; the billing vertical
//! becomes a thin `BatchProcessor` plus its trigger adapters.
//!
//! # Shape
//!
//! 1. [`create_run`] writes a `batch_run` row (status `pending`).
//! 2. [`add_items`] loads the work set into `batch_run_item`, keyed on
//!    `(run_id, item_key)` — the uniqueness constraint is the idempotency
//!    guarantee: re-adding an item is a no-op, so a crash-and-retry during load
//!    cannot double-count.
//! 3. [`start`] partitions the pending items into chunks of `chunk_size` and
//!    enqueues one `batch.chunk` job per chunk into the *central* queue, then
//!    marks the run `running`.
//! 4. The `batch.chunk` handler (registered by [`register_worker`]) looks up the
//!    [`BatchProcessor`] for the run's `run_kind` and runs it once per item. A
//!    processor error routes that one item to the exception count and the run
//!    continues — **fail-item isolation**. When the last item reaches a terminal
//!    state the run flips to `completed`.
//!
//! # Idempotent restart
//!
//! Item processing only ever acts on `pending` items and flips them with a
//! conditional `WHERE status='pending'` update, so re-running a chunk after a
//! crash reprocesses exactly the items that had not finished — never the ones
//! that had. This is what makes "resume a failed run" safe without bespoke
//! per-vertical bookkeeping.
//!
//! # Trial vs live
//!
//! A run carries a `trial` flag, handed to the processor via
//! [`ItemContext::trial`]. Trial and live use the *identical* processor; the
//! processor is responsible for suppressing external side-effects (posting,
//! e-invoice, notification) when `trial` is set. Same compute path, different
//! sink.
//!
//! # Multi-tenancy
//!
//! `batch_run` / `batch_run_item` are per-tenant tables (they live in the
//! database the run belongs to). The `ir_job` queue is *central* — the worker
//! polls the primary pool — so [`start`] reads items from the tenant pool but
//! enqueues chunk jobs into `state.db`, tagging each with `db_name` so the
//! handler resolves the right tenant pool via [`JobContext::pool`].

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::{json, Value};
use sqlx::postgres::PgPool;
use sqlx::Row;
use uuid::Uuid;

use crate::jobs::{enqueue, JobContext, JobRegistry, NewJob};
use crate::state::AppState;

/// The job `kind` the engine dispatches chunks under.
pub const CHUNK_JOB_KIND: &str = "batch.chunk";

/// Default items-per-chunk when a run does not specify one.
pub const DEFAULT_CHUNK_SIZE: i32 = 500;

// ─── Processor contract ──────────────────────────────────────────────────

/// Everything a processor needs to handle one item. The processor reads its
/// inputs from [`payload`](Self::payload) (frozen at load time) and the run's
/// [`params`](Self::params) — never from live master data mid-run.
pub struct ItemContext {
    pub state: Arc<AppState>,
    /// Tenant pool the run lives in (already resolved from the run's `db_name`).
    pub pool: PgPool,
    pub run_id: Uuid,
    pub run_kind: String,
    /// Run-level parameters (cycle id, tariff version, selector, …).
    pub params: Value,
    /// Trial run? The processor must suppress live side-effects when true.
    pub trial: bool,
    pub item_id: Uuid,
    /// The caller's stable idempotency key for this unit of work.
    pub item_key: String,
    /// Frozen per-item inputs.
    pub payload: Value,
    pub attempt: i32,
}

impl ItemContext {
    /// The run's mode as a [`crate::trial::RunMode`], for gating side-effects
    /// via [`crate::trial::RunMode::perform`]. Trial and live share this exact
    /// processor; only the gated effects differ.
    pub fn mode(&self) -> crate::trial::RunMode {
        crate::trial::RunMode::from_trial(self.trial)
    }
}

/// A processor failure, tagged with the pipeline stage it happened in so the
/// exception queue can be triaged ("failed at rating" vs "failed at posting").
#[derive(Debug, Clone)]
pub struct ProcessError {
    pub stage: String,
    pub message: String,
}

impl ProcessError {
    pub fn at(stage: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            stage: stage.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.stage, self.message)
    }
}

/// Outcome of processing one item: `Ok(optional result JSON to store on the
/// item)` or `Err(ProcessError)` to route it to the exception queue.
pub type ItemOutcome = Result<Option<Value>, ProcessError>;

/// A registered per-item processor.
pub type BatchProcessor = Arc<
    dyn Fn(ItemContext) -> Pin<Box<dyn Future<Output = ItemOutcome> + Send>> + Send + Sync,
>;

/// Maps a `run_kind` to its processor. Built at startup from every plugin's
/// `register_batch` contribution, mirroring [`JobRegistry`].
#[derive(Default, Clone)]
pub struct BatchRegistry {
    processors: HashMap<String, BatchProcessor>,
}

impl BatchRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the processor for `run_kind`.
    pub fn register<F, Fut>(&mut self, run_kind: &str, f: F)
    where
        F: Fn(ItemContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ItemOutcome> + Send + 'static,
    {
        self.processors
            .insert(run_kind.to_string(), Arc::new(move |ctx| Box::pin(f(ctx))));
    }

    fn get(&self, run_kind: &str) -> Option<BatchProcessor> {
        self.processors.get(run_kind).cloned()
    }

    pub fn kinds(&self) -> Vec<&str> {
        self.processors.keys().map(|s| s.as_str()).collect()
    }
}

// ─── Run + item value types ──────────────────────────────────────────────

/// Parameters for a new run. Use the builder helpers for the common case.
#[derive(Debug, Clone)]
pub struct NewBatchRun {
    pub run_kind: String,
    pub params: Value,
    pub trial: bool,
    pub chunk_size: i32,
    pub db_name: Option<String>,
    pub created_by: Option<String>,
}

impl NewBatchRun {
    pub fn new(run_kind: &str) -> Self {
        Self {
            run_kind: run_kind.to_string(),
            params: json!({}),
            trial: false,
            chunk_size: DEFAULT_CHUNK_SIZE,
            db_name: None,
            created_by: None,
        }
    }
    pub fn params(mut self, params: Value) -> Self {
        self.params = params;
        self
    }
    pub fn trial(mut self, trial: bool) -> Self {
        self.trial = trial;
        self
    }
    pub fn chunk_size(mut self, n: i32) -> Self {
        self.chunk_size = n.max(1);
        self
    }
    /// Tenant this run belongs to. Chunk jobs are tagged with it so the handler
    /// resolves the right tenant pool.
    pub fn for_db(mut self, db_name: impl Into<String>) -> Self {
        self.db_name = Some(db_name.into());
        self
    }
    pub fn created_by(mut self, who: impl Into<String>) -> Self {
        self.created_by = Some(who.into());
        self
    }
}

/// One unit of work to load into a run.
#[derive(Debug, Clone)]
pub struct NewItem {
    pub item_key: String,
    pub payload: Value,
}

impl NewItem {
    pub fn new(item_key: impl Into<String>, payload: Value) -> Self {
        Self {
            item_key: item_key.into(),
            payload,
        }
    }
}

/// A run's current progress, as read back for status/observability.
#[derive(Debug, Clone)]
pub struct RunStatus {
    pub run_id: Uuid,
    pub run_kind: String,
    pub status: String,
    pub trial: bool,
    pub total_items: i32,
    pub processed_items: i32,
    pub succeeded_items: i32,
    pub exception_items: i32,
    pub db_name: Option<String>,
}

// ─── Public API ──────────────────────────────────────────────────────────

/// Create a run (status `pending`). Returns the new `run_id`. Writes to the
/// tenant pool the run belongs to.
pub async fn create_run(pool: &PgPool, spec: NewBatchRun) -> Result<Uuid, String> {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO batch_run (run_kind, params, trial, chunk_size, db_name, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
    )
    .bind(&spec.run_kind)
    .bind(&spec.params)
    .bind(spec.trial)
    .bind(spec.chunk_size)
    .bind(&spec.db_name)
    .bind(&spec.created_by)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("create_run failed: {e}"))?;
    Ok(id)
}

/// Rows per multi-value INSERT when loading items. Kept well under Postgres'
/// 65535 bound-parameter ceiling (3 params/row).
const LOAD_BATCH: usize = 1000;

/// Load work items into a run, idempotently. Items already present (same
/// `(run_id, item_key)`) are skipped via `ON CONFLICT DO NOTHING`, so a retried
/// load never double-counts. Returns the number of *newly inserted* items and
/// bumps `total_items` by that amount.
///
/// Safe to call multiple times and in multiple pages before [`start`].
pub async fn add_items(
    pool: &PgPool,
    run_id: Uuid,
    items: &[NewItem],
) -> Result<usize, String> {
    if items.is_empty() {
        return Ok(0);
    }
    let mut inserted = 0usize;
    for batch in items.chunks(LOAD_BATCH) {
        // Build "($1,$2,$3),($4,$5,$6),..." with run_id repeated per row.
        let mut sql = String::from("INSERT INTO batch_run_item (run_id, item_key, payload) VALUES ");
        let mut params = 0;
        for i in 0..batch.len() {
            if i > 0 {
                sql.push(',');
            }
            sql.push_str(&format!("(${},${},${})", params + 1, params + 2, params + 3));
            params += 3;
        }
        sql.push_str(" ON CONFLICT (run_id, item_key) DO NOTHING");

        let mut q = sqlx::query(&sql);
        for item in batch {
            q = q.bind(run_id).bind(&item.item_key).bind(&item.payload);
        }
        let res = q
            .execute(pool)
            .await
            .map_err(|e| format!("add_items failed: {e}"))?;
        inserted += res.rows_affected() as usize;
    }

    if inserted > 0 {
        sqlx::query("UPDATE batch_run SET total_items = total_items + $2 WHERE id = $1")
            .bind(run_id)
            .bind(inserted as i32)
            .execute(pool)
            .await
            .map_err(|e| format!("total_items bump failed: {e}"))?;
    }
    Ok(inserted)
}

/// Partition the run's pending items into chunks and dispatch each as a
/// `batch.chunk` job, then mark the run `running`.
///
/// `pool` is the tenant pool the run lives in; chunk jobs are enqueued into the
/// central queue (`state.db`) tagged with the run's `db_name`. Returns the
/// number of chunk jobs dispatched. Restart-safe: only `pending` items are
/// picked up, so re-invoking after a partial dispatch enqueues the remainder.
pub async fn start(
    state: &Arc<AppState>,
    pool: &PgPool,
    run_id: Uuid,
) -> Result<usize, String> {
    let row = sqlx::query("SELECT run_kind, chunk_size, db_name FROM batch_run WHERE id = $1")
        .bind(run_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("start: load run failed: {e}"))?
        .ok_or_else(|| format!("start: run {run_id} not found"))?;
    let chunk_size: i32 = row.get::<i32, _>("chunk_size").max(1);
    let db_name: Option<String> = row.try_get("db_name").ok().flatten();

    // Page through pending item ids in id order, enqueuing one job per chunk.
    let mut chunks = 0usize;
    let mut after: Option<Uuid> = None;
    loop {
        let ids: Vec<Uuid> = match after {
            Some(a) => sqlx::query_scalar(
                "SELECT id FROM batch_run_item WHERE run_id = $1 AND status = 'pending' AND id > $2 \
                 ORDER BY id LIMIT $3",
            )
            .bind(run_id)
            .bind(a)
            .bind(chunk_size as i64)
            .fetch_all(pool)
            .await,
            None => sqlx::query_scalar(
                "SELECT id FROM batch_run_item WHERE run_id = $1 AND status = 'pending' \
                 ORDER BY id LIMIT $2",
            )
            .bind(run_id)
            .bind(chunk_size as i64)
            .fetch_all(pool)
            .await,
        }
        .map_err(|e| format!("start: page items failed: {e}"))?;

        if ids.is_empty() {
            break;
        }
        after = ids.last().copied();

        let mut job = NewJob::new(
            CHUNK_JOB_KIND,
            json!({ "run_id": run_id, "item_ids": ids }),
        )
        .trace("batch_run", run_id.to_string());
        if let Some(db) = &db_name {
            job = job.for_db(db.clone());
        }
        enqueue(&state.db, job).await?;
        chunks += 1;
    }

    // Mark running (and stamp started_at once). No-op if already running.
    sqlx::query(
        "UPDATE batch_run SET status = 'running', started_at = COALESCE(started_at, NOW()) \
         WHERE id = $1 AND status IN ('pending','running')",
    )
    .bind(run_id)
    .execute(pool)
    .await
    .map_err(|e| format!("start: mark running failed: {e}"))?;

    // A run with zero pending items is already complete.
    if chunks == 0 {
        maybe_complete(pool, run_id).await?;
    }
    Ok(chunks)
}

/// Read a run's progress.
pub async fn get_run(pool: &PgPool, run_id: Uuid) -> Result<Option<RunStatus>, String> {
    let row = sqlx::query(
        "SELECT id, run_kind, status, trial, total_items, processed_items, \
                succeeded_items, exception_items, db_name FROM batch_run WHERE id = $1",
    )
    .bind(run_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("get_run failed: {e}"))?;
    Ok(row.map(|r| RunStatus {
        run_id: r.get("id"),
        run_kind: r.get("run_kind"),
        status: r.get("status"),
        trial: r.get("trial"),
        total_items: r.get("total_items"),
        processed_items: r.get("processed_items"),
        succeeded_items: r.get("succeeded_items"),
        exception_items: r.get("exception_items"),
        db_name: r.try_get("db_name").ok().flatten(),
    }))
}

// ─── Exception review queue ──────────────────────────────────────────────

/// A failed item, for the review/triage queue.
#[derive(Debug, Clone)]
pub struct ExceptionItem {
    pub item_id: Uuid,
    pub item_key: String,
    pub stage_failed: Option<String>,
    pub error_detail: Option<String>,
    pub attempts: i32,
}

/// List a run's failed items (the exception queue), most-recently-processed
/// first. `limit`/`offset` page the result.
pub async fn list_exceptions(
    pool: &PgPool,
    run_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<ExceptionItem>, String> {
    let rows = sqlx::query(
        "SELECT id, item_key, stage_failed, error_detail, attempts \
         FROM batch_run_item WHERE run_id = $1 AND status = 'failed' \
         ORDER BY processed_at DESC NULLS LAST, id LIMIT $2 OFFSET $3",
    )
    .bind(run_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("list_exceptions failed: {e}"))?;
    Ok(rows
        .into_iter()
        .map(|r| ExceptionItem {
            item_id: r.get("id"),
            item_key: r.get("item_key"),
            stage_failed: r.try_get("stage_failed").ok().flatten(),
            error_detail: r.try_get("error_detail").ok().flatten(),
            attempts: r.get("attempts"),
        })
        .collect())
}

/// Reset failed items back to `pending` so a later [`start`] reprocesses them —
/// the operator remedy once the cause of a failure is fixed. Pass `Some(ids)` to
/// requeue specific items, or `None` for every failed item in the run. Adjusts
/// the run's counters and reopens it (`running`, `finished_at` cleared). Returns
/// the number of items requeued.
///
/// Prefer [`retry_exceptions`], which also re-dispatches — this is the lower
/// half if a caller wants to requeue without dispatching yet.
pub async fn requeue_exceptions(
    pool: &PgPool,
    run_id: Uuid,
    item_ids: Option<&[Uuid]>,
) -> Result<usize, String> {
    let reset = match item_ids {
        Some(ids) => {
            if ids.is_empty() {
                return Ok(0);
            }
            sqlx::query(
                "UPDATE batch_run_item SET status='pending', stage_failed=NULL, error_detail=NULL, \
                 processed_at=NULL WHERE run_id=$1 AND status='failed' AND id = ANY($2)",
            )
            .bind(run_id)
            .bind(ids)
            .execute(pool)
            .await
        }
        None => {
            sqlx::query(
                "UPDATE batch_run_item SET status='pending', stage_failed=NULL, error_detail=NULL, \
                 processed_at=NULL WHERE run_id=$1 AND status='failed'",
            )
            .bind(run_id)
            .execute(pool)
            .await
        }
    }
    .map_err(|e| format!("requeue_exceptions failed: {e}"))?
    .rows_affected() as i32;

    if reset > 0 {
        // Un-count the requeued items and reopen the run. GREATEST guards the
        // counters against ever going negative.
        sqlx::query(
            "UPDATE batch_run SET status='running', finished_at=NULL, \
                processed_items = GREATEST(0, processed_items - $2), \
                exception_items = GREATEST(0, exception_items - $2) \
             WHERE id = $1",
        )
        .bind(run_id)
        .bind(reset)
        .execute(pool)
        .await
        .map_err(|e| format!("requeue_exceptions counter update failed: {e}"))?;
    }
    Ok(reset as usize)
}

/// Requeue failed items and immediately re-dispatch them. The end-to-end
/// operator retry: fix the cause, call this, the run resumes over exactly the
/// previously-failed items. Returns the number of chunk jobs dispatched.
pub async fn retry_exceptions(
    state: &Arc<AppState>,
    pool: &PgPool,
    run_id: Uuid,
    item_ids: Option<&[Uuid]>,
) -> Result<usize, String> {
    let requeued = requeue_exceptions(pool, run_id, item_ids).await?;
    if requeued == 0 {
        return Ok(0);
    }
    start(state, pool, run_id).await
}

// ─── Chunk worker ────────────────────────────────────────────────────────

/// Register the `batch.chunk` job handler, capturing the processor registry.
/// Call once at startup from the host, after building the [`BatchRegistry`]
/// from plugin contributions. Mirrors [`crate::jobs::register_core_handlers`].
pub fn register_worker(job_reg: &mut JobRegistry, batch_reg: Arc<BatchRegistry>) {
    job_reg.register(CHUNK_JOB_KIND, move |ctx| {
        let batch_reg = batch_reg.clone();
        async move { handle_chunk(ctx, batch_reg).await }
    });
}

/// Process one chunk: run the processor over each still-pending item with
/// fail-item isolation, then update run counters once for the whole chunk and
/// check for completion.
async fn handle_chunk(ctx: JobContext, batch_reg: Arc<BatchRegistry>) -> Result<(), String> {
    let run_id: Uuid = ctx
        .payload
        .get("run_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .ok_or("batch.chunk: missing/invalid run_id")?;
    let item_ids: Vec<Uuid> = ctx
        .payload
        .get("item_ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().and_then(|s| s.parse().ok()))
                .collect()
        })
        .unwrap_or_default();

    let pool = ctx.pool().await;

    // Load run context once (kind/params/trial). If the run is gone or no
    // longer active, treat the chunk as a no-op success (idempotent).
    let run = sqlx::query(
        "SELECT run_kind, params, trial, status FROM batch_run WHERE id = $1",
    )
    .bind(run_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| format!("batch.chunk: load run failed: {e}"))?;
    let Some(run) = run else { return Ok(()) };
    let status: String = run.get("status");
    if status == "cancelled" || status == "failed" {
        return Ok(());
    }
    let run_kind: String = run.get("run_kind");
    let params: Value = run.get("params");
    let trial: bool = run.get("trial");

    let processor = batch_reg
        .get(&run_kind)
        .ok_or_else(|| format!("batch.chunk: no processor registered for run_kind '{run_kind}'"))?;

    let mut n_succeeded = 0i32;
    let mut n_exception = 0i32;

    for item_id in item_ids {
        // Load the item only if still pending — skips work already done, which
        // is what makes a chunk re-run after a crash idempotent.
        let item = sqlx::query(
            "SELECT item_key, payload, attempts FROM batch_run_item \
             WHERE id = $1 AND run_id = $2 AND status = 'pending'",
        )
        .bind(item_id)
        .bind(run_id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| format!("batch.chunk: load item failed: {e}"))?;
        let Some(item) = item else { continue };
        let item_key: String = item.get("item_key");
        let payload: Value = item.get("payload");
        let attempts: i32 = item.get("attempts");

        let ictx = ItemContext {
            state: ctx.state.clone(),
            pool: pool.clone(),
            run_id,
            run_kind: run_kind.clone(),
            params: params.clone(),
            trial,
            item_id,
            item_key: item_key.clone(),
            payload,
            attempt: attempts + 1,
        };

        // Isolate the processor (including panics) so one bad item can never
        // halt the chunk, let alone the run — fail-item isolation.
        let outcome = match tokio::spawn(processor(ictx)).await {
            Ok(r) => r,
            Err(e) if e.is_panic() => Err(ProcessError::at("panic", "processor panicked")),
            Err(_) => Err(ProcessError::at("cancelled", "processor cancelled")),
        };

        match outcome {
            Ok(result) => {
                let res = sqlx::query(
                    "UPDATE batch_run_item SET status='succeeded', result=$3, attempts=attempts+1, \
                     stage_failed=NULL, error_detail=NULL, processed_at=NOW() \
                     WHERE id=$1 AND run_id=$2 AND status='pending'",
                )
                .bind(item_id)
                .bind(run_id)
                .bind(result)
                .execute(&pool)
                .await
                .map_err(|e| format!("batch.chunk: mark succeeded failed: {e}"))?;
                // Only count if we actually transitioned it (guards double-count
                // on a chunk re-run).
                if res.rows_affected() == 1 {
                    n_succeeded += 1;
                }
            }
            Err(err) => {
                let res = sqlx::query(
                    "UPDATE batch_run_item SET status='failed', stage_failed=$3, error_detail=$4, \
                     attempts=attempts+1, processed_at=NOW() \
                     WHERE id=$1 AND run_id=$2 AND status='pending'",
                )
                .bind(item_id)
                .bind(run_id)
                .bind(&err.stage)
                .bind(&err.message)
                .execute(&pool)
                .await
                .map_err(|e| format!("batch.chunk: mark failed failed: {e}"))?;
                if res.rows_affected() == 1 {
                    n_exception += 1;
                }
            }
        }
    }

    // One counter update for the whole chunk, rather than per item.
    if n_succeeded > 0 || n_exception > 0 {
        sqlx::query(
            "UPDATE batch_run SET \
                processed_items = processed_items + $2, \
                succeeded_items = succeeded_items + $3, \
                exception_items = exception_items + $4 \
             WHERE id = $1",
        )
        .bind(run_id)
        .bind(n_succeeded + n_exception)
        .bind(n_succeeded)
        .bind(n_exception)
        .execute(&pool)
        .await
        .map_err(|e| format!("batch.chunk: counter update failed: {e}"))?;
    }

    maybe_complete(&pool, run_id).await?;
    Ok(())
}

/// Flip a `running` run to `completed` once every item has reached a terminal
/// state. The conditional `WHERE` makes this safe to call from every chunk —
/// only one call transitions the row.
async fn maybe_complete(pool: &PgPool, run_id: Uuid) -> Result<(), String> {
    sqlx::query(
        "UPDATE batch_run SET status='completed', finished_at=NOW() \
         WHERE id=$1 AND status='running' AND processed_items >= total_items",
    )
    .bind(run_id)
    .execute(pool)
    .await
    .map_err(|e| format!("maybe_complete failed: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_run_builder_defaults_and_overrides() {
        let r = NewBatchRun::new("billing.cycle");
        assert_eq!(r.chunk_size, DEFAULT_CHUNK_SIZE);
        assert!(!r.trial);
        assert!(r.db_name.is_none());

        let r = NewBatchRun::new("billing.cycle")
            .trial(true)
            .chunk_size(1000)
            .for_db("gaia")
            .created_by("chyn");
        assert!(r.trial);
        assert_eq!(r.chunk_size, 1000);
        assert_eq!(r.db_name.as_deref(), Some("gaia"));
        assert_eq!(r.created_by.as_deref(), Some("chyn"));
    }

    #[test]
    fn chunk_size_floored_at_one() {
        assert_eq!(NewBatchRun::new("k").chunk_size(0).chunk_size, 1);
        assert_eq!(NewBatchRun::new("k").chunk_size(-5).chunk_size, 1);
    }

    #[test]
    fn process_error_formats_with_stage() {
        let e = ProcessError::at("rating", "tariff class not found");
        assert_eq!(e.to_string(), "[rating] tariff class not found");
    }

    #[test]
    fn registry_registers_and_looks_up() {
        let mut reg = BatchRegistry::new();
        reg.register("billing.cycle", |_ctx| async { Ok(None) });
        assert!(reg.get("billing.cycle").is_some());
        assert!(reg.get("missing").is_none());
        assert_eq!(reg.kinds(), vec!["billing.cycle"]);
    }
}
