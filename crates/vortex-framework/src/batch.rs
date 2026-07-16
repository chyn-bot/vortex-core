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

use rust_decimal::Decimal;
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

/// Like [`create_run`], but also writes a WORM audit event attributing the run
/// to `user`. Use from a caller that has a human actor (an admin action, a
/// trigger carrying a session); system-triggered callers use [`create_run`].
pub async fn create_run_audited(
    state: &AppState,
    user: &crate::auth::AuthUser,
    pool: &PgPool,
    spec: NewBatchRun,
) -> Result<Uuid, String> {
    let run_kind = spec.run_kind.clone();
    let trial = spec.trial;
    let id = create_run(pool, spec).await?;
    crate::audit_events::emit(
        state,
        user,
        "batch.run.created",
        "batch_run",
        id.to_string(),
        json!({ "run_kind": run_kind, "trial": trial }),
    )
    .await;
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

    // Refresh planner statistics before the chunk workers start their batched
    // writes. `add_items` bulk-loads the work set; immediately afterwards the
    // table's stats are stale, and the (id, status) join in handle_chunk's
    // set-based UPDATE will otherwise be planned as a hash-scan over *all*
    // pending rows per chunk instead of a PK nested-loop — a 400k load test
    // measured ~3s per chunk-write under the bad plan vs milliseconds after
    // ANALYZE. Best-effort: a failure here (e.g. permissions) must not block the
    // run, only leave it to autovacuum to catch up.
    let _ = sqlx::query("ANALYZE batch_run_item")
        .execute(pool)
        .await
        .map_err(|e| tracing::warn!(error = %e, "batch.start: ANALYZE skipped"));

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

// ─── Run control: pause / resume / cancel ────────────────────────────────

/// Pause a running run. Queued chunks bail at their boundary (leaving items
/// pending), in-flight chunks finish their current batch. Idempotent for an
/// already-paused run; a no-op unless the run is `running`.
pub async fn pause(pool: &PgPool, run_id: Uuid) -> Result<(), String> {
    sqlx::query("UPDATE batch_run SET status='paused' WHERE id=$1 AND status='running'")
        .bind(run_id)
        .execute(pool)
        .await
        .map_err(|e| format!("pause failed: {e}"))?;
    Ok(())
}

/// Resume a paused run: flip it back to `running` and re-dispatch its remaining
/// pending items (chunk jobs consumed while paused are re-created; processing is
/// idempotent, so any stragglers are harmless). Returns chunk jobs dispatched.
pub async fn resume(state: &Arc<AppState>, pool: &PgPool, run_id: Uuid) -> Result<usize, String> {
    let res = sqlx::query("UPDATE batch_run SET status='running' WHERE id=$1 AND status='paused'")
        .bind(run_id)
        .execute(pool)
        .await
        .map_err(|e| format!("resume failed: {e}"))?;
    if res.rows_affected() == 0 {
        return Ok(0); // not paused — nothing to resume
    }
    start(state, pool, run_id).await
}

/// Cancel a run. It stops making progress (queued/future chunks bail, in-flight
/// chunks finish their current batch) and is marked terminal. Pending items are
/// left as-is for the record. Idempotent; a no-op on an already-terminal run.
pub async fn cancel(pool: &PgPool, run_id: Uuid) -> Result<(), String> {
    sqlx::query(
        "UPDATE batch_run SET status='cancelled', finished_at=NOW() \
         WHERE id=$1 AND status IN ('pending','running','paused')",
    )
    .bind(run_id)
    .execute(pool)
    .await
    .map_err(|e| format!("cancel failed: {e}"))?;
    Ok(())
}

// ─── Built-in processors + load harness ──────────────────────────────────

/// `run_kind` of the built-in no-op processor used for load testing and
/// smoke-testing the engine end to end without a domain plugin.
pub const NOOP_RUN_KIND: &str = "batch.noop";

/// `run_kind` of the built-in invoice load-test processor. Diagnostic sibling of
/// [`NOOP_RUN_KIND`]: it does *realistic* per-item persistence — one invoice row
/// plus N line rows — so a load test measures true write-bound throughput, not
/// just engine overhead. It writes to the conventional load-test tables
/// `lt_invoice` / `lt_invoice_line` (created by the benchmark harness), reads
/// `customer_id` from the item payload and `line_count` (default 5) from the run
/// params. Not for production billing — that is a vertical's own processor.
pub const LOADTEST_INVOICE_RUN_KIND: &str = "batch.loadtest_invoice";

/// Register the engine's built-in processors into `reg`. Currently just
/// [`NOOP_RUN_KIND`]: a processor that does no domain work, so a run of it
/// measures the engine's own throughput (dispatch + claim + item writes) — the
/// load-test baseline. Per-item behaviour is driven by the item payload:
///
/// - `{"sleep_ms": N}` — sleep to simulate work of a known cost.
/// - `{"fail": true}`  — return an error, to exercise the exception path.
///
/// Call from the host while assembling the [`BatchRegistry`], before plugins.
pub fn register_builtin(reg: &mut BatchRegistry) {
    reg.register(NOOP_RUN_KIND, |ctx: ItemContext| async move {
        if ctx.payload.get("fail").and_then(|v| v.as_bool()) == Some(true) {
            return Err(ProcessError::at("noop", "synthetic failure"));
        }
        if let Some(ms) = ctx.payload.get("sleep_ms").and_then(|v| v.as_u64()) {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
        Ok(None)
    });

    reg.register(LOADTEST_INVOICE_RUN_KIND, |ctx: ItemContext| async move {
        // Assemble a simple invoice: `line_count` lines, deterministic amounts
        // (realism of the numbers doesn't affect write cost — the point is the
        // persistence). This mirrors what a real billing processor does at the
        // write step: one header row + its lines.
        let line_count = ctx
            .params
            .get("line_count")
            .and_then(|v| v.as_i64())
            .unwrap_or(5)
            .clamp(1, 100) as i32;
        let customer_id = ctx
            .payload
            .get("customer_id")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<Uuid>().ok())
            .ok_or_else(|| ProcessError::at("parse", "item payload missing/invalid customer_id"))?;
        let invoice_no = format!("INV-{}", ctx.item_key);

        // Build the lines and total.
        let mut total = Decimal::ZERO;
        let mut line_vals = String::new();
        for n in 1..=line_count {
            let unit = Decimal::from(10 * n);
            total += unit; // qty 1
            if n > 1 {
                line_vals.push(',');
            }
            // ($k..) placeholders filled below; 5 bound values per line after inv_id.
            let b = 1 + (n as usize - 1) * 5;
            line_vals.push_str(&format!(
                "($1,${},${},${},${},${})",
                b + 1,
                b + 2,
                b + 3,
                b + 4,
                b + 5
            ));
        }

        // Insert the invoice header.
        let inv_id: Uuid = sqlx::query_scalar(
            "INSERT INTO lt_invoice (run_id, customer_id, invoice_no, total, status) \
             VALUES ($1,$2,$3,$4,'posted') RETURNING id",
        )
        .bind(ctx.run_id)
        .bind(customer_id)
        .bind(&invoice_no)
        .bind(total)
        .fetch_one(&ctx.pool)
        .await
        .map_err(|e| ProcessError::at("persist", format!("invoice insert failed: {e}")))?;

        // Insert its lines in one multi-row statement.
        let sql = format!(
            "INSERT INTO lt_invoice_line (invoice_id, line_no, description, quantity, unit_price, amount) VALUES {line_vals}"
        );
        let mut q = sqlx::query(&sql).bind(inv_id);
        for n in 1..=line_count {
            let unit = Decimal::from(10 * n);
            q = q
                .bind(n)
                .bind(format!("Line item {n}"))
                .bind(Decimal::ONE)
                .bind(unit)
                .bind(unit);
        }
        q.execute(&ctx.pool)
            .await
            .map_err(|e| ProcessError::at("persist", format!("line insert failed: {e}")))?;

        Ok(Some(json!({ "invoice_id": inv_id.to_string() })))
    });
}

/// Build a synthetic load item: a zero-padded key under `prefix` plus a payload.
/// Pure — the deterministic core of [`seed_run`], exposed for testing.
pub fn synthetic_item(prefix: &str, index: usize, payload: Value) -> NewItem {
    NewItem::new(format!("{prefix}-{index:08}"), payload)
}

/// Seed a load-test run: create a run from `spec` and load `count` synthetic
/// items (keys `{key_prefix}-00000000` …, each carrying `item_payload`). Returns
/// the run id, ready for [`start`]. Combine with [`register_builtin`] and a
/// [`NOOP_RUN_KIND`] spec to measure engine throughput against the target.
///
/// The whole flow, for a 400k baseline:
/// ```rust,ignore
/// let id = seed_run(pool, NewBatchRun::new(NOOP_RUN_KIND).chunk_size(1000), 400_000, "load", json!({})).await?;
/// start(state, pool, id).await?;               // watch /batch/runs/{id}
/// // items/sec ≈ total_items / (finished_at − started_at)
/// ```
pub async fn seed_run(
    pool: &PgPool,
    spec: NewBatchRun,
    count: usize,
    key_prefix: &str,
    item_payload: Value,
) -> Result<Uuid, String> {
    let run_id = create_run(pool, spec).await?;
    // Build and load in windows so a huge count never holds all items at once.
    const WINDOW: usize = 5000;
    let mut buf: Vec<NewItem> = Vec::with_capacity(WINDOW.min(count));
    for i in 0..count {
        buf.push(synthetic_item(key_prefix, i, item_payload.clone()));
        if buf.len() == WINDOW {
            add_items(pool, run_id, &buf).await?;
            buf.clear();
        }
    }
    if !buf.is_empty() {
        add_items(pool, run_id, &buf).await?;
    }
    Ok(run_id)
}

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
    // Cancelled/failed runs are terminal; a paused run should stop consuming
    // work at the chunk boundary and leave its items pending for resume. In all
    // three cases the chunk bails as a no-op success (the ir_job is done; the
    // items are untouched), so pause/cancel take effect between chunks.
    if status == "cancelled" || status == "failed" || status == "paused" {
        return Ok(());
    }
    let run_kind: String = run.get("run_kind");
    let params: Value = run.get("params");
    let trial: bool = run.get("trial");

    let processor = batch_reg
        .get(&run_kind)
        .ok_or_else(|| format!("batch.chunk: no processor registered for run_kind '{run_kind}'"))?;

    // Bulk-load the still-pending items for this chunk in ONE query. Items
    // already terminal (a chunk re-run after a crash) are simply absent from the
    // result, so they are skipped — idempotent restart, without a query per item.
    let rows = sqlx::query(
        "SELECT id, item_key, payload, attempts FROM batch_run_item \
         WHERE run_id = $1 AND id = ANY($2) AND status = 'pending' ORDER BY id",
    )
    .bind(run_id)
    .bind(&item_ids)
    .fetch_all(&pool)
    .await
    .map_err(|e| format!("batch.chunk: load items failed: {e}"))?;

    // Run the processor per item, accumulating outcomes for a set-based write.
    // Collecting first means the chunk does O(1) UPDATEs regardless of its size,
    // instead of one round trip per item — the throughput lever for large runs.
    // Each outcome class is gathered as a JSON array of rows; the write expands
    // it server-side with `jsonb_to_recordset` (one bound param, no array-type
    // encoding to reason about).
    let mut ok_rows: Vec<Value> = Vec::new();
    let mut fail_rows: Vec<Value> = Vec::new();

    for row in &rows {
        let item_id: Uuid = row.get("id");
        let item_key: String = row.get("item_key");
        let payload: Value = row.get("payload");
        let attempts: i32 = row.get("attempts");

        let ictx = ItemContext {
            state: ctx.state.clone(),
            pool: pool.clone(),
            run_id,
            run_kind: run_kind.clone(),
            params: params.clone(),
            trial,
            item_id,
            item_key,
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
            Ok(result) => ok_rows.push(json!({
                "id": item_id.to_string(),
                // JSON null here maps to SQL NULL in the result column.
                "result": result.unwrap_or(Value::Null),
            })),
            Err(err) => fail_rows.push(json!({
                "id": item_id.to_string(),
                "stage": err.stage,
                "err": err.message,
            })),
        }
    }

    // Batched writes: at most one UPDATE per outcome class for the whole chunk.
    // The `status='pending'` guard keeps a re-run from re-counting an item that
    // already transitioned (rows_affected reflects only fresh transitions).
    let mut n_succeeded = 0i32;
    if !ok_rows.is_empty() {
        let res = sqlx::query(
            "UPDATE batch_run_item AS t \
             SET status='succeeded', result=v.result, attempts=t.attempts+1, \
                 stage_failed=NULL, error_detail=NULL, processed_at=NOW() \
             FROM jsonb_to_recordset($1::jsonb) AS v(id uuid, result jsonb) \
             WHERE t.id = v.id AND t.run_id = $2 AND t.status = 'pending'",
        )
        .bind(Value::Array(ok_rows))
        .bind(run_id)
        .execute(&pool)
        .await
        .map_err(|e| format!("batch.chunk: mark succeeded failed: {e}"))?;
        n_succeeded = res.rows_affected() as i32;
    }

    let mut n_exception = 0i32;
    if !fail_rows.is_empty() {
        let res = sqlx::query(
            "UPDATE batch_run_item AS t \
             SET status='failed', stage_failed=v.stage, error_detail=v.err, \
                 attempts=t.attempts+1, processed_at=NOW() \
             FROM jsonb_to_recordset($1::jsonb) AS v(id uuid, stage text, err text) \
             WHERE t.id = v.id AND t.run_id = $2 AND t.status = 'pending'",
        )
        .bind(Value::Array(fail_rows))
        .bind(run_id)
        .execute(&pool)
        .await
        .map_err(|e| format!("batch.chunk: mark failed failed: {e}"))?;
        n_exception = res.rows_affected() as i32;
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

/// Flip a `running` run to `completed` once no item is left `pending`. The
/// conditional `WHERE` makes this safe to call from every chunk — only one call
/// transitions the row.
///
/// Completion keys off the *item states* (`NOT EXISTS` a pending item), not the
/// maintained `processed_items` counter. The counter is advisory (for progress
/// display) and could drift if a process crashes mid-chunk between writing item
/// outcomes and updating the counter; keying completion off the authoritative
/// item rows means such drift can never strand a finished run in `running`. The
/// `(run_id, status, id)` index keeps the check cheap even on a large run.
async fn maybe_complete(pool: &PgPool, run_id: Uuid) -> Result<(), String> {
    sqlx::query(
        "UPDATE batch_run SET status='completed', finished_at=NOW() \
         WHERE id=$1 AND status='running' \
           AND NOT EXISTS (SELECT 1 FROM batch_run_item WHERE run_id=$1 AND status='pending')",
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

    #[test]
    fn register_builtin_adds_noop() {
        let mut reg = BatchRegistry::new();
        register_builtin(&mut reg);
        assert!(reg.get(NOOP_RUN_KIND).is_some());
    }

    #[test]
    fn synthetic_item_keys_are_zero_padded_and_ordered() {
        let a = synthetic_item("load", 0, serde_json::json!({}));
        let b = synthetic_item("load", 42, serde_json::json!({"sleep_ms": 5}));
        assert_eq!(a.item_key, "load-00000000");
        assert_eq!(b.item_key, "load-00000042");
        // Lexicographic order matches numeric order (what the id-ordered
        // dispatch relies on for stable paging).
        assert!(a.item_key < b.item_key);
    }
}
