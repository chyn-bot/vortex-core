//! Durable background-job queue.
//!
//! The scheduler ([`crate::scheduler`]) handles *recurring* time-driven work;
//! this handles *one-off async* work that must survive a restart and retry on
//! failure — sending an email, generating a report, calling a webhook.
//!
//! Shape: [`enqueue`] writes an `ir_job` row; a [`JobWorker`] (started once at
//! boot, like the scheduler) polls the queue, atomically claims due jobs with
//! `FOR UPDATE SKIP LOCKED`, and dispatches each to the [`JobHandler`]
//! registered for its `kind`. On `Err` the job retries with exponential
//! backoff until `max_attempts`, then dead-letters (`status='dead'`). A handler
//! panic is isolated (the job is failed, not the worker).
//!
//! The queue is central — it lives in the worker's pool (the primary DB) — and
//! each job carries an optional `db_name` so its handler can resolve the right
//! tenant pool via [`AppState::pool_manager`]. Plugins register their own
//! handlers at startup via [`JobRegistry`].

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::state::AppState;

/// What a handler receives. `payload` is the job's JSON; `db_name` (if set)
/// names the tenant database the work belongs to.
pub struct JobContext {
    pub state: Arc<AppState>,
    pub job_id: Uuid,
    pub kind: String,
    pub payload: Value,
    pub db_name: Option<String>,
    pub attempt: i32,
}

impl JobContext {
    /// Resolve the pool the job should act on: the tenant pool named by
    /// `db_name`, or the primary pool when unset/unresolvable.
    pub async fn pool(&self) -> PgPool {
        if let Some(name) = &self.db_name {
            if let Ok(cp) = self.state.pool_manager.get_pool(name).await {
                return cp.pool().clone();
            }
        }
        self.state.db.clone()
    }
}

/// A registered handler. Returns `Ok(())` on success or `Err(msg)` to trigger
/// retry/dead-letter.
pub type JobHandler = Arc<
    dyn Fn(JobContext) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync,
>;

/// Maps a job `kind` to its handler. Built at startup.
#[derive(Default, Clone)]
pub struct JobRegistry {
    handlers: HashMap<String, JobHandler>,
}

impl JobRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a handler for `kind`. The closure must be `'static` and `Send`.
    pub fn register<F, Fut>(&mut self, kind: &str, f: F)
    where
        F: Fn(JobContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        self.handlers
            .insert(kind.to_string(), Arc::new(move |ctx| Box::pin(f(ctx))));
    }

    fn get(&self, kind: &str) -> Option<JobHandler> {
        self.handlers.get(kind).cloned()
    }

    pub fn kinds(&self) -> Vec<&str> {
        self.handlers.keys().map(|s| s.as_str()).collect()
    }
}

/// A job to enqueue. Use the builder helpers for the common case.
#[derive(Debug, Clone)]
pub struct NewJob {
    pub kind: String,
    pub payload: Value,
    pub queue: String,
    pub priority: i32,
    pub max_attempts: i32,
    pub run_at: Option<DateTime<Utc>>,
    pub db_name: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
}

impl NewJob {
    pub fn new(kind: &str, payload: Value) -> Self {
        Self {
            kind: kind.to_string(),
            payload,
            queue: "default".to_string(),
            priority: 0,
            max_attempts: 5,
            run_at: None,
            db_name: None,
            resource_type: None,
            resource_id: None,
        }
    }
    /// Tenant the handler should run against.
    pub fn for_db(mut self, db_name: impl Into<String>) -> Self {
        self.db_name = Some(db_name.into());
        self
    }
    pub fn max_attempts(mut self, n: i32) -> Self {
        self.max_attempts = n;
        self
    }
    pub fn priority(mut self, p: i32) -> Self {
        self.priority = p;
        self
    }
    /// Delay first execution until `at`.
    pub fn run_at(mut self, at: DateTime<Utc>) -> Self {
        self.run_at = Some(at);
        self
    }
    pub fn trace(mut self, rtype: impl Into<String>, rid: impl Into<String>) -> Self {
        self.resource_type = Some(rtype.into());
        self.resource_id = Some(rid.into());
        self
    }
}

/// Enqueue a job into `pool` (the worker's/primary pool). Returns the job id.
pub async fn enqueue(pool: &PgPool, job: NewJob) -> Result<Uuid, String> {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO ir_job (kind, payload, queue, priority, max_attempts, run_at, db_name, resource_type, resource_id) \
         VALUES ($1,$2,$3,$4,$5, COALESCE($6, NOW()), $7,$8,$9) RETURNING id",
    )
    .bind(&job.kind)
    .bind(&job.payload)
    .bind(&job.queue)
    .bind(job.priority)
    .bind(job.max_attempts)
    .bind(job.run_at)
    .bind(&job.db_name)
    .bind(&job.resource_type)
    .bind(&job.resource_id)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("enqueue failed: {e}"))?;
    Ok(id)
}

/// The background worker. Construct with a registry, then [`JobWorker::start`].
pub struct JobWorker {
    registry: Arc<JobRegistry>,
    poll_interval: std::time::Duration,
    batch: i64,
    worker_id: String,
}

impl JobWorker {
    pub fn new(registry: JobRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
            poll_interval: std::time::Duration::from_secs(5),
            batch: 10,
            worker_id: format!("worker-{}", Uuid::now_v7()),
        }
    }

    pub fn with_poll_interval(mut self, d: std::time::Duration) -> Self {
        self.poll_interval = d;
        self
    }

    /// Max jobs claimed (and run concurrently) per poll tick. The default (10)
    /// suits light background work; raise it for high-throughput batch runs
    /// where many `batch.chunk` jobs are queued at once. Floored at 1.
    pub fn with_batch_size(mut self, n: i64) -> Self {
        self.batch = n.max(1);
        self
    }

    /// Spawn the poll loop (mirrors `Scheduler::start`). Polls the primary pool.
    pub fn start(self, state: Arc<AppState>) {
        tokio::spawn(async move {
            tracing::info!(worker = %self.worker_id, kinds = ?self.registry.kinds(), "job worker started");
            loop {
                if let Err(e) = self.tick(&state).await {
                    tracing::error!(error = %e, "job worker tick failed");
                }
                tokio::time::sleep(self.poll_interval).await;
            }
        });
    }

    /// Claim and process one batch of due jobs.
    async fn tick(&self, state: &Arc<AppState>) -> Result<(), String> {
        let pool = &state.db;
        // Atomically claim due jobs and mark them running.
        let claimed = sqlx::query(
            "WITH due AS ( \
                SELECT id FROM ir_job \
                WHERE status = 'pending' AND run_at <= NOW() \
                ORDER BY priority DESC, run_at \
                LIMIT $1 FOR UPDATE SKIP LOCKED \
             ) \
             UPDATE ir_job j SET status='running', locked_at=NOW(), locked_by=$2, \
                attempts = attempts + 1, updated_at=NOW() \
             FROM due WHERE j.id = due.id \
             RETURNING j.id, j.kind, j.payload, j.db_name, j.attempts, j.max_attempts",
        )
        .bind(self.batch)
        .bind(&self.worker_id)
        .fetch_all(pool)
        .await
        .map_err(|e| e.to_string())?;

        if claimed.is_empty() {
            return Ok(());
        }

        let mut handles = Vec::new();
        for row in claimed {
            let id: Uuid = row.get("id");
            let kind: String = row.get("kind");
            let payload: Value = row.get("payload");
            let db_name: Option<String> = row.try_get("db_name").ok().flatten();
            let attempts: i32 = row.get("attempts");
            let max_attempts: i32 = row.get("max_attempts");
            let handler = self.registry.get(&kind);
            let state = state.clone();
            // Isolate each job (incl. handler panics) in its own task.
            handles.push(tokio::spawn(async move {
                run_one(state, id, kind, payload, db_name, attempts, max_attempts, handler).await
            }));
        }
        for h in handles {
            let _ = h.await; // panics already converted to a 'dead' update inside
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_one(
    state: Arc<AppState>,
    id: Uuid,
    kind: String,
    payload: Value,
    db_name: Option<String>,
    attempts: i32,
    max_attempts: i32,
    handler: Option<JobHandler>,
) {
    let pool = state.db.clone();
    let outcome: Result<(), String> = match handler {
        None => Err(format!("no handler registered for kind '{kind}'")),
        Some(h) => {
            let ctx = JobContext {
                state: state.clone(),
                job_id: id,
                kind: kind.clone(),
                payload,
                db_name,
                attempt: attempts,
            };
            // Run the handler in its own task so a panic becomes a JoinError
            // (failed job) instead of unwinding `run_one` and leaving the row
            // stuck in 'running'.
            match tokio::spawn(h(ctx)).await {
                Ok(r) => r,
                Err(e) if e.is_panic() => Err("handler panicked".to_string()),
                Err(_) => Err("handler cancelled".to_string()),
            }
        }
    };

    match outcome {
        Ok(()) => {
            let _ = sqlx::query(
                "UPDATE ir_job SET status='succeeded', finished_at=NOW(), updated_at=NOW() WHERE id=$1",
            )
            .bind(id)
            .execute(&pool)
            .await;
        }
        Err(err) => {
            if attempts >= max_attempts {
                tracing::error!(job = %id, kind = %kind, attempts, error = %err, "job dead-lettered");
                let _ = sqlx::query(
                    "UPDATE ir_job SET status='dead', last_error=$2, finished_at=NOW(), updated_at=NOW() WHERE id=$1",
                )
                .bind(id)
                .bind(&err)
                .execute(&pool)
                .await;
            } else {
                // Exponential backoff, capped at 1h: 2^attempts minutes.
                tracing::warn!(job = %id, kind = %kind, attempts, error = %err, "job failed; will retry");
                let _ = sqlx::query(
                    "UPDATE ir_job SET status='pending', last_error=$2, locked_by=NULL, locked_at=NULL, \
                     run_at = NOW() + (LEAST(POWER(2, attempts)::int, 60) * INTERVAL '1 minute'), updated_at=NOW() \
                     WHERE id=$1",
                )
                .bind(id)
                .bind(&err)
                .execute(&pool)
                .await;
            }
        }
    }
}

// ─── Core handlers ───────────────────────────────────────────────────────

/// Register the built-in handlers (`mail.send`, `report.render`).
/// Call at startup.
pub fn register_core_handlers(reg: &mut JobRegistry) {
    crate::report_jobs::register(reg);
    reg.register("mail.send", |ctx| async move {
        let p = &ctx.payload;
        let to = p.get("to").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        if to.is_empty() {
            return Err("mail.send: missing 'to'".to_string());
        }
        let subject = p.get("subject").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let text = p.get("text").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let context = p.get("context").and_then(|v| v.as_str()).unwrap_or("job").to_string();
        let pool = ctx.pool().await;
        let msg = crate::mail::EmailMessage::text(to, subject, text);
        crate::mail::send_default(&pool, &msg, &context)
            .await
            .map_err(|e| e.to_string())
    });
}
