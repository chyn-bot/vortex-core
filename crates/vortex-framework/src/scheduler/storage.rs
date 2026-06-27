//! Postgres persistence for scheduled action state.
//!
//! The scheduler owns a single table, `scheduled_actions` (created
//! by migration `118_scheduler`), and every DB operation goes
//! through one of the functions in this module. The supervisor
//! loop never writes SQL inline — it calls [`claim_due`] to pick
//! the next due action and [`record_result`] to update counters.
//!
//! ## Concurrency model
//!
//! [`claim_due`] uses `SELECT … FOR UPDATE SKIP LOCKED` to
//! atomically pick one due row without blocking on rows another
//! scheduler instance has already claimed. This makes the
//! scheduler safe under horizontally-scaled deployments: any
//! number of app instances can run concurrent supervisor loops
//! against the same database and each due action is handed to
//! exactly one of them per tick.
//!
//! The advance of `next_call` happens inside the same transaction
//! as the claim, so the window between "job selected" and "next
//! run scheduled" is atomic — no other poller can double-fire the
//! same tick. Once the transaction commits, the job runs outside
//! the lock. If the process dies mid-job the run is lost (not
//! retried) — this is the documented trade-off for not holding a
//! transaction open for the job's entire duration.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use vortex_common::{VortexError, VortexResult};

use super::action::ScheduledActionDef;

/// A row claimed from the `scheduled_actions` table, ready to be
/// dispatched to its handler. The `claim_due` function has already
/// advanced `next_call` and set `last_call = NOW()` in the same
/// transaction, so this value is authoritative — no other poller
/// will pick up the same action until the new `next_call` is due.
#[derive(Debug, Clone)]
pub struct ClaimedAction {
    /// The action code, used to look up the registered handler.
    pub code: String,
    /// Human-readable name (denormalized from `scheduled_actions.name`
    /// so the supervisor can log it without a second query).
    pub name: String,
    /// When this claim was made — passed back to [`record_result`]
    /// so run duration can be computed precisely.
    pub started_at: DateTime<Utc>,
}

/// Insert a definition if it doesn't exist, or refresh the mutable
/// *definition* fields (`name`, `interval_seconds`, `schedule_kind`)
/// if it does. Runtime state (`active`, `next_call`, counters, last
/// results) is **never** overwritten by a sync — administrators can
/// disable or manually reschedule a job from SQL and the next
/// startup will respect that choice.
///
/// On a fresh insert, `next_call` is set to `NOW()` so the first run
/// happens at the next poll tick rather than waiting a full
/// interval. `active` is set from `def.enabled_by_default`.
pub async fn upsert_definition(pool: &PgPool, def: &ScheduledActionDef) -> VortexResult<()> {
    sqlx::query(
        r#"
        INSERT INTO scheduled_actions
            (code, name, schedule_kind, interval_seconds, active, next_call)
        VALUES ($1, $2, 'every', $3, $4, NOW())
        ON CONFLICT (code) DO UPDATE
        SET name             = EXCLUDED.name,
            schedule_kind    = EXCLUDED.schedule_kind,
            interval_seconds = EXCLUDED.interval_seconds,
            updated_at       = NOW()
        "#,
    )
    .bind(def.code)
    .bind(def.name)
    .bind(def.schedule.interval_seconds())
    .bind(def.enabled_by_default)
    .execute(pool)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(())
}

/// Atomically claim the next due, active action. Returns `None`
/// when no action is ready — callers should sleep and retry.
///
/// Inside a single transaction this:
///
/// 1. Picks one active row whose `next_call <= NOW()` using
///    `FOR UPDATE SKIP LOCKED LIMIT 1`, so concurrent schedulers
///    never see the same row.
/// 2. Advances `next_call` by the row's `interval_seconds` and
///    sets `last_call = NOW()`.
/// 3. Returns the row's code and display name.
///
/// If `next_call + interval < NOW()` (i.e. the server was offline
/// long enough that the job fell behind by more than one interval),
/// the new `next_call` is clamped to `NOW() + interval` rather than
/// `NOW()` — this prevents the scheduler from running catch-up
/// batches of a job that fell behind. The caller gets exactly one
/// fire per claim regardless of how far behind the schedule drifted.
pub async fn claim_due(pool: &PgPool) -> VortexResult<Option<ClaimedAction>> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let row: Option<(String, String)> = sqlx::query_as(
        r#"
        SELECT code, name
        FROM scheduled_actions
        WHERE active AND next_call <= NOW()
        ORDER BY next_call
        FOR UPDATE SKIP LOCKED
        LIMIT 1
        "#,
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let Some((code, name)) = row else {
        tx.commit()
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        return Ok(None);
    };

    let started_at = Utc::now();

    // Advance next_call and mark last_call atomically. The GREATEST
    // clamp prevents catch-up thundering if the server has been
    // offline longer than one interval.
    sqlx::query(
        r#"
        UPDATE scheduled_actions
        SET last_call = NOW(),
            next_call = GREATEST(
                NOW() + (interval_seconds || ' seconds')::INTERVAL,
                next_call + (interval_seconds || ' seconds')::INTERVAL
            ),
            updated_at = NOW()
        WHERE code = $1
        "#,
    )
    .bind(&code)
    .execute(&mut *tx)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    Ok(Some(ClaimedAction {
        code,
        name,
        started_at,
    }))
}

/// Record the outcome of a run. Called by the supervisor after the
/// handler returns (or panics — in which case `result` carries the
/// panic message). Updates counters, last-success / last-error
/// timestamps, and the run duration.
///
/// Note: this function does NOT touch `next_call`. The advance
/// happened in [`claim_due`]; recording the result only updates
/// *observability* state.
pub async fn record_result(
    pool: &PgPool,
    code: &str,
    started_at: DateTime<Utc>,
    outcome: Result<(), String>,
) -> VortexResult<()> {
    let finished_at = Utc::now();
    let duration_ms = finished_at
        .signed_duration_since(started_at)
        .num_milliseconds()
        .max(0);

    match outcome {
        Ok(()) => {
            sqlx::query(
                r#"
                UPDATE scheduled_actions
                SET last_success     = $2,
                    last_error       = NULL,
                    last_duration_ms = $3,
                    run_count        = run_count + 1,
                    updated_at       = NOW()
                WHERE code = $1
                "#,
            )
            .bind(code)
            .bind(finished_at)
            .bind(duration_ms)
            .execute(pool)
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        }
        Err(err_msg) => {
            sqlx::query(
                r#"
                UPDATE scheduled_actions
                SET last_error       = $2,
                    last_duration_ms = $3,
                    run_count        = run_count + 1,
                    error_count      = error_count + 1,
                    updated_at       = NOW()
                WHERE code = $1
                "#,
            )
            .bind(code)
            .bind(err_msg)
            .bind(duration_ms)
            .execute(pool)
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        }
    }

    Ok(())
}
