//! Generic idempotency-key guard — run an effect at most once.
//!
//! Retries, restarts, and at-least-once delivery all reduce to the same need:
//! *"I might be asked to do this more than once; do it only the first time."*
//! This is the durable, cross-cutting form of that guard. A caller names a
//! `scope` (the class of operation) and a `key` (the specific occurrence); the
//! first [`claim`] of a `(scope, key)` returns [`Claim::Fresh`] and every later
//! one returns [`Claim::Duplicate`] — carrying the result the first run stored,
//! if any.
//!
//! It backs the `idempotency_key` table (core migration 160). It is **core**,
//! not billing: inbound webhook de-duplication, once-only notifications, and a
//! billing engine's "don't post this bill twice" all use the same guard. The
//! batch engine bakes the equivalent guarantee into its items via
//! `UNIQUE(run_id, item_key)`; this is the same idea usable outside a run.
//!
//! # Typical use
//!
//! ```rust,ignore
//! use vortex_orm::idempotency::{claim, Claim};
//!
//! match claim(pool, "webhook.inbound", &delivery_id).await? {
//!     Claim::Fresh => {
//!         let outcome = do_the_work().await?;
//!         // Optionally record the result so duplicates can return it.
//!         record_result(pool, "webhook.inbound", &delivery_id, &outcome).await?;
//!     }
//!     Claim::Duplicate(prior) => {
//!         // Already handled — skip the side-effect. `prior` is the stored
//!         // result JSON if the first run recorded one.
//!     }
//! }
//! ```
//!
//! # Atomicity note
//!
//! [`claim`] is a single `INSERT ... ON CONFLICT DO NOTHING`, so the winner is
//! decided atomically by the database even under concurrent callers — exactly
//! one gets `Fresh`. The claim is recorded *before* the work runs, so it is an
//! at-most-once guard: if the process dies after claiming but before finishing
//! the effect, the effect will not be retried under the same key. When the
//! effect must be retried until it succeeds, key the guard on the *effect's*
//! outcome (claim after success) or drive it through the job queue instead.

use serde_json::Value;
use sqlx::postgres::PgPool;

/// The result of attempting to claim a `(scope, key)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// This caller won the claim — it is the first to see this `(scope, key)`
    /// and should perform the effect.
    Fresh,
    /// The `(scope, key)` was already claimed. Carries the result JSON stored by
    /// the first run, if it recorded one.
    Duplicate(Option<Value>),
}

impl Claim {
    /// True when this caller should perform the effect.
    pub fn is_fresh(&self) -> bool {
        matches!(self, Claim::Fresh)
    }
}

/// Atomically claim `(scope, key)`. Returns [`Claim::Fresh`] to exactly one
/// caller; all others get [`Claim::Duplicate`] with the first run's stored
/// result (if any).
pub async fn claim(pool: &PgPool, scope: &str, key: &str) -> Result<Claim, String> {
    // Insert the claim; the winner gets a returned row, losers get none.
    let inserted: Option<(String,)> = sqlx::query_as(
        "INSERT INTO idempotency_key (scope, key) VALUES ($1, $2) \
         ON CONFLICT (scope, key) DO NOTHING RETURNING scope",
    )
    .bind(scope)
    .bind(key)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("idempotency claim failed: {e}"))?;

    if inserted.is_some() {
        return Ok(Claim::Fresh);
    }

    // Lost the race (or a prior run): fetch whatever result was recorded.
    let prior: Option<(Option<Value>,)> =
        sqlx::query_as("SELECT result FROM idempotency_key WHERE scope = $1 AND key = $2")
            .bind(scope)
            .bind(key)
            .fetch_optional(pool)
            .await
            .map_err(|e| format!("idempotency lookup failed: {e}"))?;
    Ok(Claim::Duplicate(prior.and_then(|(r,)| r)))
}

/// Record (or overwrite) the result stored against an already-claimed
/// `(scope, key)`, so future duplicates can return it. Call after the effect
/// succeeds. A no-op if the key was never claimed.
pub async fn record_result(
    pool: &PgPool,
    scope: &str,
    key: &str,
    result: &Value,
) -> Result<(), String> {
    sqlx::query("UPDATE idempotency_key SET result = $3 WHERE scope = $1 AND key = $2")
        .bind(scope)
        .bind(key)
        .bind(result)
        .execute(pool)
        .await
        .map_err(|e| format!("idempotency record_result failed: {e}"))?;
    Ok(())
}

/// Non-mutating check: has `(scope, key)` been claimed already? Prefer [`claim`]
/// when the check gates an effect — `seen` then `do` has a race that `claim`
/// closes.
pub async fn seen(pool: &PgPool, scope: &str, key: &str) -> Result<bool, String> {
    let found: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM idempotency_key WHERE scope = $1 AND key = $2")
            .bind(scope)
            .bind(key)
            .fetch_optional(pool)
            .await
            .map_err(|e| format!("idempotency seen failed: {e}"))?;
    Ok(found.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fresh_is_fresh_duplicate_is_not() {
        assert!(Claim::Fresh.is_fresh());
        assert!(!Claim::Duplicate(None).is_fresh());
        assert!(!Claim::Duplicate(Some(json!({"id": 1}))).is_fresh());
    }
}
