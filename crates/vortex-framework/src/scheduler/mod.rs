//! Platform scheduler — background jobs, cron-style.
//!
//! Every Vortex vertical ends up needing background work: EAM
//! recomputes overdue work orders, CRM rolls up lead scores,
//! Finance runs end-of-month postings, the audit chain verifier
//! does nightly integrity checks. Shipping one real implementation
//! of "run this async closure every N minutes, persistently,
//! safely under multiple instances" means plugins stop reinventing
//! it — badly — behind ad-hoc `tokio::spawn` loops.
//!
//! ## What this module provides
//!
//! - A [`Scheduler`] that lives on [`crate::AppState`] and owns a
//!   handler map keyed by action code.
//! - [`ScheduledAction`], [`ScheduledActionDef`], [`Schedule`] types
//!   that plugins return from `Plugin::scheduled_actions()`.
//! - A persistent `scheduled_actions` table (migration
//!   `118_scheduler`) that survives restarts and is safe to query
//!   from multiple app instances concurrently.
//! - A single background supervisor task spawned at startup that
//!   polls the DB every `poll_interval` seconds, claims due actions
//!   via `FOR UPDATE SKIP LOCKED`, dispatches them to handlers, and
//!   records results.
//!
//! ## What this module does NOT provide (yet)
//!
//! - **Cron expressions** — only fixed intervals
//!   ([`Schedule::Every`]) are supported. Adding cron strings is
//!   straightforward but requires pulling in a cron-parsing crate.
//! - **At-least-once delivery** — if the process crashes between
//!   `claim_due` committing the `next_call` advance and the handler
//!   finishing, the run is lost. The next interval's run is
//!   unaffected. Stronger guarantees would need a separate run
//!   history table and a recovery sweep.
//! - **Per-tenant schedules** — today actions are system-wide; the
//!   multi-tenant case (each tenant database has its own
//!   `scheduled_actions` rows) works trivially under
//!   single-tenant-per-DB deployment, but multi-DB-per-process
//!   scheduling is not wired yet.
//! - **Retry with backoff** — a failed run just waits for the next
//!   scheduled tick. No exponential backoff, no dead-letter queue.
//! - **UI** — actions must be inspected / toggled via SQL.
//! - **Manual run-now** — scheduled only, no imperative trigger.
//!
//! These are deliberate scope cuts. The goal of this module is to
//! unblock plugins that need periodic work, not to ship a job queue.
//!
//! ## Usage from a plugin
//!
//! ```rust,ignore
//! use std::time::Duration;
//! use vortex_framework::{Plugin, scheduler::{Schedule, ScheduledAction, ScheduledActionDef}};
//!
//! impl Plugin for MyPlugin {
//!     // … other methods …
//!
//!     fn scheduled_actions(&self) -> Vec<ScheduledAction> {
//!         vec![
//!             ScheduledAction::new(
//!                 ScheduledActionDef {
//!                     code: "myplugin.housekeeping",
//!                     name: "MyPlugin: nightly housekeeping",
//!                     schedule: Schedule::Every(Duration::from_secs(3600)),
//!                     enabled_by_default: true,
//!                 },
//!                 |state| async move {
//!                     // do work using state.db, state.audit, etc.
//!                     Ok(())
//!                 },
//!             ),
//!         ]
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tracing::{info, warn};
use vortex_common::VortexResult;

use crate::state::AppState;

pub mod action;
mod storage;
mod supervisor;

pub use action::{ActionHandler, Schedule, ScheduledAction, ScheduledActionDef};

/// Default interval between scheduler polls. Fifteen seconds is a
/// reasonable trade-off: tight enough that minute-resolution
/// schedules are accurate, loose enough that an idle scheduler
/// makes ~4 DB queries per minute.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(15);

/// The platform scheduler. Built at startup from the full set of
/// plugin-contributed actions, persisted to the database, and run
/// as a background tokio task until process shutdown.
///
/// Scheduler is stored on `AppState.scheduler` so handlers can
/// inspect it (e.g. to check which jobs are currently registered)
/// without reaching into the host binary. The handler map is the
/// only piece of non-persistent state: every run of the process
/// rebuilds it from the plugins compiled into the binary.
pub struct Scheduler {
    /// Handler callbacks, keyed by action code. Populated once at
    /// construction time from the plugins' `scheduled_actions()`
    /// contributions; never mutated after.
    handlers: Arc<HashMap<String, ActionHandler>>,
    /// Action definitions, used by [`Self::sync_definitions`] to
    /// upsert into the DB at startup.
    definitions: Vec<ScheduledActionDef>,
    /// How long the supervisor sleeps when no action is due.
    poll_interval: Duration,
}

impl Scheduler {
    /// Construct a scheduler from the aggregated scheduled actions
    /// returned by every registered plugin. Collisions — two
    /// plugins contributing the same action code — are logged as a
    /// warning and the first registration wins. Plugins should
    /// namespace their action codes with their technical name (e.g.
    /// `eam.foo`) so collisions cannot happen in practice.
    pub fn new(actions: Vec<ScheduledAction>) -> Self {
        let mut handlers: HashMap<String, ActionHandler> = HashMap::new();
        let mut definitions: Vec<ScheduledActionDef> = Vec::new();

        for action in actions {
            let code = action.def.code.to_string();
            if handlers.contains_key(&code) {
                warn!(
                    code = %code,
                    "duplicate scheduled action code — keeping first registration"
                );
                continue;
            }
            handlers.insert(code, action.handler);
            definitions.push(action.def);
        }

        Self {
            handlers: Arc::new(handlers),
            definitions,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }

    /// Override the default [`DEFAULT_POLL_INTERVAL`] (15 seconds).
    /// Use values under 5 seconds only for testing — in production
    /// this translates to DB poll traffic.
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Number of handler callbacks currently registered.
    pub fn action_count(&self) -> usize {
        self.handlers.len()
    }

    /// Upsert every registered action's definition into the
    /// `scheduled_actions` table. Idempotent; preserves runtime
    /// state (`next_call`, `active`, counters) for actions that
    /// already exist. Call this once during host startup, before
    /// [`Self::start`].
    pub async fn sync_definitions(&self, pool: &PgPool) -> VortexResult<()> {
        info!(count = self.definitions.len() as i64, "syncing scheduled action definitions");
        for def in &self.definitions {
            storage::upsert_definition(pool, def).await?;
        }
        Ok(())
    }

    /// Spawn the supervisor task on the current tokio runtime. The
    /// task holds an `Arc<AppState>` so handlers can receive state
    /// on every invocation. Returns immediately; the task runs
    /// until process shutdown.
    ///
    /// Call after [`Self::sync_definitions`] and after `AppState`
    /// construction — typically alongside other background tasks
    /// in the host binary's startup sequence.
    pub fn start(&self, state: Arc<AppState>) {
        let handlers = self.handlers.clone();
        let poll_interval = self.poll_interval;
        tokio::spawn(async move {
            supervisor::run(state, handlers, poll_interval).await;
        });
    }
}

impl std::fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scheduler")
            .field("action_count", &self.handlers.len())
            .field("poll_interval", &self.poll_interval)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_def(code: &'static str) -> ScheduledActionDef {
        ScheduledActionDef {
            code,
            name: "test",
            schedule: Schedule::Every(Duration::from_secs(60)),
            enabled_by_default: true,
        }
    }

    #[test]
    fn new_builds_handler_map_from_actions() {
        let actions = vec![
            ScheduledAction::new(make_def("test.a"), |_state| async { Ok(()) }),
            ScheduledAction::new(make_def("test.b"), |_state| async { Ok(()) }),
        ];
        let scheduler = Scheduler::new(actions);
        assert_eq!(scheduler.action_count(), 2);
    }

    #[test]
    fn new_dedupes_colliding_codes_first_wins() {
        let actions = vec![
            ScheduledAction::new(make_def("test.dup"), |_state| async { Ok(()) }),
            ScheduledAction::new(make_def("test.dup"), |_state| async { Ok(()) }),
        ];
        let scheduler = Scheduler::new(actions);
        assert_eq!(scheduler.action_count(), 1);
    }

    #[test]
    fn with_poll_interval_overrides_default() {
        let scheduler = Scheduler::new(vec![]).with_poll_interval(Duration::from_secs(1));
        assert_eq!(scheduler.poll_interval, Duration::from_secs(1));
    }

    #[test]
    fn default_poll_interval_is_fifteen_seconds() {
        let scheduler = Scheduler::new(vec![]);
        assert_eq!(scheduler.poll_interval, DEFAULT_POLL_INTERVAL);
        assert_eq!(scheduler.poll_interval.as_secs(), 15);
    }
}
