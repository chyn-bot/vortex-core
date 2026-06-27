//! Types plugins use to declare scheduled background actions.
//!
//! A plugin contributes zero or more [`ScheduledAction`]s via the
//! `Plugin::scheduled_actions()` trait method. Each action pairs a
//! declarative [`ScheduledActionDef`] (the stable identity, display
//! name, and firing schedule) with a callable [`ActionHandler`] (the
//! async function that runs when the action fires).
//!
//! The split exists because the *definition* is what gets persisted
//! into the `scheduled_actions` table at startup — it is data,
//! survives restarts, and is visible to administrators in the DB. The
//! *handler* is a closure that captures plugin state and is only live
//! inside the running process; it's re-registered every startup from
//! the plugin's compiled code.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use vortex_common::VortexResult;

use crate::state::AppState;

/// How frequently a scheduled action fires.
///
/// Today only `Every(Duration)` — fixed real-time interval — is
/// supported. Cron-expression schedules (`Schedule::Cron("0 3 * * *")`)
/// are reserved for a later iteration; adding them will not change the
/// existing `Every` path.
#[derive(Debug, Clone, Copy)]
pub enum Schedule {
    /// Fire every N real-time seconds, independent of wall-clock
    /// time. The counter advances from `next_call` by this interval
    /// after each run, so a job that takes 30s to execute still
    /// fires exactly on schedule.
    Every(Duration),
}

impl Schedule {
    /// The interval in whole seconds, rounded down. Used by the
    /// storage layer to persist the schedule into the
    /// `scheduled_actions.interval_seconds` column.
    pub fn interval_seconds(&self) -> i64 {
        match self {
            Schedule::Every(d) => d.as_secs() as i64,
        }
    }
}

/// Declarative definition of a plugin-contributed scheduled action.
///
/// Everything here is a plain-data description: no handler, no
/// runtime state. The host persists a copy of this into
/// `scheduled_actions` on startup so administrators can see and
/// toggle plugin jobs without a code change. When the plugin's code
/// changes (e.g. interval bumped from 10 min to 5 min) the startup
/// sync upserts the new values.
///
/// ## Code namespacing
///
/// `code` must be globally unique across all plugins — the standard
/// convention is `<plugin_technical_name>.<job_name>`, e.g.
/// `eam.work_order_overdue_check` or `crm.lead_score_recompute`.
#[derive(Debug, Clone)]
pub struct ScheduledActionDef {
    /// Globally-unique action code. Used as the primary key in the
    /// `scheduled_actions` table and as the dispatch key into the
    /// scheduler's handler map.
    pub code: &'static str,
    /// Human-readable display name, shown in admin UI and logs.
    pub name: &'static str,
    /// How often this action fires.
    pub schedule: Schedule,
    /// Whether to enable the action the first time its definition is
    /// inserted. Ignored on subsequent startups — the DB is the
    /// source of truth for runtime state.
    pub enabled_by_default: bool,
}

/// A pinned, boxed, send-safe async handler callback. This is the
/// type stored in the scheduler's handler map after plugins register
/// their actions. Use [`ScheduledAction::new`] to construct one from
/// an ordinary async closure.
pub type ActionHandler = Arc<
    dyn Fn(Arc<AppState>) -> Pin<Box<dyn Future<Output = VortexResult<()>> + Send>>
        + Send
        + Sync,
>;

/// A complete scheduled action contribution from a plugin: the
/// declarative definition plus the callable handler.
///
/// Construct with [`ScheduledAction::new`], which adapts any
/// `async fn(Arc<AppState>) -> VortexResult<()>`-shaped closure into
/// the boxed handler type the scheduler stores.
#[derive(Clone)]
pub struct ScheduledAction {
    pub def: ScheduledActionDef,
    pub handler: ActionHandler,
}

impl ScheduledAction {
    /// Wrap a plain async closure into a `ScheduledAction`.
    ///
    /// ```rust,ignore
    /// use std::time::Duration;
    /// use vortex_framework::scheduler::{Schedule, ScheduledAction, ScheduledActionDef};
    ///
    /// ScheduledAction::new(
    ///     ScheduledActionDef {
    ///         code: "eam.wo_overdue_check",
    ///         name: "EAM: mark overdue work orders",
    ///         schedule: Schedule::Every(Duration::from_secs(600)),
    ///         enabled_by_default: true,
    ///     },
    ///     |state| async move {
    ///         // … sqlx::query!("UPDATE eam_work_orders SET …")
    ///         //     .execute(&state.db).await?;
    ///         Ok(())
    ///     },
    /// )
    /// ```
    pub fn new<F, Fut>(def: ScheduledActionDef, handler: F) -> Self
    where
        F: Fn(Arc<AppState>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = VortexResult<()>> + Send + 'static,
    {
        Self {
            def,
            handler: Arc::new(move |state: Arc<AppState>| Box::pin(handler(state))),
        }
    }
}

impl std::fmt::Debug for ScheduledAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScheduledAction")
            .field("def", &self.def)
            .field("handler", &"<fn>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_every_interval_seconds() {
        assert_eq!(Schedule::Every(Duration::from_secs(600)).interval_seconds(), 600);
        assert_eq!(Schedule::Every(Duration::from_secs(5)).interval_seconds(), 5);
    }

    #[test]
    fn schedule_every_truncates_sub_second() {
        // Sub-second intervals are meaningless for a cron-style poller
        // and round down to 0 when persisted. That's acceptable —
        // intervals below the poll interval will fire every poll tick.
        assert_eq!(
            Schedule::Every(Duration::from_millis(500)).interval_seconds(),
            0
        );
    }
}
