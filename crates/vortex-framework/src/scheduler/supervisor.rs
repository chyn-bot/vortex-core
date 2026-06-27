//! The background supervisor task: poll the DB for due actions,
//! dispatch them to registered handlers, record results.
//!
//! One supervisor runs per process, spawned from
//! [`crate::scheduler::Scheduler::start`]. It holds an `Arc<AppState>`
//! so it can hand the state to every handler invocation, plus a
//! clone of the scheduler's handler map so it can dispatch by code
//! without looking the map up each iteration.
//!
//! ## Poll loop shape
//!
//! ```text
//! loop {
//!     claim = storage::claim_due(&db)?
//!     match claim {
//!         Some(action) => {
//!             run_handler(action)
//!             storage::record_result(...)
//!         }
//!         None => sleep(poll_interval)
//!     }
//! }
//! ```
//!
//! On any error from `claim_due` the supervisor logs and sleeps —
//! a transient DB failure should not crash the task. There is no
//! retry/backoff logic yet; the next poll tick is the retry.
//!
//! ## Panic isolation
//!
//! Handlers are caught with `tokio::spawn` + `JoinHandle::await` so
//! a panicking handler does not take down the supervisor. The panic
//! message is persisted into `scheduled_actions.last_error` via
//! `record_result` and the supervisor continues to the next tick.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};

use crate::state::AppState;

use super::action::ActionHandler;
use super::storage;

/// Run the supervisor loop forever. This function is spawned as a
/// tokio task by [`crate::scheduler::Scheduler::start`] and returns
/// only on panic (which is caught by `tokio::spawn` and logged by
/// the runtime).
pub(super) async fn run(
    state: Arc<AppState>,
    handlers: Arc<HashMap<String, ActionHandler>>,
    poll_interval: Duration,
) {
    info!(
        poll_interval_secs = poll_interval.as_secs() as i64,
        action_count = handlers.len() as i64,
        "scheduler supervisor started"
    );

    loop {
        match storage::claim_due(&state.db).await {
            Ok(Some(claim)) => {
                // Clone the code out of the claim so the original
                // can be moved into the record_result call below
                // without reborrowing.
                let code_for_dispatch = claim.code.clone();
                let handler = handlers.get(&code_for_dispatch).cloned();

                let outcome: Result<(), String> = match handler {
                    Some(h) => {
                        // Dispatch inside tokio::spawn so a panic in
                        // the handler is caught by the runtime and
                        // surfaced as a JoinError rather than aborting
                        // the supervisor. The state is cloned into the
                        // task; the handler itself decides whether it
                        // needs to clone again internally.
                        let state_for_task = state.clone();
                        let join = tokio::spawn(async move { (h)(state_for_task).await });
                        match join.await {
                            Ok(Ok(())) => Ok(()),
                            Ok(Err(e)) => Err(e.to_string()),
                            Err(join_err) => {
                                if join_err.is_panic() {
                                    Err(format!("handler panicked: {join_err}"))
                                } else {
                                    Err(format!("handler task failed: {join_err}"))
                                }
                            }
                        }
                    }
                    None => {
                        // A definition exists in the DB but no
                        // handler is registered — this happens when
                        // a plugin has been uninstalled without
                        // cleaning up its scheduled_actions rows,
                        // or when the DB is newer than the binary.
                        // Log it as a warning and record an error so
                        // the row doesn't keep getting picked up on
                        // every tick without trace.
                        warn!(
                            code = %code_for_dispatch,
                            "scheduled action has no registered handler — skipping"
                        );
                        Err("no handler registered".to_string())
                    }
                };

                match &outcome {
                    Ok(()) => info!(
                        code = %code_for_dispatch,
                        name = %claim.name,
                        "scheduled action completed"
                    ),
                    Err(e) => error!(
                        code = %code_for_dispatch,
                        name = %claim.name,
                        error = %e,
                        "scheduled action failed"
                    ),
                }

                if let Err(e) =
                    storage::record_result(&state.db, &claim.code, claim.started_at, outcome).await
                {
                    error!(
                        code = %code_for_dispatch,
                        error = %e,
                        "failed to record scheduled action result"
                    );
                }

                // Immediately loop again — if there are more due
                // actions we want to drain them, not sleep. claim_due
                // returns None once the queue is empty.
            }
            Ok(None) => {
                // Nothing due — sleep until the next tick.
                tokio::time::sleep(poll_interval).await;
            }
            Err(e) => {
                // DB hiccup — log and back off by one poll interval.
                error!(error = %e, "scheduler claim_due query failed");
                tokio::time::sleep(poll_interval).await;
            }
        }
    }
}
