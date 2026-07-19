//! Trial vs live run mode — one compute path, a gated sink.
//!
//! A trial (dry / staging) run must exercise the *identical* calculation as a
//! live one — otherwise the trial proves nothing — and differ only in what it
//! does with the result: a live run posts to the GL, submits the e-invoice, and
//! notifies the customer; a trial run does none of those. The failure mode this
//! primitive prevents is a `if trial { ... } else { ... }` fork drifting until
//! the two paths compute different numbers.
//!
//! [`RunMode`] makes the distinction a single value threaded through the
//! pipeline, and [`RunMode::perform`] is the one place a side-effect is gated:
//! wrap each external effect in it, and trial mode skips exactly the effects and
//! nothing else. It is **core** — any vertical with a preview/simulate mode
//! reuses it.
//!
//! # Example
//!
//! ```rust,ignore
//! // In a batch processor: derive the mode from the run, compute unconditionally,
//! // gate only the side-effects.
//! let mode = RunMode::from_trial(ctx.trial);
//! let bill = assemble_bill(&snapshot)?;                 // same in both modes
//! mode.perform("gl.post", || post_to_ledger(&bill)).await?;
//! mode.perform("einvoice.submit", || submit_einvoice(&bill)).await?;
//! ```

use std::future::Future;

/// Whether a run's side-effects actually happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    /// Real run: side-effects execute.
    Live,
    /// Dry run: the same computation runs, but side-effects are suppressed.
    Trial,
}

/// The result of a gated side-effect: either it ran (`Performed`) or trial mode
/// skipped it (`Suppressed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SideEffect<T> {
    Performed(T),
    Suppressed,
}

impl<T> SideEffect<T> {
    /// The produced value if the effect ran, else `None`.
    pub fn performed(self) -> Option<T> {
        match self {
            SideEffect::Performed(v) => Some(v),
            SideEffect::Suppressed => None,
        }
    }
    pub fn was_suppressed(&self) -> bool {
        matches!(self, SideEffect::Suppressed)
    }
}

impl RunMode {
    /// Map a boolean `trial` flag (as carried on a batch run) to a mode.
    pub fn from_trial(trial: bool) -> Self {
        if trial {
            RunMode::Trial
        } else {
            RunMode::Live
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(self, RunMode::Live)
    }
    pub fn is_trial(&self) -> bool {
        matches!(self, RunMode::Trial)
    }

    /// Short label for logs / UI.
    pub fn label(&self) -> &'static str {
        match self {
            RunMode::Live => "live",
            RunMode::Trial => "trial",
        }
    }

    /// Perform a side-effect only in [`RunMode::Live`]. In [`RunMode::Trial`]
    /// the closure is never invoked — the effect is skipped and a trace line is
    /// emitted naming it — and [`SideEffect::Suppressed`] is returned.
    ///
    /// `name` identifies the effect for the suppressed-run log (e.g. `gl.post`).
    pub async fn perform<T, F, Fut>(&self, name: &str, effect: F) -> SideEffect<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        match self {
            RunMode::Live => SideEffect::Performed(effect().await),
            RunMode::Trial => {
                tracing::debug!(effect = name, "trial run: side-effect suppressed");
                SideEffect::Suppressed
            }
        }
    }

    /// Like [`perform`](Self::perform) but for fallible effects: in live mode
    /// returns the closure's `Result`; in trial mode returns `Ok(Suppressed)`
    /// without running it.
    pub async fn try_perform<T, E, F, Fut>(
        &self,
        name: &str,
        effect: F,
    ) -> Result<SideEffect<T>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        match self {
            RunMode::Live => Ok(SideEffect::Performed(effect().await?)),
            RunMode::Trial => {
                tracing::debug!(effect = name, "trial run: side-effect suppressed");
                Ok(SideEffect::Suppressed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_flag_and_predicates() {
        assert_eq!(RunMode::from_trial(false), RunMode::Live);
        assert_eq!(RunMode::from_trial(true), RunMode::Trial);
        assert!(RunMode::Live.is_live());
        assert!(RunMode::Trial.is_trial());
        assert_eq!(RunMode::Trial.label(), "trial");
    }

    #[tokio::test]
    async fn live_runs_effect_trial_suppresses() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = AtomicUsize::new(0);

        let r = RunMode::Live
            .perform("x", || async {
                calls.fetch_add(1, Ordering::SeqCst);
                42
            })
            .await;
        assert_eq!(r, SideEffect::Performed(42));

        let r = RunMode::Trial
            .perform("x", || async {
                calls.fetch_add(1, Ordering::SeqCst);
                42
            })
            .await;
        assert!(r.was_suppressed());
        // Trial never invoked the closure.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn try_perform_propagates_and_gates() {
        let live: Result<SideEffect<i32>, String> = RunMode::Live
            .try_perform("x", || async { Ok(7) })
            .await;
        assert_eq!(live.unwrap(), SideEffect::Performed(7));

        let err: Result<SideEffect<i32>, String> = RunMode::Live
            .try_perform("x", || async { Err("boom".to_string()) })
            .await;
        assert!(err.is_err());

        let trial: Result<SideEffect<i32>, String> = RunMode::Trial
            .try_perform("x", || async { panic!("must not run") })
            .await;
        assert!(trial.unwrap().was_suppressed());
    }
}
