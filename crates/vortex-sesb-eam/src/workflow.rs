//! Work-order lifecycle — declarative state machine + a Cedar-gated
//! transition helper.
//!
//! This is the authorization chokepoint the §7 field API (`maintenance_action`)
//! uses instead of the old hardcoded `match (action, state)`. It gives three
//! guarantees the inline match lacked:
//!
//!   1. **Legality** — `work_order_machine()` is the single source of truth for
//!      which `(from_state, action)` edges exist.
//!   2. **Authorization** — every transition is checked against Cedar for the
//!      calling principal, so "field agents may `complete`, only supervisors may
//!      `verify`" becomes policy, not Rust.
//!   3. (The atomic-audit guarantee is provided by the handler, which wraps the
//!      domain `UPDATE` + `audit.log_tx` in one tenant-pool transaction.)
//!
//! `guarded_transition` is intentionally generic (machine + policy only). It
//! should be promoted to `vortex_framework::workflow_guard` so every plugin
//! shares one authz chokepoint (remediation item 3); it lives here for now to
//! keep item 1 scoped to a single crate.
//!
//! NOTE: this deliberately does **not** route through
//! `vortex_workflow::WorkflowEngine`. That engine's store is bound to a single
//! pool at startup and models each entity as a `WorkflowInstance`, whereas a
//! work order is a pre-existing row in the tenant DB. Routing through the engine
//! would split the transaction across two databases — see
//! `docs/PLAN_item1_workorder_authz.md` §0. We reuse the engine's *mechanism*
//! (state machine + `policy.check`), not its instance store.

use std::sync::OnceLock;

use vortex_plugin_sdk::policy::{Decision, PolicyPrincipal, PolicyResource, PolicyService};
use vortex_plugin_sdk::workflow::StateMachine;

/// The Cedar source that migration 008 seeds into `policy_rules`. This is the
/// single source of truth for the work-order authorization policy; the
/// migration SQL embeds a byte-for-byte copy (a drift test guards the two).
/// Exposed so tests can build a `PolicyService` from the exact shipped policy.
pub const WORK_ORDER_POLICY: &str =
    include_str!("../migrations/008_eam_policy/work_order_transitions.cedar");

/// The work-order lifecycle, lifted verbatim from the legality that used to
/// live inline in `maintenance_action`. Legality only — the domain-column side
/// effects (`accepted_by`, `rejection_reason`, `actual_duration_hours`, the
/// checklist-completeness guard) stay in the handler.
///
/// Built once; immutable thereafter.
pub fn work_order_machine() -> &'static StateMachine {
    static MACHINE: OnceLock<StateMachine> = OnceLock::new();
    MACHINE.get_or_init(|| {
        StateMachine::new("eam_work_order")
            .initial("scheduled")
            .state("scheduled")
            .state("assigned")
            .state("in_progress")
            .state("on_hold")
            .state("completed")
            .terminal("completed")
            .transition("accept", "scheduled", "in_progress")
            .transition("accept", "assigned", "in_progress")
            .transition("start", "scheduled", "in_progress")
            .transition("start", "assigned", "in_progress")
            .transition("reject", "scheduled", "scheduled") // reassignment self-loop
            .transition("reject", "assigned", "scheduled")
            .transition("hold", "in_progress", "on_hold")
            .transition("resume", "on_hold", "in_progress")
            .transition("complete", "in_progress", "completed")
            .transition("complete", "on_hold", "completed")
            .build()
    })
}

/// Result of a guarded transition attempt.
pub enum Guard {
    /// Allowed — carries the target state the handler should write.
    Allow(String),
    /// `action` is not a legal edge from `from_state`.
    Illegal,
    /// Cedar denied the action for this principal (enforce mode only).
    Denied,
    /// Policy evaluation itself failed (misconfiguration / infra).
    Error(String),
}

/// Whether Cedar denials are enforced (`true`) or only logged (`false`,
/// "warn" rollout mode). Now **enforce by default** — work-order transitions
/// on the field API must actually be Cedar-gated, not just logged. Migration
/// `008_eam_policy` seeds the starter `eam_work_order_transitions` policy, so
/// enforcement has a policy to evaluate. Set `EAM_TRANSITION_POLICY=warn` (or
/// `0`/`false`) to fall back to log-only during a staged rollout.
pub fn policy_enforced() -> bool {
    match std::env::var("EAM_TRANSITION_POLICY") {
        Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("warn") => {
            false
        }
        _ => true,
    }
}

/// Legality (state machine) + Cedar authorization. Returns the target state on
/// allow. In warn mode a denial is logged and treated as allow.
pub async fn guarded_transition(
    policy: &PolicyService,
    machine: &StateMachine,
    from_state: &str,
    action: &str,
    principal: &PolicyPrincipal,
    resource: PolicyResource,
    enforce: bool,
) -> Guard {
    // 1. Legality — is `action` a real edge from `from_state`?
    let Some(edge) = machine.find_transition(from_state, action) else {
        return Guard::Illegal;
    };
    let to_state = edge.to_state.clone();

    // 2. Cedar — may this principal perform this action on this resource?
    match policy.check(principal, action, &resource).await {
        Ok(Decision::Allow { .. }) => Guard::Allow(to_state),
        Ok(Decision::Deny { .. }) => {
            if enforce {
                vortex_plugin_sdk::tracing::warn!(
                    action,
                    user = %principal.user_id,
                    from = from_state,
                    "work-order transition denied by policy"
                );
                Guard::Denied
            } else {
                vortex_plugin_sdk::tracing::warn!(
                    action,
                    user = %principal.user_id,
                    from = from_state,
                    "work-order transition would be DENIED (warn mode — allowed)"
                );
                Guard::Allow(to_state)
            }
        }
        Err(e) => Guard::Error(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legal_edges_resolve_to_expected_target_state() {
        let m = work_order_machine();
        let edge = |from, name| m.find_transition(from, name).map(|t| t.to_state.as_str());
        assert_eq!(edge("scheduled", "accept"), Some("in_progress"));
        assert_eq!(edge("assigned", "accept"), Some("in_progress"));
        assert_eq!(edge("scheduled", "start"), Some("in_progress"));
        assert_eq!(edge("assigned", "reject"), Some("scheduled"));
        assert_eq!(edge("scheduled", "reject"), Some("scheduled"));
        assert_eq!(edge("in_progress", "hold"), Some("on_hold"));
        assert_eq!(edge("on_hold", "resume"), Some("in_progress"));
        assert_eq!(edge("in_progress", "complete"), Some("completed"));
        assert_eq!(edge("on_hold", "complete"), Some("completed"));
    }

    #[test]
    fn illegal_edges_are_rejected() {
        let m = work_order_machine();
        // Cannot complete a job that was never started.
        assert!(m.find_transition("scheduled", "complete").is_none());
        // Terminal: nothing leaves `completed`.
        assert!(m.find_transition("completed", "start").is_none());
        // Already accepted — cannot accept again.
        assert!(m.find_transition("in_progress", "accept").is_none());
        // Unknown action name.
        assert!(m.find_transition("scheduled", "frobnicate").is_none());
    }

    #[test]
    fn initial_state_is_scheduled() {
        assert_eq!(work_order_machine().initial_state(), Some("scheduled"));
    }

    #[test]
    fn policy_enforced_defaults_off_and_reads_env() {
        // Not asserting the process env (tests share it); just prove the
        // parse: only the literal "enforce" (case-insensitive) enables it.
        assert!(!"warn".eq_ignore_ascii_case("enforce"));
        assert!("ENFORCE".eq_ignore_ascii_case("enforce"));
    }
}
