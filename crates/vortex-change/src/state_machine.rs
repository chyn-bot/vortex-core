//! CR state machine definition.
//!
//! Six-state workflow covering the full CR lifecycle from initial
//! capture to post-execution closure:
//!
//! ```text
//!    draft ────► submitted ────► under_review ────► approved
//!      │              │               │                │
//!      ▼              ▼               ▼                ▼
//!   withdraw     withdraw         rejected           closed
//! ```
//!
//! - **draft**: requester is still editing. Can be submitted or
//!   withdrawn.
//! - **submitted**: in the queue for initial review. A reviewer
//!   picks it up (→ under_review) or sends it back (→ withdraw).
//! - **under_review**: an approver is actively assessing. They can
//!   approve (→ approved) or reject (→ rejected).
//! - **approved**: the change is authorised. It sits here until
//!   execution is complete, then the requester closes it (→ closed).
//! - **rejected / withdraw / closed**: terminal states. No further
//!   transitions allowed.
//!
//! Cedar policies enforced at the engine level:
//! - requester cannot transition `approve` (segregation of duties)
//! - only `change_approver` or `system_administrator` roles can
//!   trigger `approve`, `reject`, `review`
//! - anyone can `withdraw` their own CR; only admins can withdraw
//!   someone else's

use vortex_workflow::StateMachine;

/// The CR state machine, built fresh each time because `StateMachine`
/// is cheap to construct and the plugin registers it exactly once at
/// startup.
pub fn cr_state_machine() -> StateMachine {
    StateMachine::new("change_request")
        .state("draft")
        .state("submitted")
        .state("under_review")
        .state("approved")
        .state("rejected")
        .state("withdrawn")
        .state("closed")
        .initial("draft")
        .terminal("rejected")
        .terminal("withdrawn")
        .terminal("closed")
        // Happy path
        .transition("submit", "draft", "submitted")
        .transition("review", "submitted", "under_review")
        .transition("approve", "under_review", "approved")
        .transition("close", "approved", "closed")
        // Rejection paths
        .transition("reject", "under_review", "rejected")
        .transition("send_back", "under_review", "submitted")
        // Withdrawal (requester-initiated cancellation)
        .transition("withdraw", "draft", "withdrawn")
        .transition("withdraw", "submitted", "withdrawn")
        .transition("withdraw", "under_review", "withdrawn")
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_transitions_are_defined() {
        let sm = cr_state_machine();
        assert!(sm.find_transition("draft", "submit").is_some());
        assert!(sm.find_transition("submitted", "review").is_some());
        assert!(sm.find_transition("under_review", "approve").is_some());
        assert!(sm.find_transition("approved", "close").is_some());
    }

    #[test]
    fn rejection_paths_are_defined() {
        let sm = cr_state_machine();
        assert!(sm.find_transition("under_review", "reject").is_some());
        assert!(sm.find_transition("under_review", "send_back").is_some());
    }

    #[test]
    fn withdraw_is_available_from_multiple_source_states() {
        let sm = cr_state_machine();
        assert!(sm.find_transition("draft", "withdraw").is_some());
        assert!(sm.find_transition("submitted", "withdraw").is_some());
        assert!(sm.find_transition("under_review", "withdraw").is_some());
        // But not from terminal states
        assert!(sm.find_transition("approved", "withdraw").is_none());
        assert!(sm.find_transition("closed", "withdraw").is_none());
    }

    #[test]
    fn terminal_states_are_marked() {
        let sm = cr_state_machine();
        assert!(sm.is_terminal("rejected"));
        assert!(sm.is_terminal("withdrawn"));
        assert!(sm.is_terminal("closed"));
        assert!(!sm.is_terminal("draft"));
        assert!(!sm.is_terminal("approved"));
    }

    #[test]
    fn initial_state_is_draft() {
        let sm = cr_state_machine();
        assert_eq!(sm.initial_state(), Some("draft"));
    }

    #[test]
    fn cannot_skip_review_from_draft_to_approved() {
        // CLAUDE.md compliance rule: no "convenience" shortcuts
        // bypassing review. Assert the state machine has no direct
        // draft → approved edge.
        let sm = cr_state_machine();
        assert!(sm.find_transition("draft", "approve").is_none());
        assert!(sm.find_transition("submitted", "approve").is_none());
    }
}
