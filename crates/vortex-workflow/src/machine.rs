//! Compile-time state machine definitions.
//!
//! A plugin declares its workflow as a [`StateMachine`] value (usually
//! a `const` or a `lazy_static!`), then registers that machine with
//! the [`crate::WorkflowEngine`] at startup. Machines are immutable
//! once built — state, transition, and action sets are closed.
//!
//! ## Why compile-time rather than DB-driven
//!
//! A DB-driven workflow engine (states and transitions stored in
//! tables, edited via admin UI) sounds flexible but creates an
//! operational nightmare: every admin change risks breaking live
//! instances, every code path needs to defensively handle unknown
//! transitions, and there's no way to statically prove the handler
//! for a given transition exists. Compile-time machines let Rust's
//! type system + code review catch the class of errors that
//! business-process-management tools famously can't.
//!
//! ## Usage
//!
//! ```no_run
//! use vortex_workflow::{StateMachine, Transition};
//!
//! let sm = StateMachine::new("change_request")
//!     .state("draft")
//!     .state("submitted")
//!     .state("under_review")
//!     .state("approved")
//!     .state("rejected")
//!     .state("closed")
//!     .initial("draft")
//!     .terminal("approved")
//!     .terminal("rejected")
//!     .terminal("closed")
//!     .transition("submit", "draft", "submitted")
//!     .transition("review", "submitted", "under_review")
//!     .transition("approve", "under_review", "approved")
//!     .transition("reject", "under_review", "rejected")
//!     .transition("close", "approved", "closed")
//!     .build();
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// The workflow type identifier — a short stable string like
/// `"change_request"` or `"purchase_order"`. Used as the key in the
/// engine's registry and stored on every `WorkflowInstance` row.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkflowType(String);

impl WorkflowType {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for WorkflowType {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for WorkflowType {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl std::fmt::Display for WorkflowType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A single state in a state machine. Just a wrapper around the
/// state name to give callers a typed handle.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct State(String);

impl State {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for State {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// A single transition: named edge with a from-state and a to-state.
/// Multiple transitions can share the same name as long as their
/// from-states differ — the engine looks up by `(from_state, name)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub name: String,
    pub from_state: String,
    pub to_state: String,
}

/// A state machine definition. Built via the builder pattern; once
/// `build()` is called, the machine is immutable and ready to be
/// registered with the engine.
///
/// State machines are keyed by `(from_state, transition_name)` → to_state,
/// so the same transition name (e.g. `"cancel"`) can exist on multiple
/// source states with different target states.
#[derive(Debug, Clone)]
pub struct StateMachine {
    workflow_type: WorkflowType,
    states: HashSet<String>,
    initial_state: Option<String>,
    terminal_states: HashSet<String>,
    /// Map from (from_state, transition_name) to (to_state).
    transitions: HashMap<(String, String), Transition>,
    /// Flat list of transitions in declaration order, for the
    /// `transitions()` accessor used by the inspection CLI.
    transition_list: Vec<Transition>,
}

impl StateMachine {
    /// Start building a state machine with the given workflow type.
    pub fn new(workflow_type: impl Into<String>) -> Self {
        Self {
            workflow_type: WorkflowType::new(workflow_type),
            states: HashSet::new(),
            initial_state: None,
            terminal_states: HashSet::new(),
            transitions: HashMap::new(),
            transition_list: Vec::new(),
        }
    }

    /// Register a state. Calling this multiple times with the same
    /// state name is idempotent.
    pub fn state(mut self, name: impl Into<String>) -> Self {
        self.states.insert(name.into());
        self
    }

    /// Declare the initial state for new instances. Must be a state
    /// already registered via [`Self::state`], but the check is
    /// deferred to [`Self::build`] (if called).
    pub fn initial(mut self, name: impl Into<String>) -> Self {
        self.initial_state = Some(name.into());
        self
    }

    /// Mark a state as terminal — instances that reach it cannot
    /// transition further. The engine uses this for diagnostics only;
    /// a terminal state with outgoing transitions is still accepted
    /// (the engine lets you model "archive" flows where a terminal
    /// can be "reopened").
    pub fn terminal(mut self, name: impl Into<String>) -> Self {
        self.terminal_states.insert(name.into());
        self
    }

    /// Register a transition. `from` and `to` must be states
    /// registered via [`Self::state`]. The `name` is the identifier
    /// the engine uses to look up this edge (e.g. `"submit"`).
    pub fn transition(
        mut self,
        name: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
    ) -> Self {
        let name = name.into();
        let from = from.into();
        let to = to.into();
        let t = Transition {
            name: name.clone(),
            from_state: from.clone(),
            to_state: to,
        };
        self.transitions.insert((from, name), t.clone());
        self.transition_list.push(t);
        self
    }

    /// Finalize the state machine. No further modifications allowed
    /// after this returns. The type here is `Self` rather than a
    /// distinct `BuiltStateMachine` type because Rust's move semantics
    /// make the before/after distinction cheap to enforce by convention.
    pub fn build(self) -> Self {
        self
    }

    // ─── Accessors ─────────────────────────────────────────────

    pub fn workflow_type(&self) -> &WorkflowType {
        &self.workflow_type
    }

    pub fn states(&self) -> impl Iterator<Item = &str> {
        self.states.iter().map(|s| s.as_str())
    }

    pub fn initial_state(&self) -> Option<&str> {
        self.initial_state.as_deref()
    }

    pub fn is_terminal(&self, state: &str) -> bool {
        self.terminal_states.contains(state)
    }

    pub fn has_state(&self, state: &str) -> bool {
        self.states.contains(state)
    }

    /// Find a transition by (from_state, transition_name). Returns
    /// the target state if the transition is valid from the current
    /// state, or `None` if no such transition exists.
    pub fn find_transition(&self, from_state: &str, name: &str) -> Option<&Transition> {
        self.transitions
            .get(&(from_state.to_string(), name.to_string()))
    }

    /// All valid transitions from a given state (used by UI for
    /// rendering "what can I do next?" action lists).
    pub fn transitions_from(&self, from_state: &str) -> Vec<&Transition> {
        self.transitions
            .iter()
            .filter_map(|((from, _), t)| {
                if from == from_state {
                    Some(t)
                } else {
                    None
                }
            })
            .collect()
    }

    /// All transitions in declaration order.
    pub fn all_transitions(&self) -> &[Transition] {
        &self.transition_list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cr_machine() -> StateMachine {
        StateMachine::new("change_request")
            .state("draft")
            .state("submitted")
            .state("approved")
            .state("rejected")
            .initial("draft")
            .terminal("approved")
            .terminal("rejected")
            .transition("submit", "draft", "submitted")
            .transition("approve", "submitted", "approved")
            .transition("reject", "submitted", "rejected")
            .transition("withdraw", "draft", "rejected")
            .build()
    }

    #[test]
    fn state_machine_basics() {
        let sm = cr_machine();
        assert_eq!(sm.workflow_type().as_str(), "change_request");
        assert!(sm.has_state("draft"));
        assert!(sm.has_state("approved"));
        assert!(!sm.has_state("nonsense"));
        assert_eq!(sm.initial_state(), Some("draft"));
    }

    #[test]
    fn terminal_states_detected() {
        let sm = cr_machine();
        assert!(sm.is_terminal("approved"));
        assert!(sm.is_terminal("rejected"));
        assert!(!sm.is_terminal("draft"));
    }

    #[test]
    fn find_transition_returns_valid_edge() {
        let sm = cr_machine();
        let t = sm.find_transition("submitted", "approve").unwrap();
        assert_eq!(t.to_state, "approved");
    }

    #[test]
    fn find_transition_returns_none_for_invalid_source() {
        let sm = cr_machine();
        // "approve" is defined, but not from "draft"
        assert!(sm.find_transition("draft", "approve").is_none());
    }

    #[test]
    fn find_transition_returns_none_for_unknown_name() {
        let sm = cr_machine();
        assert!(sm.find_transition("submitted", "time_travel").is_none());
    }

    #[test]
    fn transitions_from_lists_all_valid_exits() {
        let sm = cr_machine();
        let from_draft = sm.transitions_from("draft");
        assert_eq!(from_draft.len(), 2);
        let names: HashSet<&str> = from_draft.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains("submit"));
        assert!(names.contains("withdraw"));
    }

    #[test]
    fn all_transitions_is_ordered_by_declaration() {
        let sm = cr_machine();
        let ts = sm.all_transitions();
        assert_eq!(ts.len(), 4);
        assert_eq!(ts[0].name, "submit");
        assert_eq!(ts[3].name, "withdraw");
    }

    #[test]
    fn same_transition_name_different_source_states() {
        // Real workflows often have "cancel" from multiple states.
        let sm = StateMachine::new("cancel_demo")
            .state("draft")
            .state("submitted")
            .state("cancelled")
            .transition("cancel", "draft", "cancelled")
            .transition("cancel", "submitted", "cancelled")
            .build();
        assert!(sm.find_transition("draft", "cancel").is_some());
        assert!(sm.find_transition("submitted", "cancel").is_some());
    }
}
