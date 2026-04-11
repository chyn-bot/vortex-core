//! Runtime workflow instance data — one row in `workflow_instances`.
//!
//! A [`WorkflowInstance`] is the living, mutable half of a workflow:
//! the current state, the JSON state data (fields the workflow tracks
//! but that don't belong in a dedicated table yet), the tenant scope,
//! and the audit timestamps.
//!
//! The immutable half — states, transitions, legal edges — lives in
//! the [`crate::StateMachine`] that the engine has registered for the
//! instance's workflow type. The engine matches them up every time
//! it loads an instance to perform a transition.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::machine::WorkflowType;

/// Strongly-typed wrapper around the workflow instance UUID.
/// Matches CLAUDE.md's "use typed IDs" guidance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InstanceId(pub Uuid);

impl InstanceId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for InstanceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for InstanceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A running workflow instance — one row in `workflow_instances`.
///
/// `state_data` is a free-form JSON blob where plugins store
/// workflow-scoped fields that don't justify their own column (e.g.
/// "approver_notes", "amount", "requested_by"). The schema of this
/// blob is a private contract between the plugin and its own
/// handlers; the engine treats it as opaque.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowInstance {
    pub id: InstanceId,
    pub workflow_type: WorkflowType,
    pub current_state: String,
    pub state_data: serde_json::Value,
    /// Company / tenant scope. Matches the `company_id` on every
    /// multi-tenant record and is used by Cedar policies and WORM
    /// audit chain scoping.
    pub company_id: Uuid,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl WorkflowInstance {
    /// Convenience constructor for the "fresh instance" case —
    /// typically called from a handler that creates a new business
    /// record (a new CR, PO, incident, etc.) and wants a
    /// `WorkflowInstance` in the machine's initial state.
    pub fn new(
        workflow_type: impl Into<WorkflowType>,
        initial_state: impl Into<String>,
        company_id: Uuid,
        created_by: Uuid,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: InstanceId::new(),
            workflow_type: workflow_type.into(),
            current_state: initial_state.into(),
            state_data: serde_json::Value::Null,
            company_id,
            created_by,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_state_data(mut self, data: serde_json::Value) -> Self {
        self.state_data = data;
        self
    }
}
