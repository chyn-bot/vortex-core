//! Workflow error types.

use thiserror::Error;

pub type WorkflowResult<T> = Result<T, WorkflowError>;

#[derive(Debug, Error)]
pub enum WorkflowError {
    /// The workflow type on the instance does not match any registered
    /// state machine. This is a programming error — the engine's
    /// registry was built without the required state machine.
    #[error("unknown workflow type '{0}'")]
    UnknownWorkflow(String),

    /// The current state on the instance is not in the state machine's
    /// declared state set. Indicates external modification of the
    /// instance row or a mismatch between the state machine definition
    /// and what's in the database.
    #[error("instance is in state '{state}' which is not defined by workflow '{workflow}'")]
    UnknownState { workflow: String, state: String },

    /// The requested transition does not exist in the state machine.
    #[error("workflow '{workflow}' has no transition named '{transition}'")]
    UnknownTransition { workflow: String, transition: String },

    /// The requested transition exists but not from the current state.
    /// This is the "invalid transition" case — the state machine has
    /// `submit` defined but you tried to trigger it from the `approved`
    /// state, which is not a valid source for `submit`.
    #[error(
        "workflow '{workflow}' transition '{transition}' is not valid from state '{from_state}'"
    )]
    InvalidTransition {
        workflow: String,
        transition: String,
        from_state: String,
    },

    /// Cedar policy denied the transition.
    #[error("policy denied transition '{transition}' for principal {principal}: {reason}")]
    PolicyDenied {
        transition: String,
        principal: String,
        reason: String,
    },

    /// Workflow instance not found by id.
    #[error("workflow instance not found: {0}")]
    InstanceNotFound(uuid::Uuid),

    /// Database access failure.
    #[error("workflow store error: {0}")]
    Store(String),

    /// Audit ledger write failure during a transition — the transition
    /// is not committed in this case because the audit write is part
    /// of the same transaction as the state update.
    #[error("audit write failed during transition: {0}")]
    AuditFailed(String),

    /// An internal invariant broke — means the engine has a bug.
    #[error("workflow engine internal error: {0}")]
    Internal(String),
}

impl From<vortex_common::VortexError> for WorkflowError {
    fn from(e: vortex_common::VortexError) -> Self {
        WorkflowError::Store(e.to_string())
    }
}
