//! Error types for the policy engine.

use thiserror::Error;

pub type PolicyResult<T> = Result<T, PolicyError>;

#[derive(Debug, Error)]
pub enum PolicyError {
    /// Failure to parse a Cedar policy document. The offending policy's
    /// database id is included when available so operators can find it.
    #[error("failed to parse Cedar policy '{policy_id}': {reason}")]
    ParseFailed { policy_id: String, reason: String },

    /// Failure to build a Cedar Entity from Vortex domain data.
    #[error("failed to build policy entity: {0}")]
    EntityBuild(String),

    /// Failure to construct a Cedar Request (usually malformed EUID).
    #[error("failed to build policy request: {0}")]
    RequestBuild(String),

    /// Database access failure.
    #[error("policy store database error: {0}")]
    Store(String),

    /// The policy evaluation itself failed (usually a runtime error in
    /// a `when` clause).
    #[error("policy evaluation failed: {0}")]
    Evaluation(String),
}
