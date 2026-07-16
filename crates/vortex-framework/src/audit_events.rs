//! WORM audit helper for the batch / rules / snapshot core primitives.
//!
//! Core policy (see the workspace CLAUDE.md) is that every state-changing
//! operation is written to the tamper-evident WORM ledger via
//! [`AppState::audit`] — never a raw insert. The batch engine's operator
//! actions and the governance actions on rules and snapshots (publishing a rule
//! version, sealing a snapshot) are exactly the events a regulated deployment
//! must be able to attribute to a person months later, so they go through here.
//!
//! The engine's low-level functions stay pure (`pool`-only) so system-triggered
//! callers with no human actor can use them; the `*_audited` wrappers and this
//! helper are for the caller that *does* have a user in hand (an admin action, a
//! trigger adapter carrying a session).

use serde_json::Value;

use vortex_common::UserId;
use vortex_security::{AuditAction, AuditEntry, AuditSeverity};

use crate::auth::AuthUser;
use crate::state::AppState;

/// Emit a WORM audit event for a core state change, attributed to `user`.
///
/// Best-effort by design: a ledger write failure is logged, not propagated —
/// the underlying operation already committed, and failing the caller because
/// the ledger was briefly unhealthy would be worse than a logged gap (the
/// nightly chain verify surfaces real tampering regardless). This mirrors the
/// reports endpoint's audit handling.
pub async fn emit(
    state: &AppState,
    user: &AuthUser,
    action_code: &str,
    resource_type: &str,
    resource_id: impl Into<String>,
    details: Value,
) {
    let entry = AuditEntry::new(
        AuditAction::Custom(action_code.to_string()),
        AuditSeverity::Info,
    )
    .with_user(UserId(user.id))
    .with_username(user.username.clone())
    .with_session(user.session_id)
    .with_resource(resource_type, resource_id)
    .with_details(details);

    if let Err(e) = state.audit.log(entry).await {
        tracing::warn!(action = action_code, error = %e, "failed to write audit event");
    }
}
