//! Immutable Audit Logging - NERC CIP-007 / CIP-010 Compliance
//!
//! Provides tamper-evident, cryptographically-chained, WORM audit logging
//! for all security-relevant events. The on-disk ledger uses a per-tenant
//! SHA-256 hash chain with optional Ed25519 signatures over each entry.
//!
//! Submodules:
//! - [`canonical`] — RFC 8785 JSON Canonicalization Scheme used to produce
//!   the deterministic byte sequence that gets hashed and signed.
//! - [`pg`] — Postgres-backed [`AuditStorage`] implementation with per-tenant
//!   chain heads, `FOR UPDATE` serialization, and atomic transactional writes.
//!
//! The in-memory [`MemoryAuditStorage`] remains for unit tests and local
//! development; it does **not** provide tamper-evidence and must never be
//! used in production.

pub mod canonical;
pub mod pg;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;
use uuid::Uuid;
use vortex_common::{CompanyId, UserId, VortexResult};

pub use pg::PgAuditStorage;

/// Audit action types per NERC CIP-007-6 R5 and CIP-010-4 R1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    // Authentication events (CIP-007-6 R5.1)
    LoginSuccess,
    LoginFailure,
    Logout,
    SessionTimeout,
    PasswordChange,
    PasswordReset,
    MfaChallenge,
    MfaSuccess,
    MfaFailure,

    // Authorization events (CIP-004-7 R4)
    AccessGranted,
    AccessDenied,
    PermissionChange,
    RoleAssigned,
    RoleRevoked,

    // User lifecycle (CIP-004-7 R4)
    UserCreated,
    UserUpdated,
    UserLocked,
    UserUnlocked,

    // Data events
    RecordCreated,
    RecordUpdated,
    RecordDeleted,
    RecordViewed,
    BulkExport,

    // Configuration events (CIP-010-4 R1)
    ConfigChanged,
    SystemStartup,
    SystemShutdown,
    ModuleLoaded,
    ModuleUnloaded,

    // Security events
    SecurityAlert,
    IntrusionAttempt,
    RateLimitExceeded,
    InvalidToken,

    // Audit self-attestation (CIP-007-6 R5.5)
    GenesisCreated,
    ChainVerificationPassed,
    ChainVerificationFailed,
    KeyRotated,
    TriggerDisabled,

    // Custom action
    Custom(String),
}

impl AuditAction {
    /// Stable, lowercase string code for the action. Used as the
    /// `audit_log.action` column value and as a field in the canonical
    /// payload. Must never change for a given variant — changing the code
    /// would break all verification of historical entries.
    pub fn code(&self) -> String {
        match self {
            AuditAction::LoginSuccess => "login_success".into(),
            AuditAction::LoginFailure => "login_failure".into(),
            AuditAction::Logout => "logout".into(),
            AuditAction::SessionTimeout => "session_timeout".into(),
            AuditAction::PasswordChange => "password_change".into(),
            AuditAction::PasswordReset => "password_reset".into(),
            AuditAction::MfaChallenge => "mfa_challenge".into(),
            AuditAction::MfaSuccess => "mfa_success".into(),
            AuditAction::MfaFailure => "mfa_failure".into(),
            AuditAction::AccessGranted => "access_granted".into(),
            AuditAction::AccessDenied => "access_denied".into(),
            AuditAction::PermissionChange => "permission_change".into(),
            AuditAction::RoleAssigned => "role_assigned".into(),
            AuditAction::RoleRevoked => "role_revoked".into(),
            AuditAction::UserCreated => "user_created".into(),
            AuditAction::UserUpdated => "user_updated".into(),
            AuditAction::UserLocked => "user_locked".into(),
            AuditAction::UserUnlocked => "user_unlocked".into(),
            AuditAction::RecordCreated => "record_created".into(),
            AuditAction::RecordUpdated => "record_updated".into(),
            AuditAction::RecordDeleted => "record_deleted".into(),
            AuditAction::RecordViewed => "record_viewed".into(),
            AuditAction::BulkExport => "bulk_export".into(),
            AuditAction::ConfigChanged => "config_changed".into(),
            AuditAction::SystemStartup => "system_startup".into(),
            AuditAction::SystemShutdown => "system_shutdown".into(),
            AuditAction::ModuleLoaded => "module_loaded".into(),
            AuditAction::ModuleUnloaded => "module_unloaded".into(),
            AuditAction::SecurityAlert => "security_alert".into(),
            AuditAction::IntrusionAttempt => "intrusion_attempt".into(),
            AuditAction::RateLimitExceeded => "rate_limit_exceeded".into(),
            AuditAction::InvalidToken => "invalid_token".into(),
            AuditAction::GenesisCreated => "genesis_created".into(),
            AuditAction::ChainVerificationPassed => "chain_verification_passed".into(),
            AuditAction::ChainVerificationFailed => "chain_verification_failed".into(),
            AuditAction::KeyRotated => "key_rotated".into(),
            AuditAction::TriggerDisabled => "trigger_disabled".into(),
            AuditAction::Custom(s) => format!("custom:{s}"),
        }
    }

    /// Get the CIP requirement this action relates to.
    pub fn cip_requirement(&self) -> &'static str {
        match self {
            AuditAction::LoginSuccess
            | AuditAction::LoginFailure
            | AuditAction::Logout
            | AuditAction::SessionTimeout
            | AuditAction::PasswordChange
            | AuditAction::PasswordReset
            | AuditAction::MfaChallenge
            | AuditAction::MfaSuccess
            | AuditAction::MfaFailure => "CIP-007-6 R5",

            AuditAction::AccessGranted
            | AuditAction::AccessDenied
            | AuditAction::PermissionChange
            | AuditAction::RoleAssigned
            | AuditAction::RoleRevoked
            | AuditAction::UserCreated
            | AuditAction::UserUpdated
            | AuditAction::UserLocked
            | AuditAction::UserUnlocked => "CIP-004-7 R4",

            AuditAction::ConfigChanged
            | AuditAction::SystemStartup
            | AuditAction::SystemShutdown
            | AuditAction::ModuleLoaded
            | AuditAction::ModuleUnloaded => "CIP-010-4 R1",

            AuditAction::GenesisCreated
            | AuditAction::ChainVerificationPassed
            | AuditAction::ChainVerificationFailed
            | AuditAction::KeyRotated
            | AuditAction::TriggerDisabled => "CIP-007-6 R5.5",

            _ => "CIP-007-6",
        }
    }

    /// Check if this is a security-critical event that requires immediate alerting.
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            AuditAction::LoginFailure
                | AuditAction::MfaFailure
                | AuditAction::AccessDenied
                | AuditAction::SecurityAlert
                | AuditAction::IntrusionAttempt
                | AuditAction::RateLimitExceeded
                | AuditAction::ChainVerificationFailed
                | AuditAction::TriggerDisabled
        )
    }
}

/// Severity level for audit entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditSeverity {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl AuditSeverity {
    pub fn code(&self) -> &'static str {
        match self {
            AuditSeverity::Debug => "debug",
            AuditSeverity::Info => "info",
            AuditSeverity::Warning => "warning",
            AuditSeverity::Error => "error",
            AuditSeverity::Critical => "critical",
        }
    }
}

/// A single audit event captured at the application layer.
///
/// This struct is the **caller-facing** shape. When a `PgAuditStorage`
/// persists an entry, it first projects this into an [`pg::AuditDbRow`]
/// whose JCS canonicalization is what actually gets hashed and signed. See
/// [`canonical`] for the serialization format and [`pg`] for the write path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID (UUID v7 for time-ordering).
    pub id: Uuid,
    /// When the event occurred (application clock).
    pub timestamp: DateTime<Utc>,
    /// The action that was performed.
    pub action: AuditAction,
    /// Severity level.
    pub severity: AuditSeverity,
    /// User who performed the action (if authenticated).
    pub user_id: Option<UserId>,
    /// Denormalized username for audit persistence (survives user deletion).
    pub username: Option<String>,
    /// Company / tenant context (required for chain scoping).
    pub company_id: Option<CompanyId>,
    /// Session ID for correlation.
    pub session_id: Option<Uuid>,
    /// Request ID for tracing.
    pub request_id: Option<Uuid>,
    /// Source IP address.
    pub source_ip: Option<String>,
    /// User agent.
    pub user_agent: Option<String>,
    /// Resource affected (model/table name).
    pub resource: Option<String>,
    /// Resource ID affected.
    pub resource_id: Option<String>,
    /// Resource display name (denormalized).
    pub resource_name: Option<String>,
    /// Whether the action succeeded.
    pub success: bool,
    /// Error message if the action failed.
    pub error_message: Option<String>,
    /// Action-specific details.
    pub details: serde_json::Value,
    /// Previous state for change tracking.
    pub previous_state: Option<serde_json::Value>,
    /// New state for change tracking.
    pub new_state: Option<serde_json::Value>,
    /// CIP requirement reference (denormalized from `action.cip_requirement()`).
    pub cip_reference: String,
}

impl AuditEntry {
    /// Create a new audit entry.
    pub fn new(action: AuditAction, severity: AuditSeverity) -> Self {
        let cip_reference = action.cip_requirement().to_string();
        Self {
            id: Uuid::now_v7(),
            timestamp: Utc::now(),
            action,
            severity,
            user_id: None,
            username: None,
            company_id: None,
            session_id: None,
            request_id: None,
            source_ip: None,
            user_agent: None,
            resource: None,
            resource_id: None,
            resource_name: None,
            success: true,
            error_message: None,
            details: serde_json::Value::Null,
            previous_state: None,
            new_state: None,
            cip_reference,
        }
    }

    pub fn with_user(mut self, user_id: UserId) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn with_company(mut self, company_id: CompanyId) -> Self {
        self.company_id = Some(company_id);
        self
    }

    pub fn with_session(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn with_request(mut self, request_id: Uuid) -> Self {
        self.request_id = Some(request_id);
        self
    }

    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    pub fn with_user_agent(mut self, agent: impl Into<String>) -> Self {
        self.user_agent = Some(agent.into());
        self
    }

    pub fn with_resource(mut self, resource: impl Into<String>, id: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self.resource_id = Some(id.into());
        self
    }

    pub fn with_resource_name(mut self, name: impl Into<String>) -> Self {
        self.resource_name = Some(name.into());
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }

    pub fn with_change(
        mut self,
        previous: Option<serde_json::Value>,
        new: Option<serde_json::Value>,
    ) -> Self {
        self.previous_state = previous;
        self.new_state = new;
        self
    }

    pub fn with_success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.success = false;
        self.error_message = Some(error.into());
        self
    }
}

/// Audit log storage interface.
///
/// Implementations are responsible for the actual persistence of audit
/// entries. The [`PgAuditStorage`] implementation additionally enforces the
/// cryptographic chain; callers must not bypass it by writing directly to
/// the `audit_log` table.
#[async_trait::async_trait]
pub trait AuditStorage: Send + Sync {
    /// Write an audit entry, opening an internal transaction if necessary.
    async fn write(&self, entry: AuditEntry) -> VortexResult<()>;

    /// Write an audit entry on an existing caller-owned transaction.
    ///
    /// This is the primitive used when the caller is already inside a
    /// transaction that modifies business data: the audit write must commit
    /// atomically with the business mutation. If the caller's transaction
    /// rolls back, the audit write rolls back with it. Implementations that
    /// cannot participate in the caller's transaction (e.g. the in-memory
    /// storage) should log a warning and degrade to a best-effort direct
    /// write — never silently drop the entry.
    async fn write_tx<'c>(
        &self,
        entry: AuditEntry,
        tx: &mut sqlx::Transaction<'c, sqlx::Postgres>,
    ) -> VortexResult<()>;

    /// Query audit entries.
    async fn query(&self, filter: AuditFilter) -> VortexResult<Vec<AuditEntry>>;

    /// Get entry count matching the filter.
    async fn count(&self, filter: AuditFilter) -> VortexResult<u64>;
}

/// Filter for querying audit logs.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub user_id: Option<UserId>,
    pub company_id: Option<CompanyId>,
    pub action: Option<AuditAction>,
    pub severity_min: Option<AuditSeverity>,
    pub resource: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// In-memory audit log (for development and unit tests **only**).
///
/// Does not provide tamper evidence and must never be wired into a
/// production runtime.
pub struct MemoryAuditStorage {
    entries: RwLock<VecDeque<AuditEntry>>,
    max_entries: usize,
}

impl MemoryAuditStorage {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(VecDeque::with_capacity(max_entries)),
            max_entries,
        }
    }
}

#[async_trait::async_trait]
impl AuditStorage for MemoryAuditStorage {
    async fn write(&self, entry: AuditEntry) -> VortexResult<()> {
        let mut entries = self.entries.write().await;
        while entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back(entry);
        Ok(())
    }

    async fn write_tx<'c>(
        &self,
        entry: AuditEntry,
        _tx: &mut sqlx::Transaction<'c, sqlx::Postgres>,
    ) -> VortexResult<()> {
        // In-memory storage cannot participate in a Postgres transaction.
        // Degrade to a direct write and warn loudly: any caller hitting this
        // path is misconfigured (production must use PgAuditStorage).
        warn!(
            "MemoryAuditStorage::write_tx called — atomicity with caller's \
             transaction is NOT guaranteed. This storage is for tests only."
        );
        self.write(entry).await
    }

    async fn query(&self, filter: AuditFilter) -> VortexResult<Vec<AuditEntry>> {
        let entries = self.entries.read().await;
        let mut results: Vec<_> = entries
            .iter()
            .filter(|e| {
                filter.user_id.map_or(true, |u| e.user_id == Some(u))
                    && filter.company_id.map_or(true, |c| e.company_id == Some(c))
                    && filter.action.as_ref().map_or(true, |a| &e.action == a)
                    && filter.severity_min.map_or(true, |s| e.severity >= s)
                    && filter.resource.as_ref().map_or(true, |r| e.resource.as_ref() == Some(r))
                    && filter.start_time.map_or(true, |t| e.timestamp >= t)
                    && filter.end_time.map_or(true, |t| e.timestamp <= t)
            })
            .cloned()
            .collect();

        if let Some(offset) = filter.offset {
            results = results.into_iter().skip(offset).collect();
        }
        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }

        Ok(results)
    }

    async fn count(&self, filter: AuditFilter) -> VortexResult<u64> {
        let results = self.query(AuditFilter { limit: None, offset: None, ..filter }).await?;
        Ok(results.len() as u64)
    }
}

/// High-level audit log service wrapping an [`AuditStorage`] backend.
pub struct AuditLog {
    storage: Arc<dyn AuditStorage>,
    /// Alert callback for critical events.
    alert_handler: Option<Box<dyn Fn(&AuditEntry) + Send + Sync>>,
}

impl AuditLog {
    pub fn new(storage: Arc<dyn AuditStorage>) -> Self {
        Self {
            storage,
            alert_handler: None,
        }
    }

    pub fn with_alert_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(&AuditEntry) + Send + Sync + 'static,
    {
        self.alert_handler = Some(Box::new(handler));
        self
    }

    /// Log an audit entry through the storage backend.
    pub async fn log(&self, entry: AuditEntry) -> VortexResult<()> {
        self.fire_alert(&entry);
        self.storage.write(entry).await
    }

    /// Log an audit entry as part of an existing transaction.
    ///
    /// Use this from handlers that open their own transaction to mutate
    /// business data: passing the same transaction here ensures the audit
    /// write and the business mutation commit or roll back together. This
    /// is the only correct way to satisfy CIP-007-6 R5 for state changes
    /// inside multi-statement handlers.
    pub async fn log_tx<'c>(
        &self,
        entry: AuditEntry,
        tx: &mut sqlx::Transaction<'c, sqlx::Postgres>,
    ) -> VortexResult<()> {
        self.fire_alert(&entry);
        self.storage.write_tx(entry, tx).await
    }

    pub async fn query(&self, filter: AuditFilter) -> VortexResult<Vec<AuditEntry>> {
        self.storage.query(filter).await
    }

    pub async fn count(&self, filter: AuditFilter) -> VortexResult<u64> {
        self.storage.count(filter).await
    }

    fn fire_alert(&self, entry: &AuditEntry) {
        if entry.action.is_critical() {
            warn!(
                action = ?entry.action,
                user_id = ?entry.user_id,
                source_ip = ?entry.source_ip,
                "Critical security event"
            );
            if let Some(handler) = &self.alert_handler {
                handler(entry);
            }
        }
    }

    // ─── Convenience helpers for common events ─────────────────────────

    pub async fn log_login_success(
        &self,
        user_id: UserId,
        username: &str,
        source_ip: Option<&str>,
    ) -> VortexResult<()> {
        let mut entry = AuditEntry::new(AuditAction::LoginSuccess, AuditSeverity::Info)
            .with_user(user_id)
            .with_username(username);
        if let Some(ip) = source_ip {
            entry = entry.with_source_ip(ip);
        }
        self.log(entry).await
    }

    pub async fn log_login_failure(
        &self,
        username: &str,
        source_ip: Option<&str>,
        reason: &str,
    ) -> VortexResult<()> {
        let mut entry = AuditEntry::new(AuditAction::LoginFailure, AuditSeverity::Warning)
            .with_username(username)
            .with_error(reason)
            .with_details(serde_json::json!({
                "username": username,
                "reason": reason,
            }));
        if let Some(ip) = source_ip {
            entry = entry.with_source_ip(ip);
        }
        self.log(entry).await
    }

    pub async fn log_access_denied(
        &self,
        user_id: UserId,
        resource: &str,
        action: &str,
        source_ip: Option<&str>,
    ) -> VortexResult<()> {
        let mut entry = AuditEntry::new(AuditAction::AccessDenied, AuditSeverity::Warning)
            .with_user(user_id)
            .with_details(serde_json::json!({
                "resource": resource,
                "action": action,
            }));
        if let Some(ip) = source_ip {
            entry = entry.with_source_ip(ip);
        }
        self.log(entry).await
    }

    pub async fn log_data_change(
        &self,
        user_id: UserId,
        resource: &str,
        resource_id: &str,
        action: AuditAction,
        previous: Option<serde_json::Value>,
        new: Option<serde_json::Value>,
    ) -> VortexResult<()> {
        let entry = AuditEntry::new(action, AuditSeverity::Info)
            .with_user(user_id)
            .with_resource(resource, resource_id)
            .with_change(previous, new);
        self.log(entry).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_storage_round_trip() {
        let storage = MemoryAuditStorage::new(100);
        let entry = AuditEntry::new(AuditAction::LoginSuccess, AuditSeverity::Info)
            .with_username("alice");
        storage.write(entry.clone()).await.unwrap();
        let results = storage.query(AuditFilter::default()).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].username.as_deref(), Some("alice"));
    }

    #[test]
    fn action_codes_are_stable() {
        assert_eq!(AuditAction::LoginSuccess.code(), "login_success");
        assert_eq!(AuditAction::UserCreated.code(), "user_created");
        assert_eq!(AuditAction::ChainVerificationFailed.code(), "chain_verification_failed");
        assert_eq!(
            AuditAction::Custom("my_action".into()).code(),
            "custom:my_action"
        );
    }

    #[test]
    fn critical_actions_include_verification_failures() {
        assert!(AuditAction::ChainVerificationFailed.is_critical());
        assert!(AuditAction::TriggerDisabled.is_critical());
        assert!(!AuditAction::LoginSuccess.is_critical());
    }
}
