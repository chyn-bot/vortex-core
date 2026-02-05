//! Immutable Audit Logging - NERC CIP-007 Compliance
//!
//! Provides tamper-evident audit logging for all security-relevant events.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;
use vortex_common::{CompanyId, UserId, VortexResult};

/// Audit action types per NERC CIP-007-6 R5
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

    // Custom action
    Custom(String),
}

impl AuditAction {
    /// Get the CIP requirement this action relates to
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
            | AuditAction::RoleRevoked => "CIP-004-7 R4",

            AuditAction::ConfigChanged
            | AuditAction::SystemStartup
            | AuditAction::SystemShutdown
            | AuditAction::ModuleLoaded
            | AuditAction::ModuleUnloaded => "CIP-010-4 R1",

            _ => "CIP-007-6",
        }
    }

    /// Check if this is a security-critical event that requires immediate alerting
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            AuditAction::LoginFailure
                | AuditAction::MfaFailure
                | AuditAction::AccessDenied
                | AuditAction::SecurityAlert
                | AuditAction::IntrusionAttempt
                | AuditAction::RateLimitExceeded
        )
    }
}

/// Severity level for audit entries
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditSeverity {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID (UUID v7 for time-ordering)
    pub id: Uuid,
    /// When the event occurred
    pub timestamp: DateTime<Utc>,
    /// The action that was performed
    pub action: AuditAction,
    /// Severity level
    pub severity: AuditSeverity,
    /// User who performed the action (if authenticated)
    pub user_id: Option<UserId>,
    /// Company context
    pub company_id: Option<CompanyId>,
    /// Session ID for correlation
    pub session_id: Option<Uuid>,
    /// Request ID for tracing
    pub request_id: Option<Uuid>,
    /// Source IP address
    pub source_ip: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Resource affected (model/table name)
    pub resource: Option<String>,
    /// Resource ID affected
    pub resource_id: Option<String>,
    /// Action-specific details
    pub details: serde_json::Value,
    /// Previous state for change tracking
    pub previous_state: Option<serde_json::Value>,
    /// New state for change tracking
    pub new_state: Option<serde_json::Value>,
    /// CIP requirement reference
    pub cip_reference: String,
    /// Checksum for tamper detection
    pub checksum: String,
}

impl AuditEntry {
    /// Create a new audit entry
    pub fn new(action: AuditAction, severity: AuditSeverity) -> Self {
        let mut entry = Self {
            id: Uuid::now_v7(),
            timestamp: Utc::now(),
            action: action.clone(),
            severity,
            user_id: None,
            company_id: None,
            session_id: None,
            request_id: None,
            source_ip: None,
            user_agent: None,
            resource: None,
            resource_id: None,
            details: serde_json::Value::Null,
            previous_state: None,
            new_state: None,
            cip_reference: action.cip_requirement().to_string(),
            checksum: String::new(),
        };
        entry.checksum = entry.compute_checksum();
        entry
    }

    /// Set user context
    pub fn with_user(mut self, user_id: UserId) -> Self {
        self.user_id = Some(user_id);
        self.checksum = self.compute_checksum();
        self
    }

    /// Set company context
    pub fn with_company(mut self, company_id: CompanyId) -> Self {
        self.company_id = Some(company_id);
        self.checksum = self.compute_checksum();
        self
    }

    /// Set session context
    pub fn with_session(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self.checksum = self.compute_checksum();
        self
    }

    /// Set request context
    pub fn with_request(mut self, request_id: Uuid) -> Self {
        self.request_id = Some(request_id);
        self.checksum = self.compute_checksum();
        self
    }

    /// Set source IP
    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self.checksum = self.compute_checksum();
        self
    }

    /// Set user agent
    pub fn with_user_agent(mut self, agent: impl Into<String>) -> Self {
        self.user_agent = Some(agent.into());
        self.checksum = self.compute_checksum();
        self
    }

    /// Set resource affected
    pub fn with_resource(mut self, resource: impl Into<String>, id: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self.resource_id = Some(id.into());
        self.checksum = self.compute_checksum();
        self
    }

    /// Set action details
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self.checksum = self.compute_checksum();
        self
    }

    /// Set change tracking data
    pub fn with_change(
        mut self,
        previous: Option<serde_json::Value>,
        new: Option<serde_json::Value>,
    ) -> Self {
        self.previous_state = previous;
        self.new_state = new;
        self.checksum = self.compute_checksum();
        self
    }

    /// Compute checksum for tamper detection
    fn compute_checksum(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();

        // Hash all relevant fields
        self.id.hash(&mut hasher);
        self.timestamp.timestamp_nanos_opt().hash(&mut hasher);
        format!("{:?}", self.action).hash(&mut hasher);
        format!("{:?}", self.severity).hash(&mut hasher);
        format!("{:?}", self.user_id).hash(&mut hasher);
        format!("{:?}", self.company_id).hash(&mut hasher);
        format!("{:?}", self.session_id).hash(&mut hasher);
        self.source_ip.hash(&mut hasher);
        self.resource.hash(&mut hasher);
        self.resource_id.hash(&mut hasher);
        self.details.to_string().hash(&mut hasher);

        format!("{:016x}", hasher.finish())
    }

    /// Verify the checksum is valid
    pub fn verify_checksum(&self) -> bool {
        let expected = self.compute_checksum();
        self.checksum == expected
    }
}

/// Audit log storage interface
#[async_trait::async_trait]
pub trait AuditStorage: Send + Sync {
    /// Write an audit entry
    async fn write(&self, entry: AuditEntry) -> VortexResult<()>;

    /// Query audit entries
    async fn query(&self, filter: AuditFilter) -> VortexResult<Vec<AuditEntry>>;

    /// Get entry count
    async fn count(&self, filter: AuditFilter) -> VortexResult<u64>;
}

/// Filter for querying audit logs
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

/// In-memory audit log (for development/testing)
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

        // Remove oldest entries if at capacity
        while entries.len() >= self.max_entries {
            entries.pop_front();
        }

        entries.push_back(entry);
        Ok(())
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

        // Apply offset and limit
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

/// Main audit log service
pub struct AuditLog {
    storage: Arc<dyn AuditStorage>,
    /// Alert callback for critical events
    alert_handler: Option<Box<dyn Fn(&AuditEntry) + Send + Sync>>,
}

impl AuditLog {
    /// Create a new audit log with the given storage backend
    pub fn new(storage: Arc<dyn AuditStorage>) -> Self {
        Self {
            storage,
            alert_handler: None,
        }
    }

    /// Set alert handler for critical events
    pub fn with_alert_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(&AuditEntry) + Send + Sync + 'static,
    {
        self.alert_handler = Some(Box::new(handler));
        self
    }

    /// Log an audit entry
    pub async fn log(&self, entry: AuditEntry) -> VortexResult<()> {
        // Check for critical events
        if entry.action.is_critical() {
            warn!(
                action = ?entry.action,
                user_id = ?entry.user_id,
                source_ip = ?entry.source_ip,
                "Critical security event"
            );

            if let Some(handler) = &self.alert_handler {
                handler(&entry);
            }
        }

        self.storage.write(entry).await
    }

    /// Query audit entries
    pub async fn query(&self, filter: AuditFilter) -> VortexResult<Vec<AuditEntry>> {
        self.storage.query(filter).await
    }

    /// Count audit entries
    pub async fn count(&self, filter: AuditFilter) -> VortexResult<u64> {
        self.storage.count(filter).await
    }

    /// Log a login success
    pub async fn log_login_success(&self, user_id: UserId, source_ip: &str) -> VortexResult<()> {
        let entry = AuditEntry::new(AuditAction::LoginSuccess, AuditSeverity::Info)
            .with_user(user_id)
            .with_source_ip(source_ip);
        self.log(entry).await
    }

    /// Log a login failure
    pub async fn log_login_failure(&self, username: &str, source_ip: &str, reason: &str) -> VortexResult<()> {
        let entry = AuditEntry::new(AuditAction::LoginFailure, AuditSeverity::Warning)
            .with_source_ip(source_ip)
            .with_details(serde_json::json!({
                "username": username,
                "reason": reason
            }));
        self.log(entry).await
    }

    /// Log an access denied event
    pub async fn log_access_denied(
        &self,
        user_id: UserId,
        resource: &str,
        action: &str,
        source_ip: &str,
    ) -> VortexResult<()> {
        let entry = AuditEntry::new(AuditAction::AccessDenied, AuditSeverity::Warning)
            .with_user(user_id)
            .with_source_ip(source_ip)
            .with_details(serde_json::json!({
                "resource": resource,
                "action": action
            }));
        self.log(entry).await
    }

    /// Log a data change
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
