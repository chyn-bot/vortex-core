//! Execution context for request handling
//!
//! The Context carries user identity, company scope, and audit information
//! through all operations. This is critical for compliance and audit.

use crate::{CompanyId, UserId, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request/execution context carrying identity and audit information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Context {
    /// Unique identifier for this request/operation
    pub request_id: Uuid,

    /// The authenticated user (if any)
    pub user_id: Option<UserId>,

    /// The active company/tenant scope
    pub company_id: Option<CompanyId>,

    /// User's roles for access control
    pub roles: Vec<String>,

    /// Session identifier for audit trail
    pub session_id: Option<Uuid>,

    /// Source IP address for audit logging
    pub source_ip: Option<String>,

    /// User agent for audit logging
    pub user_agent: Option<String>,

    /// Request timestamp
    pub timestamp: Timestamp,

    /// Whether this is a system/internal context (bypasses some checks)
    pub is_system: bool,

    /// Correlation ID for distributed tracing
    pub correlation_id: Option<String>,
}

impl Context {
    /// Create a new context for an authenticated user
    pub fn authenticated(user_id: UserId, company_id: CompanyId) -> Self {
        Self {
            request_id: Uuid::now_v7(),
            user_id: Some(user_id),
            company_id: Some(company_id),
            roles: Vec::new(),
            session_id: None,
            source_ip: None,
            user_agent: None,
            timestamp: Timestamp::now(),
            is_system: false,
            correlation_id: None,
        }
    }

    /// Create a system context for internal operations
    /// IMPORTANT: Use sparingly - system contexts bypass permission checks
    pub fn system() -> Self {
        Self {
            request_id: Uuid::now_v7(),
            user_id: None,
            company_id: None,
            roles: vec!["system".to_string()],
            session_id: None,
            source_ip: Some("127.0.0.1".to_string()),
            user_agent: Some("vortex-system".to_string()),
            timestamp: Timestamp::now(),
            is_system: true,
            correlation_id: None,
        }
    }

    /// Create an anonymous context (for public endpoints)
    pub fn anonymous() -> Self {
        Self {
            request_id: Uuid::now_v7(),
            user_id: None,
            company_id: None,
            roles: Vec::new(),
            session_id: None,
            source_ip: None,
            user_agent: None,
            timestamp: Timestamp::now(),
            is_system: false,
            correlation_id: None,
        }
    }

    /// Add roles to the context
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Set session information
    pub fn with_session(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Set source IP for audit logging
    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    /// Set user agent for audit logging
    pub fn with_user_agent(mut self, agent: impl Into<String>) -> Self {
        self.user_agent = Some(agent.into());
        self
    }

    /// Set correlation ID for distributed tracing
    pub fn with_correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Check if user has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.is_system || self.roles.iter().any(|r| r == role)
    }

    /// Check if user has any of the specified roles
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        self.is_system || roles.iter().any(|r| self.has_role(r))
    }

    /// Get the user ID or return an error
    pub fn require_user(&self) -> crate::VortexResult<UserId> {
        self.user_id.ok_or_else(|| {
            crate::VortexError::AuthenticationFailed {
                username: "anonymous".to_string(),
            }
        })
    }

    /// Get the company ID or return an error
    pub fn require_company(&self) -> crate::VortexResult<CompanyId> {
        self.company_id.ok_or_else(|| {
            crate::VortexError::AccessDenied {
                action: "access".to_string(),
                resource: "company-scoped resource".to_string(),
            }
        })
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::anonymous()
    }
}
