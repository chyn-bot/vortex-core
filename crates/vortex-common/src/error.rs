//! Error types for Vortex
//!
//! Provides a unified error type for regulated-industry-grade error handling
//! with proper categorization for audit logging.

use thiserror::Error;
use uuid::Uuid;

/// Result type alias for Vortex operations
pub type VortexResult<T> = Result<T, VortexError>;

/// Unified error type for all Vortex operations
#[derive(Error, Debug)]
pub enum VortexError {
    // ─────────────────────────────────────────────────────────────────────
    // Database & ORM Errors
    // ─────────────────────────────────────────────────────────────────────
    #[error("Database connection failed: {0}")]
    DatabaseConnection(String),

    #[error("Query execution failed: {0}")]
    QueryExecution(String),

    #[error("Record not found: {model} with id {id}")]
    RecordNotFound { model: String, id: RecordId },

    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),

    #[error("Migration failed: {0}")]
    MigrationFailed(String),

    // ─────────────────────────────────────────────────────────────────────
    // Security Errors
    // ─────────────────────────────────────────────────────────────────────
    #[error("Authentication failed for user: {username}")]
    AuthenticationFailed { username: String },

    #[error("Access denied: {action} on {resource}")]
    AccessDenied { action: String, resource: String },

    #[error("Session expired or invalid")]
    SessionInvalid,

    #[error("Insufficient permissions: requires {required}, has {current}")]
    InsufficientPermissions { required: String, current: String },

    #[error("Security policy violation: {0}")]
    SecurityPolicyViolation(String),

    #[error("Rate limit exceeded for {resource}")]
    RateLimitExceeded { resource: String },

    // ─────────────────────────────────────────────────────────────────────
    // Module System Errors
    // ─────────────────────────────────────────────────────────────────────
    #[error("Module not found: {0}")]
    ModuleNotFound(String),

    #[error("Module dependency error: {module} requires {dependency}")]
    ModuleDependencyError { module: String, dependency: String },

    #[error("Module load failed: {module} - {reason}")]
    ModuleLoadFailed { module: String, reason: String },

    #[error("Circular dependency detected: {0}")]
    CircularDependency(String),

    // ─────────────────────────────────────────────────────────────────────
    // Validation Errors
    // ─────────────────────────────────────────────────────────────────────
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    #[error("Invalid field value: {field} - {reason}")]
    InvalidFieldValue { field: String, reason: String },

    #[error("Required field missing: {0}")]
    RequiredFieldMissing(String),

    // ─────────────────────────────────────────────────────────────────────
    // Configuration Errors
    // ─────────────────────────────────────────────────────────────────────
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Invalid configuration value: {key} = {value}")]
    InvalidConfigValue { key: String, value: String },

    // ─────────────────────────────────────────────────────────────────────
    // Internal Errors
    // ─────────────────────────────────────────────────────────────────────
    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Record identifier - supports both integer and UUID primary keys
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RecordId {
    Int(i64),
    Uuid(Uuid),
}

impl std::fmt::Display for RecordId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordId::Int(id) => write!(f, "{}", id),
            RecordId::Uuid(id) => write!(f, "{}", id),
        }
    }
}

impl From<i64> for RecordId {
    fn from(id: i64) -> Self {
        RecordId::Int(id)
    }
}

impl From<Uuid> for RecordId {
    fn from(id: Uuid) -> Self {
        RecordId::Uuid(id)
    }
}

impl VortexError {
    /// Returns the error category for audit logging
    pub fn category(&self) -> ErrorCategory {
        match self {
            VortexError::DatabaseConnection(_)
            | VortexError::QueryExecution(_)
            | VortexError::RecordNotFound { .. }
            | VortexError::ConstraintViolation(_)
            | VortexError::MigrationFailed(_) => ErrorCategory::Database,

            VortexError::AuthenticationFailed { .. }
            | VortexError::AccessDenied { .. }
            | VortexError::SessionInvalid
            | VortexError::InsufficientPermissions { .. }
            | VortexError::SecurityPolicyViolation(_)
            | VortexError::RateLimitExceeded { .. } => ErrorCategory::Security,

            VortexError::ModuleNotFound(_)
            | VortexError::ModuleDependencyError { .. }
            | VortexError::ModuleLoadFailed { .. }
            | VortexError::CircularDependency(_) => ErrorCategory::Module,

            VortexError::ValidationFailed(_)
            | VortexError::InvalidFieldValue { .. }
            | VortexError::RequiredFieldMissing(_) => ErrorCategory::Validation,

            VortexError::ConfigurationError(_)
            | VortexError::InvalidConfigValue { .. } => ErrorCategory::Configuration,

            VortexError::Internal(_)
            | VortexError::Serialization(_)
            | VortexError::Io(_) => ErrorCategory::Internal,
        }
    }

    /// Returns whether this error should be logged for compliance/audit
    pub fn requires_audit_log(&self) -> bool {
        matches!(
            self.category(),
            ErrorCategory::Security | ErrorCategory::Configuration
        )
    }

    /// Returns the CIP requirement this error relates to (if any)
    pub fn cip_requirement(&self) -> Option<&'static str> {
        match self {
            VortexError::AuthenticationFailed { .. } => Some("CIP-007-6 R5"),
            VortexError::AccessDenied { .. } => Some("CIP-004-7 R4"),
            VortexError::SessionInvalid => Some("CIP-007-6 R5"),
            VortexError::InsufficientPermissions { .. } => Some("CIP-004-7 R4"),
            VortexError::SecurityPolicyViolation(_) => Some("CIP-007-6"),
            VortexError::ConfigurationError(_) => Some("CIP-010-4 R1"),
            _ => None,
        }
    }
}

/// Error categories for classification and routing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    Database,
    Security,
    Module,
    Validation,
    Configuration,
    Internal,
}

impl std::fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCategory::Database => write!(f, "DATABASE"),
            ErrorCategory::Security => write!(f, "SECURITY"),
            ErrorCategory::Module => write!(f, "MODULE"),
            ErrorCategory::Validation => write!(f, "VALIDATION"),
            ErrorCategory::Configuration => write!(f, "CONFIGURATION"),
            ErrorCategory::Internal => write!(f, "INTERNAL"),
        }
    }
}
