//! Vortex Security - Enterprise Security Layer for regulated industries
//!
//! Provides comprehensive security features:
//! - Role-Based Access Control (RBAC)
//! - Record-level security rules
//! - Field-level access control
//! - Immutable audit logging
//! - Session management
//! - Password policies
//!
//! # Access Control Architecture
//!
//! The access control system implements a three-tier model:
//!
//! 1. **Model Access** - Can user CRUD this model? (e.g., "Viewers can read Users but not write")
//! 2. **Record Rules** - Which records can user see? (e.g., "Users only see own company's data")
//! 3. **Field Access** - Which fields are visible? (e.g., "Password hash hidden from non-admins")
//!
//! ## Example
//!
//! ```ignore
//! use vortex_security::prelude::*;
//!
//! // Create access controller
//! let store = Arc::new(MemoryAccessStore::new());
//! let controller = AccessController::new(store);
//!
//! // Check model access
//! controller.check_model_access(&ctx, "users", AccessMode::Read).await?;
//!
//! // Get record domain filter
//! let domain = controller.get_record_domain(&ctx, "users", AccessMode::Read).await?;
//!
//! // Get field access
//! let fields = controller.get_field_access(&ctx, "users").await?;
//! ```

pub mod access;
pub mod audit;
pub mod auth;
pub mod controller;
pub mod crypto;
pub mod csv_loader;
pub mod domain;
pub mod mfa;
pub mod password;
pub mod rbac;
pub mod session;
pub mod signing;

pub mod prelude {
    // Legacy access control (still useful for simple cases)
    pub use crate::access::{AccessChecker, FieldAccess, RecordRule};

    // New access control system
    pub use crate::controller::{
        AccessController, AccessMode, AccessStore, FieldAccessMap, FieldAccessRule,
        MemoryAccessStore, ModelAccessRule, RecordRuleEntry,
    };
    pub use crate::domain::{DomainExpr, DomainOp, DomainValue, MssqlDialect, PostgresDialect, SqlDialect};
    pub use crate::csv_loader::{CsvLoader, MemoryRoleResolver, RoleResolver};

    // Core security
    pub use crate::audit::{
        AuditAction, AuditEntry, AuditFilter, AuditLog, AuditSeverity, AuditStorage,
        MemoryAuditStorage, PgAuditStorage,
    };
    pub use crate::auth::{AuthService, Credentials};
    pub use crate::password::{PasswordHasher, PasswordPolicy};
    pub use crate::rbac::{Permission, Role, RoleManager};
    pub use crate::session::{Session, SessionManager};
    pub use crate::signing::{Ed25519Key, SigningKey, SigningMode};
}

pub use prelude::*;
